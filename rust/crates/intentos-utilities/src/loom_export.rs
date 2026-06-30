//! Signed Loom export/import — portable session bundles between machines.

use crate::loom_store::LoomStore;
use intentos_kernel::{
    sign, verify, IntentCard, ThresholdLevel, SECRET_KEY_LEN, SIGNATURE_LEN, PUBLIC_KEY_LEN,
};
use crate::loom_store::hex_bytes;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::loom_store::LoomError;

/// Signed export format version.
pub const LOOM_EXPORT_VERSION: u32 = 1;

/// Portable payload (no local signing secrets).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoomExportPayload {
    pub profile_id: String,
    pub active_field_id: Option<String>,
    pub fields: Vec<intentos_kernel::Field>,
    pub cards: Vec<IntentCard>,
    pub default_threshold: ThresholdLevel,
    pub telemetry_enabled: bool,
    pub ai_enabled: bool,
}

/// Signed bundle written to disk for cross-machine transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoomSignedExport {
    pub export_version: u32,
    pub exported_at_ms: u64,
    pub signing_public_key_hex: String,
    pub payload: LoomExportPayload,
    pub signature_hex: String,
}

impl LoomStore {
    /// Write a signed export file from the current session.
    pub fn export_signed(&self, path: impl AsRef<Path>) -> Result<LoomSignedExport, LoomError> {
        let session = self.session();
        if session.signing_secret_key_hex.is_empty() || session.signing_public_key_hex.is_empty() {
            return Err(LoomError::State(
                "profile signing keys missing — complete OOBE first".into(),
            ));
        }

        let payload = LoomExportPayload {
            profile_id: session.profile_id.clone(),
            active_field_id: session.active_field_id.clone(),
            fields: session.fields.clone(),
            cards: session.cards.clone(),
            default_threshold: session.default_threshold,
            telemetry_enabled: session.telemetry_enabled,
            ai_enabled: session.ai_enabled,
        };

        let payload_bytes = serde_json::to_vec(&payload)?;
        let secret_key = decode_secret_key(&session.signing_secret_key_hex)?;
        let signature = sign(&secret_key, &payload_bytes).map_err(|e| {
            LoomError::State(format!("sign export: {e}"))
        })?;

        let bundle = LoomSignedExport {
            export_version: LOOM_EXPORT_VERSION,
            exported_at_ms: intentos_kernel::wall_ms(),
            signing_public_key_hex: session.signing_public_key_hex.clone(),
            payload,
            signature_hex: hex_bytes(&signature),
        };

        let bytes = serde_json::to_vec_pretty(&bundle)?;
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path.as_ref(), bytes)?;
        Ok(bundle)
    }

    /// Verify signature and merge imported fields/cards into the local session.
    pub fn import_signed(&self, path: impl AsRef<Path>) -> Result<LoomExportPayload, LoomError> {
        let bytes = fs::read(path.as_ref())?;
        let bundle: LoomSignedExport = serde_json::from_slice(&bytes)?;
        if bundle.export_version != LOOM_EXPORT_VERSION {
            return Err(LoomError::State(format!(
                "unsupported export version {}",
                bundle.export_version
            )));
        }

        let payload_bytes = serde_json::to_vec(&bundle.payload)?;
        let public_key = decode_public_key(&bundle.signing_public_key_hex)?;
        let signature = decode_signature(&bundle.signature_hex)?;
        verify(&public_key, &payload_bytes, &signature).map_err(|e| {
            LoomError::State(format!("import signature invalid: {e}"))
        })?;

        self.merge_import_payload(&bundle.payload)?;
        Ok(bundle.payload)
    }

}

fn decode_secret_key(hex_str: &str) -> Result<[u8; SECRET_KEY_LEN], LoomError> {
    let bytes = hex_decode(hex_str)?;
    bytes
        .try_into()
        .map_err(|_| LoomError::State("invalid secret key length".into()))
}

fn decode_public_key(hex_str: &str) -> Result<[u8; PUBLIC_KEY_LEN], LoomError> {
    let bytes = hex_decode(hex_str)?;
    if bytes.len() < 32 {
        return Err(LoomError::State("invalid public key hex".into()));
    }
    let mut public_key = [0u8; PUBLIC_KEY_LEN];
    public_key[..32].copy_from_slice(&bytes[..32]);
    Ok(public_key)
}

fn decode_signature(hex_str: &str) -> Result<[u8; SIGNATURE_LEN], LoomError> {
    let bytes = hex_decode(hex_str)?;
    bytes
        .try_into()
        .map_err(|_| LoomError::State("invalid signature length".into()))
}

fn hex_decode(hex_str: &str) -> Result<Vec<u8>, LoomError> {
    if hex_str.len() % 2 != 0 {
        return Err(LoomError::State("invalid hex length".into()));
    }
    (0..hex_str.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex_str[i..i + 2], 16)
                .map_err(|_| LoomError::State("invalid hex digit".into()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loom_store::LoomStore;
    use intentos_kernel::ThresholdLevel;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir() -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("intentos-loom-export-{nanos}"))
    }

    #[test]
    fn signed_export_round_trip() {
        let dir = temp_dir();
        let export_path = dir.join("loom.export.json");
        let store = LoomStore::open_in(&dir).unwrap();
        store.complete_oobe(ThresholdLevel::Medium).unwrap();
        store.create_card("Read", "file", "read").unwrap();

        store.export_signed(&export_path).unwrap();

        let dir2 = temp_dir();
        let store2 = LoomStore::open_in(&dir2).unwrap();
        store2.complete_oobe(ThresholdLevel::Low).unwrap();
        let payload = store2.import_signed(&export_path).unwrap();
        assert!(!payload.cards.is_empty());
        assert!(store2.session().cards.iter().any(|c| c.title == "Read"));

        let _ = fs::remove_dir_all(dir);
        let _ = fs::remove_dir_all(dir2);
    }

    #[test]
    fn tampered_export_rejected() {
        let dir = temp_dir();
        let export_path = dir.join("loom.export.json");
        let store = LoomStore::open_in(&dir).unwrap();
        store.complete_oobe(ThresholdLevel::Medium).unwrap();
        store.export_signed(&export_path).unwrap();

        let mut raw = fs::read_to_string(&export_path).unwrap();
        raw = raw.replace("Read", "Tampered");
        fs::write(&export_path, raw).unwrap();

        let dir2 = temp_dir();
        let store2 = LoomStore::open_in(&dir2).unwrap();
        store2.complete_oobe(ThresholdLevel::Low).unwrap();
        assert!(store2.import_signed(&export_path).is_err());

        let _ = fs::remove_dir_all(dir);
        let _ = fs::remove_dir_all(dir2);
    }
}