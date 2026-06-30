//! Intent Broker wire protocol — signed JSON envelopes over a local file transport.

use intentos_kernel::{sign, verify, BrokerPeer, PUBLIC_KEY_LEN, SECRET_KEY_LEN, SIGNATURE_LEN};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;
use uuid::Uuid;

pub const BROKER_WIRE_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerWireKind {
    Delegate,
    DelegateAck,
    Handshake,
}

/// Signed federation envelope (signature covers canonical JSON without `signature_hex`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrokerWireMessage {
    pub wire_version: u32,
    pub kind: BrokerWireKind,
    pub from_device: String,
    pub to_peer: String,
    pub nonce: String,
    pub sent_at_ms: u64,
    pub payload_b64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_hex: Option<String>,
}

#[derive(Debug, Error)]
pub enum BrokerWireError {
    #[error("wire I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("wire JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("wire crypto: {0}")]
    Crypto(String),
    #[error("wire protocol: {0}")]
    Protocol(String),
}

/// File-backed inbox/outbox transport for cross-process broker federation.
pub struct BrokerWireHub {
    root: PathBuf,
}

impl BrokerWireHub {
    pub fn open_default() -> Self {
        Self::open(state_broker_root())
    }

    pub fn open(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }

    pub fn open_in(dir: impl AsRef<Path>) -> Self {
        Self::open(dir.as_ref().join("broker"))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn inbox_path(&self, device_id: &str) -> PathBuf {
        self.root.join("inbox").join(format!("{device_id}.jsonl"))
    }

    pub fn outbox_path(&self) -> PathBuf {
        self.root.join("outbox").join("sent.jsonl")
    }

    pub fn build_delegate(
        from_device: &str,
        to_peer: &str,
        payload: &[u8],
        sent_at_ms: u64,
    ) -> BrokerWireMessage {
        BrokerWireMessage {
            wire_version: BROKER_WIRE_VERSION,
            kind: BrokerWireKind::Delegate,
            from_device: from_device.to_string(),
            to_peer: to_peer.to_string(),
            nonce: Uuid::new_v4().to_string(),
            sent_at_ms,
            payload_b64: base64_payload(payload),
            signature_hex: None,
        }
    }

    pub fn build_ack(request: &BrokerWireMessage, body: &[u8], sent_at_ms: u64) -> BrokerWireMessage {
        BrokerWireMessage {
            wire_version: BROKER_WIRE_VERSION,
            kind: BrokerWireKind::DelegateAck,
            from_device: request.to_peer.clone(),
            to_peer: request.from_device.clone(),
            nonce: Uuid::new_v4().to_string(),
            sent_at_ms,
            payload_b64: base64_payload(body),
            signature_hex: None,
        }
    }

    pub fn sign_message(
        msg: &mut BrokerWireMessage,
        secret_key_hex: &str,
    ) -> Result<(), BrokerWireError> {
        let secret = decode_secret_key(secret_key_hex)?;
        let bytes = unsigned_bytes(msg)?;
        let sig = sign(&secret, &bytes).map_err(|e| BrokerWireError::Crypto(e.to_string()))?;
        msg.signature_hex = Some(hex_encode(&sig));
        Ok(())
    }

    pub fn verify_message(
        msg: &BrokerWireMessage,
        peer_public_key_hex: &str,
    ) -> Result<(), BrokerWireError> {
        let sig_hex = msg
            .signature_hex
            .as_deref()
            .ok_or_else(|| BrokerWireError::Protocol("missing signature".into()))?;
        let public = decode_public_key(peer_public_key_hex)?;
        let signature = decode_signature(sig_hex)?;
        let bytes = unsigned_bytes(msg)?;
        verify(&public, &bytes, &signature)
            .map_err(|e| BrokerWireError::Crypto(e.to_string()))
    }

    pub fn enqueue_to_peer(&self, peer: &BrokerPeer, msg: &BrokerWireMessage) -> Result<(), BrokerWireError> {
        if msg.wire_version != BROKER_WIRE_VERSION {
            return Err(BrokerWireError::Protocol(format!(
                "unsupported wire version {}",
                msg.wire_version
            )));
        }
        let path = if peer.endpoint.is_empty() {
            self.inbox_path(&peer.peer_id)
        } else {
            PathBuf::from(peer.endpoint.trim_start_matches("file://"))
        };
        self.append_message(&path, msg)?;
        self.append_message(&self.outbox_path(), msg)?;
        Ok(())
    }

    pub fn recv_inbox(&self, device_id: &str, max: usize) -> Result<Vec<BrokerWireMessage>, BrokerWireError> {
        let path = self.inbox_path(device_id);
        if !path.exists() {
            return Ok(Vec::new());
        }
        let file = fs::File::open(&path)?;
        let reader = BufReader::new(file);
        let mut out = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let msg: BrokerWireMessage = serde_json::from_str(&line)?;
            out.push(msg);
            if out.len() >= max {
                break;
            }
        }
        Ok(out)
    }

    pub fn process_delegate_ack(
        &self,
        request: &BrokerWireMessage,
        secret_key_hex: &str,
        sent_at_ms: u64,
    ) -> Result<BrokerWireMessage, BrokerWireError> {
        let body = format!(
            "ack:nonce={}:payload_len={}",
            request.nonce,
            request.payload_b64.len()
        );
        let mut ack = Self::build_ack(request, body.as_bytes(), sent_at_ms);
        Self::sign_message(&mut ack, secret_key_hex)?;
        let path = self.inbox_path(&request.from_device);
        self.append_message(&path, &ack)?;
        Ok(ack)
    }

    fn append_message(&self, path: &Path, msg: &BrokerWireMessage) -> Result<(), BrokerWireError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let line = serde_json::to_string(msg)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        writeln!(file, "{line}")?;
        file.flush()?;
        Ok(())
    }
}

fn unsigned_bytes(msg: &BrokerWireMessage) -> Result<Vec<u8>, BrokerWireError> {
    let mut clone = msg.clone();
    clone.signature_hex = None;
    Ok(serde_json::to_vec(&clone)?)
}

fn base64_payload(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn decode_payload_hex(payload_b64: &str) -> Result<Vec<u8>, BrokerWireError> {
    if payload_b64.len() % 2 != 0 {
        return Err(BrokerWireError::Protocol("invalid payload hex".into()));
    }
    (0..payload_b64.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&payload_b64[i..i + 2], 16)
                .map_err(|_| BrokerWireError::Protocol("invalid payload hex digit".into()))
        })
        .collect()
}

fn decode_secret_key(hex_str: &str) -> Result<[u8; SECRET_KEY_LEN], BrokerWireError> {
    let bytes = hex_decode(hex_str)?;
    bytes
        .try_into()
        .map_err(|_| BrokerWireError::Crypto("invalid secret key length".into()))
}

fn decode_public_key(hex_str: &str) -> Result<[u8; PUBLIC_KEY_LEN], BrokerWireError> {
    let bytes = hex_decode(hex_str)?;
    if bytes.len() < 32 {
        return Err(BrokerWireError::Crypto("invalid public key hex".into()));
    }
    let mut public_key = [0u8; PUBLIC_KEY_LEN];
    public_key[..32].copy_from_slice(&bytes[..32]);
    Ok(public_key)
}

fn decode_signature(hex_str: &str) -> Result<[u8; SIGNATURE_LEN], BrokerWireError> {
    let bytes = hex_decode(hex_str)?;
    bytes
        .try_into()
        .map_err(|_| BrokerWireError::Crypto("invalid signature length".into()))
}

fn hex_decode(hex_str: &str) -> Result<Vec<u8>, BrokerWireError> {
    if hex_str.len() % 2 != 0 {
        return Err(BrokerWireError::Crypto("invalid hex length".into()));
    }
    (0..hex_str.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex_str[i..i + 2], 16)
                .map_err(|_| BrokerWireError::Crypto("invalid hex digit".into()))
        })
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn state_broker_root() -> PathBuf {
    if let Ok(dir) = std::env::var("INTENTOS_STATE_DIR") {
        return PathBuf::from(dir).join("broker");
    }
    if let Ok(home) = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")) {
        return PathBuf::from(home).join(".intentos").join("broker");
    }
    PathBuf::from(".intentos").join("broker")
}

#[cfg(test)]
mod tests {
    use super::*;
    use intentos_kernel::generate_broker_keys;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("intentos-broker-wire-{nanos}"))
    }

    #[test]
    fn signed_delegate_round_trip_on_file_transport() {
        let keys = generate_broker_keys().unwrap();
        let secret_hex: String = keys.secret_key_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let public_hex: String = keys.public_key_bytes()[..32]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

        let hub = BrokerWireHub::open(temp_root());
        let mut msg = BrokerWireHub::build_delegate("device-a", "device-b", b"hello-wire", 1);
        BrokerWireHub::sign_message(&mut msg, &secret_hex).unwrap();
        BrokerWireHub::verify_message(&msg, &public_hex).unwrap();

        let peer = BrokerPeer::new("device-b", public_hex.clone(), 1);
        hub.enqueue_to_peer(&peer, &msg).unwrap();
        let inbox = hub.recv_inbox("device-b", 10).unwrap();
        assert_eq!(inbox.len(), 1);
        BrokerWireHub::verify_message(&inbox[0], &public_hex).unwrap();
        let payload = decode_payload_hex(&inbox[0].payload_b64).unwrap();
        assert_eq!(payload, b"hello-wire");
    }
}