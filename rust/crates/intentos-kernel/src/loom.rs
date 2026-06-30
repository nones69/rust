//! Loom — local session continuity for fields, cards, and profile settings.

use crate::card::IntentCard;
use crate::field::Field;
use crate::policy_pack::PolicyPack;
use crate::threshold::ThresholdLevel;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use uuid::Uuid;

/// Loom state schema version.
pub const LOOM_SCHEMA_VERSION: u32 = 1;

/// Local-only continuity bundle restored on restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoomSession {
    pub schema_version: u32,
    pub profile_id: String,
    pub active_field_id: Option<String>,
    pub fields: Vec<Field>,
    pub cards: Vec<IntentCard>,
    #[serde(default)]
    pub policy_pack: PolicyPack,
    pub default_threshold: ThresholdLevel,
    pub telemetry_enabled: bool,
    pub ai_enabled: bool,
    pub oobe_complete: bool,
    /// Ed25519 public key (hex, first 32 bytes of broker public key).
    #[serde(default)]
    pub signing_public_key_hex: String,
    /// Broker secret key material for signing exports (hex, local-only).
    #[serde(default)]
    pub signing_secret_key_hex: String,
    pub checksum: String,
}

impl Default for LoomSession {
    fn default() -> Self {
        let mut session = Self {
            schema_version: LOOM_SCHEMA_VERSION,
            profile_id: format!("profile-{}", Uuid::new_v4()),
            active_field_id: None,
            fields: Vec::new(),
            cards: Vec::new(),
            policy_pack: PolicyPack::Personal,
            default_threshold: PolicyPack::Personal.default_threshold(),
            telemetry_enabled: false,
            ai_enabled: false,
            oobe_complete: false,
            signing_public_key_hex: String::new(),
            signing_secret_key_hex: String::new(),
            checksum: String::new(),
        };
        session.checksum = session.compute_checksum();
        session
    }
}

impl LoomSession {
    pub fn ensure_default_field(&mut self, created_at: u64) -> &Field {
        if self.fields.is_empty() {
            let field = Field::new("default", created_at);
            self.active_field_id = Some(field.id.clone());
            self.fields.push(field);
        }
        self.fields.first_mut().unwrap()
    }

    pub fn active_field(&self) -> Option<&Field> {
        let id = self.active_field_id.as_ref()?;
        self.fields.iter().find(|f| &f.id == id)
    }

    pub fn set_active_field(&mut self, field_id: &str) -> Result<(), String> {
        if !self.fields.iter().any(|f| f.id == field_id) {
            return Err(format!("unknown field: {field_id}"));
        }
        self.active_field_id = Some(field_id.to_string());
        self.refresh_checksum();
        Ok(())
    }

    pub fn add_field(&mut self, name: &str, created_at: u64) -> Field {
        let field = Field::new(name, created_at);
        self.fields.push(field.clone());
        self.refresh_checksum();
        field
    }

    pub fn add_card(&mut self, card: IntentCard) -> Result<(), String> {
        card.validate()?;
        if !self.fields.iter().any(|f| f.id == card.field_id) {
            return Err(format!("card field_id {} not found", card.field_id));
        }
        self.cards.push(card);
        self.refresh_checksum();
        Ok(())
    }

    pub fn find_card(&self, card_id: &str) -> Option<&IntentCard> {
        self.cards.iter().find(|c| c.id == card_id)
    }

    pub fn refresh_checksum(&mut self) {
        self.checksum = self.compute_checksum();
    }

    pub fn verify_checksum(&self) -> bool {
        self.checksum == self.compute_checksum()
    }

    fn compute_checksum(&self) -> String {
        let mut clone = self.clone();
        clone.checksum.clear();
        let bytes = serde_json::to_vec(&clone).unwrap_or_default();
        let digest = Sha3_256::digest(&bytes);
        hex::encode(digest)
    }
}

// Minimal hex helper to avoid adding a dependency — use format loop
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::wall_ms;

    #[test]
    fn round_trip_checksum() {
        let mut session = LoomSession::default();
        session.ensure_default_field(wall_ms());
        session.refresh_checksum();
        assert!(session.verify_checksum());
    }
}