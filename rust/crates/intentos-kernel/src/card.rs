//! Intent Card — typed, scoped user intent with explicit capability request.

use crate::threshold::ThresholdLevel;
use crate::types::{CapabilityScope, wall_ms};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Schema version for forward-compatible card serialization.
pub const CARD_SCHEMA_VERSION: u32 = 1;

/// User-facing intent packaged as a capability request card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentCard {
    pub schema_version: u32,
    pub id: String,
    pub title: String,
    pub field_id: String,
    pub requested_caps: Vec<CapabilityScope>,
    pub ttl_ms: u64,
    pub uses: u32,
    pub risk_level: ThresholdLevel,
    pub created_at: u64,
}

impl IntentCard {
    pub fn new(
        title: &str,
        field_id: &str,
        resource: &str,
        action: &str,
        risk_level: ThresholdLevel,
    ) -> Self {
        let (ttl_ms, uses) = default_ttl_uses(resource, action);
        Self {
            schema_version: CARD_SCHEMA_VERSION,
            id: format!("card-{}", Uuid::new_v4()),
            title: title.to_string(),
            field_id: field_id.to_string(),
            requested_caps: vec![CapabilityScope::new(resource, action)],
            ttl_ms,
            uses,
            risk_level,
            created_at: wall_ms(),
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.requested_caps.is_empty() {
            return Err("card missing requested_caps".into());
        }
        if self.ttl_ms == 0 {
            return Err("card ttl_ms must be > 0".into());
        }
        if self.uses == 0 {
            return Err("card uses must be > 0".into());
        }
        if self.field_id.is_empty() {
            return Err("card missing field_id".into());
        }
        Ok(())
    }

    pub fn cap_summary(&self) -> String {
        self.requested_caps
            .iter()
            .map(|c| format!("{}/{}", c.resource, c.action))
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub fn primary_cap(&self) -> Option<&CapabilityScope> {
        self.requested_caps.first()
    }
}

fn default_ttl_uses(resource: &str, action: &str) -> (u64, u32) {
    match (action, resource) {
        ("read", "file") => (5_000, 1),
        ("write", "file") => (10_000, 1),
        ("list", "dir") | ("list", "file") => (5_000, 1),
        ("send", "network") => (30_000, 1),
        ("descramble", "network") => (15_000, 1),
        ("infer", "ai") => (60_000, 1),
        _ => (5_000, 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_caps() {
        let mut card = IntentCard::new("x", "fld-1", "file", "read", ThresholdLevel::Low);
        card.requested_caps.clear();
        assert!(card.validate().is_err());
    }

    #[test]
    fn valid_card_passes() {
        let card = IntentCard::new("Read", "fld-1", "file", "read", ThresholdLevel::Low);
        assert!(card.validate().is_ok());
    }
}