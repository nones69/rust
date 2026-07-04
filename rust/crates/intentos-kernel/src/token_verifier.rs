//! Token verification for the kernel dispatch layer.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::table::CapabilityTable;
use crate::wall_ms;

/// A verified capability token with its core identity fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedToken {
    pub id: Uuid,
    pub issued_to: String,
    /// Expiry as milliseconds since Unix epoch.
    pub expires_at: u64,
}

impl VerifiedToken {
    pub fn is_expired(&self) -> bool {
        wall_ms() >= self.expires_at
    }
}

/// Verify a capability token against the live capability table.
///
/// Returns `Ok(VerifiedToken)` if a non-expired, non-exhausted slot holds the
/// given JTI; otherwise `Err` with a human-readable reason.
pub fn verify_with_table(table: &CapabilityTable, token_id: &Uuid) -> Result<VerifiedToken, String> {
    let jti = token_id.to_string();
    table
        .lookup_by_jti(&jti)
        .ok_or_else(|| format!("token {token_id} not found or expired in capability table"))
}

/// Simple verification stub for local testing.
/// Replace with real lookup and signature verification in production.
pub fn verify_token(token_id: &Uuid) -> Result<VerifiedToken, String> {
    // TODO: look up token in capability table, verify signature, check revocation list
    Ok(VerifiedToken {
        id: *token_id,
        issued_to: "stub-subject".to_string(),
        expires_at: wall_ms() + 60_000,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PolicyEngine;
    use crate::table::CapabilityTable;
    use crate::token::TokenBroker;
    use crate::types::{Intent, TrustAnchor, wall_ms as _wall_ms};

    #[test]
    fn stub_token_is_not_expired() {
        let id = Uuid::new_v4();
        let t = verify_token(&id).unwrap();
        assert_eq!(t.id, id);
        assert!(!t.is_expired());
    }

    #[test]
    fn verify_with_table_finds_registered_token() {
        let broker = TokenBroker::generate("test-broker").unwrap();
        let intent = Intent {
            actor: "alice".into(),
            resource: "file".into(),
            action: "read".into(),
            anchor: TrustAnchor::UiEvent,
            timestamp_ms: _wall_ms(),
            metadata: Default::default(),
        };
        let decision = PolicyEngine::evaluate(&intent);
        let token = broker.mint(&intent, &decision).unwrap();
        let jti_uuid = Uuid::parse_str(&token.jti).unwrap();

        let mut table = CapabilityTable::new();
        table.register(&token).unwrap();

        let verified = verify_with_table(&table, &jti_uuid).unwrap();
        assert_eq!(verified.id, jti_uuid);
        assert_eq!(verified.issued_to, "alice");
        assert!(!verified.is_expired());
    }

    #[test]
    fn verify_with_table_rejects_unknown_jti() {
        let table = CapabilityTable::new();
        let random_id = Uuid::new_v4();
        assert!(verify_with_table(&table, &random_id).is_err());
    }
}
