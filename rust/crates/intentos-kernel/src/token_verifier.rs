//! Token verification stub for the kernel dispatch layer.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

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

    #[test]
    fn stub_token_is_not_expired() {
        let id = Uuid::new_v4();
        let t = verify_token(&id).unwrap();
        assert_eq!(t.id, id);
        assert!(!t.is_expired());
    }
}
