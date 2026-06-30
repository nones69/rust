//! Global JTI revocation list — blocks replay of compromised capability tokens.

use std::collections::HashSet;

/// In-memory revocation set keyed by token `jti`.
#[derive(Debug, Default)]
pub struct RevocationList {
    revoked: HashSet<String>,
}

impl RevocationList {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn revoke(&mut self, jti: &str) -> bool {
        self.revoked.insert(jti.to_string())
    }

    pub fn is_revoked(&self, jti: &str) -> bool {
        self.revoked.contains(jti)
    }

    pub fn len(&self) -> usize {
        self.revoked.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revoke_is_idempotent() {
        let mut list = RevocationList::new();
        assert!(list.revoke("jti-1"));
        assert!(!list.revoke("jti-1"));
        assert!(list.is_revoked("jti-1"));
    }
}