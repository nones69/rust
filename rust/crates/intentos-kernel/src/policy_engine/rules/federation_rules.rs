//! Module E — Federation rules.
//!
//! Federation rules govern cross-kernel trust and policy-hash consistency.
//! A remote kernel is identified by a peer prefix in the token's `issued_to`
//! field: `"peer:<peer-name>"`.  These rules are skeletons; in a full
//! deployment they would consult a live federation trust registry.

use crate::policy_engine::evidence::Evidence;
use crate::policy_engine::rule::{PolicyResult, PolicyRule};
use crate::syscall_envelope::IkSyscall;
use crate::token_verifier::VerifiedToken;

fn peer_name(token: &VerifiedToken) -> Option<String> {
    token.issued_to.strip_prefix("peer:").map(|s| s.to_string())
}

// ── Remote-kernel trust rule ──────────────────────────────────────────────────

fn evaluate_remote_kernel_trust(token: &VerifiedToken, _syscall: &IkSyscall) -> PolicyResult {
    match peer_name(token) {
        Some(peer) => {
            // TODO: consult federation trust registry.
            // For now, all peer-prefixed tokens are trusted (skeleton).
            PolicyResult::Allow {
                evidence: vec![Evidence::FederationTrusted { peer }],
            }
        }
        None => {
            // Local principal — not a federation call; pass through.
            PolicyResult::Allow { evidence: vec![] }
        }
    }
}

/// Verifies that remote kernel principals are in the federation trust list.
pub fn remote_kernel_trust_rule() -> PolicyRule {
    PolicyRule {
        id: "federation-trust".into(),
        description: "Verify remote kernel principals against the federation trust list".into(),
        evaluate: evaluate_remote_kernel_trust,
    }
}

// ── Policy-hash consistency rule ──────────────────────────────────────────────

fn evaluate_policy_hash_consistency(_token: &VerifiedToken, _syscall: &IkSyscall) -> PolicyResult {
    // TODO: compare the policy hash in the token metadata against the local
    // kernel's active policy hash.  For now, emit a match (skeleton).
    PolicyResult::Allow {
        evidence: vec![Evidence::PolicyHashMatch],
    }
}

/// Verifies that the policy hash in the call matches the cluster-agreed hash.
pub fn policy_hash_consistency_rule() -> PolicyRule {
    PolicyRule {
        id: "federation-policy-hash".into(),
        description: "Verify the policy hash is consistent with the cluster quorum".into(),
        evaluate: evaluate_policy_hash_consistency,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_schema::{FsOp, FsScope, TokenScope};
    use crate::policy_engine::evidence::Evidence;
    use crate::policy_engine::rule::PolicyResult;
    use crate::syscall_envelope::OpenMode;
    use std::time::{Duration, SystemTime};
    use uuid::Uuid;

    fn make_token(principal: &str) -> VerifiedToken {
        VerifiedToken {
            id: Uuid::new_v4(),
            issued_to: principal.into(),
            expires_at: SystemTime::now() + Duration::from_secs(3600),
            scope: TokenScope::Fs(FsScope {
                path_prefix: "/tmp".into(),
                ops: vec![FsOp::Read],
            }),
            quota: crate::token_verifier::TokenQuota::unlimited_now(),
        }
    }

    fn open_syscall() -> IkSyscall {
        IkSyscall::IkOpen {
            path: "/tmp/x".into(),
            mode: OpenMode::Read,
        }
    }

    #[test]
    fn trust_rule_emits_trusted_for_peer_principal() {
        let t = make_token("peer:node-a");
        let result = (remote_kernel_trust_rule().evaluate)(&t, &open_syscall());
        assert!(matches!(
            result,
            PolicyResult::Allow { evidence } if evidence.iter().any(|e| matches!(e, Evidence::FederationTrusted { peer } if peer == "node-a"))
        ));
    }

    #[test]
    fn trust_rule_passes_through_local_principal() {
        let t = make_token("local-app");
        let result = (remote_kernel_trust_rule().evaluate)(&t, &open_syscall());
        assert!(matches!(result, PolicyResult::Allow { .. }));
    }

    #[test]
    fn policy_hash_rule_emits_match() {
        let t = make_token("any-app");
        let result = (policy_hash_consistency_rule().evaluate)(&t, &open_syscall());
        assert!(matches!(
            result,
            PolicyResult::Allow { evidence } if evidence.contains(&Evidence::PolicyHashMatch)
        ));
    }
}
