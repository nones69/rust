//! Core policy rule types.

use crate::policy_engine::evidence::Evidence;
use crate::syscall_envelope::IkSyscall;
use crate::token_verifier::VerifiedToken;

/// Result of a single policy rule evaluation.
#[derive(Debug, Clone)]
pub enum PolicyResult {
    /// The rule permits this syscall; evidence explains why.
    Allow { evidence: Vec<Evidence> },
    /// The rule denies this syscall; evidence explains why.
    Deny { reason: String, evidence: Vec<Evidence> },
}

/// A single policy rule — a pure, stateless predicate over token + syscall.
///
/// Rules are registered in the [`RuleRegistry`](super::registry::RuleRegistry)
/// at kernel boot and evaluated in registration order by the
/// [`evaluate`](super::evaluator::evaluate) function.
pub struct PolicyRule {
    /// Stable identifier, e.g. `"fs-scope"` or `"quota-bytes"`.
    pub id: String,
    /// Human-readable description for the Policy Inspector.
    pub description: String,
    /// Pure evaluation function — must be free of side effects.
    pub evaluate: fn(&VerifiedToken, &IkSyscall) -> PolicyResult,
}

// Manual Debug since fn pointers don't implement Debug.
impl std::fmt::Debug for PolicyRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyRule")
            .field("id", &self.id)
            .field("description", &self.description)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_schema::{FsOp, FsScope, TokenScope};
    use crate::syscall_envelope::OpenMode;
    use std::time::{Duration, SystemTime};
    use uuid::Uuid;

    fn test_token() -> VerifiedToken {
        VerifiedToken {
            id: Uuid::new_v4(),
            issued_to: "test".into(),
            expires_at: SystemTime::now() + Duration::from_secs(60),
            scope: TokenScope::Fs(FsScope {
                path_prefix: "/tmp".into(),
                ops: vec![FsOp::Read],
            }),
        }
    }

    #[test]
    fn policy_rule_debug_prints_id_and_description() {
        let rule = PolicyRule {
            id: "my-rule".into(),
            description: "A test rule".into(),
            evaluate: |_, _| PolicyResult::Allow { evidence: vec![] },
        };
        let dbg = format!("{rule:?}");
        assert!(dbg.contains("my-rule"));
    }

    #[test]
    fn allow_result_carries_evidence() {
        let t = test_token();
        let syscall = IkSyscall::IkOpen { path: "/tmp/x".into(), mode: OpenMode::Read };
        let rule = PolicyRule {
            id: "stub-allow".into(),
            description: "always allow".into(),
            evaluate: |_, _| PolicyResult::Allow {
                evidence: vec![Evidence::TTLValid],
            },
        };
        let result = (rule.evaluate)(&t, &syscall);
        assert!(matches!(result, PolicyResult::Allow { .. }));
    }

    #[test]
    fn deny_result_carries_reason_and_evidence() {
        let t = test_token();
        let syscall = IkSyscall::IkClose { handle: Uuid::new_v4() };
        let rule = PolicyRule {
            id: "stub-deny".into(),
            description: "always deny".into(),
            evaluate: |_, _| PolicyResult::Deny {
                reason: "blocked".into(),
                evidence: vec![Evidence::TTLExpired],
            },
        };
        let result = (rule.evaluate)(&t, &syscall);
        assert!(matches!(result, PolicyResult::Deny { .. }));
    }
}
