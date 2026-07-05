//! IntentKernel Policy Engine (IKPE).
//!
//! The policy engine evaluates every syscall using modular rules, evidence
//! generation, multi-module evaluation, conflict resolution, and full
//! explainability.
//!
//! # Structure
//!
//! | Module | Purpose |
//! |---|---|
//! | [`evidence`] | Evidence variants emitted by rules |
//! | [`rule`] | `PolicyRule` and `PolicyResult` types |
//! | [`registry`] | `RuleRegistry` — ordered collection of rules |
//! | [`evaluator`] | `evaluate()` — multi-rule evaluation with short-circuit denial |
//! | [`rules`] | Built-in rule families (scope, quota, token, sandbox, federation, custom) |
//!
//! # Quick start
//!
//! ```rust,ignore
//! use intentos_kernel::policy_engine::{build_default_registry, evaluator};
//!
//! let registry = build_default_registry();
//! let decision = evaluator::evaluate(&registry, &token, &syscall);
//! if !decision.allow {
//!     return Err(decision.deny_reason.into());
//! }
//! ```

pub mod evidence;
pub mod evaluator;
pub mod registry;
pub mod rule;
pub mod rules;

pub use evaluator::{evaluate, IkpeDecision};
pub use evidence::Evidence;
pub use registry::RuleRegistry;
pub use rule::{PolicyResult, PolicyRule};

use rules::{
    federation_rules::{policy_hash_consistency_rule, remote_kernel_trust_rule},
    quota_rules::{max_bytes_rule, max_requests_rule, ttl_rule},
    sandbox_rules::{sandbox_isolation_rule, sandbox_mode_rule},
    scope_rules::fs_scope_rule,
    token_rules::{token_expiry_rule, token_revocation_rule, token_signature_rule},
};

/// Build the default kernel rule registry.
///
/// The default registry includes all built-in rule families in the recommended
/// evaluation order:
///
/// 1. Token expiry (fastest gate — reject dead tokens first)
/// 2. TTL check (redundant with expiry but explicit in evidence)
/// 3. Token signature (skeleton)
/// 4. Token revocation (skeleton)
/// 5. Scope check
/// 6. Quota — max bytes
/// 7. Quota — max requests
/// 8. Sandbox mode (evidence-only)
/// 9. Sandbox isolation (deny net/AI from sandboxed principals)
/// 10. Federation trust
/// 11. Policy hash consistency
pub fn build_default_registry() -> RuleRegistry {
    let mut r = RuleRegistry::new();
    r.register(token_expiry_rule());
    r.register(ttl_rule());
    r.register(token_signature_rule());
    r.register(token_revocation_rule());
    r.register(fs_scope_rule());
    r.register(max_bytes_rule());
    r.register(max_requests_rule());
    r.register(sandbox_mode_rule());
    r.register(sandbox_isolation_rule());
    r.register(remote_kernel_trust_rule());
    r.register(policy_hash_consistency_rule());
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_schema::{FsOp, FsScope, TokenScope};
    use crate::syscall_envelope::OpenMode;
    use std::time::{Duration, SystemTime};
    use uuid::Uuid;
    use crate::token_verifier::VerifiedToken;

    fn live_token() -> VerifiedToken {
        VerifiedToken {
            id: Uuid::new_v4(),
            issued_to: "app".into(),
            expires_at: SystemTime::now() + Duration::from_secs(3600),
            scope: TokenScope::Fs(FsScope {
                path_prefix: "/tmp".into(),
                ops: vec![FsOp::Read],
            }),
        }
    }

    fn expired_token() -> VerifiedToken {
        VerifiedToken {
            id: Uuid::new_v4(),
            issued_to: "app".into(),
            expires_at: SystemTime::UNIX_EPOCH,
            scope: TokenScope::Fs(FsScope {
                path_prefix: "/tmp".into(),
                ops: vec![FsOp::Read],
            }),
        }
    }

    #[test]
    fn default_registry_has_expected_rule_count() {
        let r = build_default_registry();
        assert_eq!(r.len(), 11);
    }

    #[test]
    fn default_registry_allows_valid_fs_read() {
        let reg = build_default_registry();
        let token = live_token();
        let syscall = crate::syscall_envelope::IkSyscall::IkOpen {
            path: "/tmp/data.txt".into(),
            mode: OpenMode::Read,
        };
        let d = evaluate(&reg, &token, &syscall);
        assert!(d.allow, "expected allow, got: {}", d.deny_reason);
    }

    #[test]
    fn default_registry_denies_expired_token() {
        let reg = build_default_registry();
        let token = expired_token();
        let syscall = crate::syscall_envelope::IkSyscall::IkOpen {
            path: "/tmp/data.txt".into(),
            mode: OpenMode::Read,
        };
        let d = evaluate(&reg, &token, &syscall);
        assert!(!d.allow);
        assert!(d.evidence.iter().any(|e| matches!(e, Evidence::TokenExpired)));
    }

    #[test]
    fn default_registry_denies_out_of_scope_path() {
        let reg = build_default_registry();
        let token = live_token(); // scope = /tmp
        let syscall = crate::syscall_envelope::IkSyscall::IkOpen {
            path: "/etc/shadow".into(),
            mode: OpenMode::Read,
        };
        let d = evaluate(&reg, &token, &syscall);
        assert!(!d.allow);
        assert!(d.evidence.iter().any(|e| matches!(e, Evidence::ScopeMismatch { .. })));
    }
}
