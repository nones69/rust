//! Module C — Token integrity rules.
//!
//! These rules verify that the token presented is alive and structurally sound.
//! Signature verification (`TokenSignatureRule`) and revocation
//! (`TokenRevocationRule`) require kernel-level key material and are therefore
//! marked as future work; they are included as stubs so the registry has
//! explicit placeholders.

use std::time::SystemTime;

use crate::policy_engine::evidence::Evidence;
use crate::policy_engine::rule::{PolicyResult, PolicyRule};
use crate::syscall_envelope::IkSyscall;
use crate::token_verifier::VerifiedToken;

// ── Token-expiry rule ─────────────────────────────────────────────────────────

fn evaluate_token_expiry(token: &VerifiedToken, _syscall: &IkSyscall) -> PolicyResult {
    if token.expires_at > SystemTime::now() {
        PolicyResult::Allow {
            evidence: vec![Evidence::TokenValid],
        }
    } else {
        PolicyResult::Deny {
            reason: "token has expired".into(),
            evidence: vec![Evidence::TokenExpired],
        }
    }
}

/// Denies syscalls from tokens that have passed their expiry timestamp.
pub fn token_expiry_rule() -> PolicyRule {
    PolicyRule {
        id: "token-expiry".into(),
        description: "Deny syscalls from expired tokens".into(),
        evaluate: evaluate_token_expiry,
    }
}

// ── Token-signature rule (future) ─────────────────────────────────────────────

fn evaluate_token_signature(_token: &VerifiedToken, _syscall: &IkSyscall) -> PolicyResult {
    // TODO: verify cryptographic signature against the broker's public key.
    // For now, assume the token was correctly verified upstream by
    // `verify_token` / `TokenBroker::verify`.
    PolicyResult::Allow {
        evidence: vec![Evidence::TokenValid],
    }
}

/// Verifies the token's cryptographic signature (skeleton — full verification
/// happens in `TokenBroker::verify` before dispatch).
pub fn token_signature_rule() -> PolicyRule {
    PolicyRule {
        id: "token-signature".into(),
        description: "Verify token cryptographic signature (future — currently a pass-through)"
            .into(),
        evaluate: evaluate_token_signature,
    }
}

// ── Token-revocation rule (future) ────────────────────────────────────────────

fn evaluate_token_revocation(_token: &VerifiedToken, _syscall: &IkSyscall) -> PolicyResult {
    // TODO: check token JTI against the kernel RevocationList.
    // Revocation is currently enforced in the `Kernel::syscall` method; this
    // stub provides the rule-registry hook for future inline integration.
    PolicyResult::Allow {
        evidence: vec![Evidence::TokenValid],
    }
}

/// Checks whether the token has been revoked (skeleton — currently enforced
/// in `Kernel::syscall` via `RevocationList`).
pub fn token_revocation_rule() -> PolicyRule {
    PolicyRule {
        id: "token-revocation".into(),
        description: "Deny syscalls from revoked tokens (future — currently a pass-through)".into(),
        evaluate: evaluate_token_revocation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_schema::{FsOp, FsScope, TokenScope};
    use crate::policy_engine::rule::PolicyResult;
    use crate::syscall_envelope::OpenMode;
    use std::time::{Duration, SystemTime};
    use uuid::Uuid;

    fn make_token(expires_at: SystemTime) -> VerifiedToken {
        VerifiedToken {
            id: Uuid::new_v4(),
            issued_to: "test".into(),
            expires_at,
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
    fn expiry_rule_allows_live_token() {
        let token = make_token(SystemTime::now() + Duration::from_secs(3600));
        assert!(matches!(
            (token_expiry_rule().evaluate)(&token, &open_syscall()),
            PolicyResult::Allow { .. }
        ));
    }

    #[test]
    fn expiry_rule_denies_expired_token() {
        let token = make_token(SystemTime::UNIX_EPOCH);
        assert!(matches!(
            (token_expiry_rule().evaluate)(&token, &open_syscall()),
            PolicyResult::Deny { .. }
        ));
    }

    #[test]
    fn signature_rule_passes_through() {
        let token = make_token(SystemTime::now() + Duration::from_secs(60));
        assert!(matches!(
            (token_signature_rule().evaluate)(&token, &open_syscall()),
            PolicyResult::Allow { .. }
        ));
    }

    #[test]
    fn revocation_rule_passes_through() {
        let token = make_token(SystemTime::now() + Duration::from_secs(60));
        assert!(matches!(
            (token_revocation_rule().evaluate)(&token, &open_syscall()),
            PolicyResult::Allow { .. }
        ));
    }
}
