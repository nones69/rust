//! Module B — Quota and TTL rules.
//!
//! These rules enforce byte/request quotas and token lifetime windows.  They
//! read quota metadata from the token's `issued_to` field in production; the
//! implementation here is a clean policy skeleton that always passes unless
//! you inject quota data via the token's `scope` metadata.
//!
//! In a real kernel you would attach quota state to the token or look it up in
//! a shared quota table.  The rules below check what is available from the
//! `VerifiedToken` alone and emit appropriate evidence.

use std::time::SystemTime;

use crate::capability_schema::TokenScope;
use crate::policy_engine::evidence::Evidence;
use crate::policy_engine::rule::{PolicyResult, PolicyRule};
use crate::syscall_envelope::IkSyscall;
use crate::token_verifier::VerifiedToken;

// ── TTL rule ─────────────────────────────────────────────────────────────────

fn evaluate_ttl(token: &VerifiedToken, _syscall: &IkSyscall) -> PolicyResult {
    if token.expires_at > SystemTime::now() {
        PolicyResult::Allow { evidence: vec![Evidence::TTLValid] }
    } else {
        PolicyResult::Deny {
            reason: "token TTL has expired".into(),
            evidence: vec![Evidence::TTLExpired],
        }
    }
}

/// Denies syscalls from an expired token (TTL check).
pub fn ttl_rule() -> PolicyRule {
    PolicyRule {
        id: "ttl-check".into(),
        description: "Deny syscalls from tokens whose TTL has elapsed".into(),
        evaluate: evaluate_ttl,
    }
}

// ── Max-bytes rule ────────────────────────────────────────────────────────────

fn evaluate_max_bytes(token: &VerifiedToken, syscall: &IkSyscall) -> PolicyResult {
    // Extract max_tokens from AI scope as a byte-analogue for AI calls.
    // For Fs/Net/Composite we have no byte counter in VerifiedToken; pass through.
    let limit = match &token.scope {
        TokenScope::Ai(ai) => ai.max_tokens,
        _ => None,
    };

    if let Some(limit) = limit {
        if let IkSyscall::IkAiInfer { max_tokens: Some(requested), .. } = syscall {
            if *requested > limit {
                return PolicyResult::Deny {
                    reason: format!(
                        "max_tokens {requested} exceeds quota limit {limit}"
                    ),
                    evidence: vec![Evidence::QuotaExceeded { field: "max_tokens".into() }],
                };
            }
        }
        PolicyResult::Allow {
            evidence: vec![Evidence::QuotaRemaining {
                bytes: limit,
                requests: 1,
            }],
        }
    } else {
        PolicyResult::Allow {
            evidence: vec![Evidence::QuotaRemaining { bytes: u64::MAX, requests: u64::MAX }],
        }
    }
}

/// Enforces the maximum-bytes (max_tokens for AI) quota.
pub fn max_bytes_rule() -> PolicyRule {
    PolicyRule {
        id: "quota-max-bytes".into(),
        description: "Enforce the token's byte/token quota".into(),
        evaluate: evaluate_max_bytes,
    }
}

// ── Max-requests rule (placeholder — no per-token request counter yet) ────────

fn evaluate_max_requests(_token: &VerifiedToken, _syscall: &IkSyscall) -> PolicyResult {
    // No per-token request counter is available in VerifiedToken today.
    // Pass through and emit headroom evidence.
    PolicyResult::Allow {
        evidence: vec![Evidence::QuotaRemaining { bytes: u64::MAX, requests: u64::MAX }],
    }
}

/// Enforces the maximum-requests quota (currently a pass-through skeleton).
pub fn max_requests_rule() -> PolicyRule {
    PolicyRule {
        id: "quota-max-requests".into(),
        description: "Enforce the token's request-count quota".into(),
        evaluate: evaluate_max_requests,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_schema::{AiScope, FsOp, FsScope, TokenScope};
    use crate::policy_engine::rule::PolicyResult;
    use crate::syscall_envelope::OpenMode;
    use std::time::{Duration, SystemTime};
    use uuid::Uuid;

    fn fs_token(expires_in: Option<Duration>) -> VerifiedToken {
        VerifiedToken {
            id: Uuid::new_v4(),
            issued_to: "tester".into(),
            expires_at: expires_in
                .map(|d| SystemTime::now() + d)
                .unwrap_or(SystemTime::UNIX_EPOCH),
            scope: TokenScope::Fs(FsScope {
                path_prefix: "/tmp".into(),
                ops: vec![FsOp::Read],
            }),
        }
    }

    fn ai_token(max_tokens: Option<u64>) -> VerifiedToken {
        VerifiedToken {
            id: Uuid::new_v4(),
            issued_to: "tester".into(),
            expires_at: SystemTime::now() + Duration::from_secs(3600),
            scope: TokenScope::Ai(AiScope {
                model: "gpt-4".into(),
                max_tokens,
            }),
        }
    }

    #[test]
    fn ttl_rule_allows_valid_token() {
        let token = fs_token(Some(Duration::from_secs(3600)));
        let syscall = IkSyscall::IkOpen { path: "/tmp/x".into(), mode: OpenMode::Read };
        let rule = ttl_rule();
        assert!(matches!((rule.evaluate)(&token, &syscall), PolicyResult::Allow { .. }));
    }

    #[test]
    fn ttl_rule_denies_expired_token() {
        let token = fs_token(None); // expires_at = UNIX_EPOCH = in the past
        let syscall = IkSyscall::IkOpen { path: "/tmp/x".into(), mode: OpenMode::Read };
        let rule = ttl_rule();
        assert!(matches!((rule.evaluate)(&token, &syscall), PolicyResult::Deny { .. }));
    }

    #[test]
    fn max_bytes_rule_allows_within_limit() {
        let token = ai_token(Some(1000));
        let syscall = IkSyscall::IkAiInfer { prompt: "hi".into(), max_tokens: Some(500) };
        let rule = max_bytes_rule();
        assert!(matches!((rule.evaluate)(&token, &syscall), PolicyResult::Allow { .. }));
    }

    #[test]
    fn max_bytes_rule_denies_over_limit() {
        let token = ai_token(Some(100));
        let syscall = IkSyscall::IkAiInfer { prompt: "hi".into(), max_tokens: Some(200) };
        let rule = max_bytes_rule();
        assert!(matches!((rule.evaluate)(&token, &syscall), PolicyResult::Deny { .. }));
    }
}
