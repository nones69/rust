//! Module D — Sandbox rules.
//!
//! Sandbox rules enforce isolation boundaries.  Whether a syscall originates
//! from a sandboxed context is determined by metadata on the token's
//! `issued_to` field: a principal whose name starts with `"sandbox:"` is
//! treated as sandboxed.  Applications can extend this convention.

use crate::policy_engine::evidence::Evidence;
use crate::policy_engine::rule::{PolicyResult, PolicyRule};
use crate::syscall_envelope::IkSyscall;
use crate::token_verifier::VerifiedToken;

fn is_sandboxed(token: &VerifiedToken) -> bool {
    token.issued_to.starts_with("sandbox:")
}

// ── Sandbox-mode rule ─────────────────────────────────────────────────────────

fn evaluate_sandbox_mode(token: &VerifiedToken, _syscall: &IkSyscall) -> PolicyResult {
    if is_sandboxed(token) {
        PolicyResult::Allow { evidence: vec![Evidence::SandboxIsolated] }
    } else {
        // Non-sandboxed principals are allowed; they just emit different evidence.
        PolicyResult::Allow { evidence: vec![Evidence::SandboxUnisolated] }
    }
}

/// Emits sandbox-mode evidence; does not deny non-sandboxed principals.
pub fn sandbox_mode_rule() -> PolicyRule {
    PolicyRule {
        id: "sandbox-mode".into(),
        description: "Record whether the caller is running in sandbox mode".into(),
        evaluate: evaluate_sandbox_mode,
    }
}

// ── Sandbox-isolation rule ────────────────────────────────────────────────────

fn evaluate_sandbox_isolation(token: &VerifiedToken, syscall: &IkSyscall) -> PolicyResult {
    if !is_sandboxed(token) {
        return PolicyResult::Allow { evidence: vec![Evidence::SandboxUnisolated] };
    }

    // Sandboxed principals may not perform network or AI calls.
    match syscall {
        IkSyscall::IkNetRequest { .. } => PolicyResult::Deny {
            reason: "sandbox isolation: network calls are not permitted".into(),
            evidence: vec![Evidence::SandboxIsolated],
        },
        IkSyscall::IkAiInfer { .. } => PolicyResult::Deny {
            reason: "sandbox isolation: AI inference is not permitted".into(),
            evidence: vec![Evidence::SandboxIsolated],
        },
        _ => PolicyResult::Allow { evidence: vec![Evidence::SandboxIsolated] },
    }
}

/// Denies network and AI syscalls from sandboxed principals.
pub fn sandbox_isolation_rule() -> PolicyRule {
    PolicyRule {
        id: "sandbox-isolation".into(),
        description: "Block network and AI syscalls from sandboxed principals".into(),
        evaluate: evaluate_sandbox_isolation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_schema::{FsOp, FsScope, TokenScope};
    use crate::policy_engine::rule::PolicyResult;
    use crate::syscall_envelope::{HttpMethod, OpenMode};
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
        }
    }

    #[test]
    fn sandbox_mode_emits_isolated_for_sandboxed_principal() {
        let t = make_token("sandbox:my-app");
        let result = (sandbox_mode_rule().evaluate)(
            &t,
            &IkSyscall::IkOpen { path: "/tmp/x".into(), mode: OpenMode::Read },
        );
        assert!(matches!(result, PolicyResult::Allow { evidence } if evidence.contains(&Evidence::SandboxIsolated)));
    }

    #[test]
    fn sandbox_mode_emits_unisolated_for_normal_principal() {
        let t = make_token("my-app");
        let result = (sandbox_mode_rule().evaluate)(
            &t,
            &IkSyscall::IkOpen { path: "/tmp/x".into(), mode: OpenMode::Read },
        );
        assert!(matches!(result, PolicyResult::Allow { evidence } if evidence.contains(&Evidence::SandboxUnisolated)));
    }

    #[test]
    fn sandbox_isolation_blocks_net_from_sandbox() {
        let t = make_token("sandbox:my-app");
        let syscall = IkSyscall::IkNetRequest {
            method: HttpMethod::GET,
            url: "https://example.com".into(),
            headers: vec![],
            body: vec![],
        };
        let result = (sandbox_isolation_rule().evaluate)(&t, &syscall);
        assert!(matches!(result, PolicyResult::Deny { .. }));
    }

    #[test]
    fn sandbox_isolation_blocks_ai_from_sandbox() {
        let t = make_token("sandbox:my-app");
        let syscall = IkSyscall::IkAiInfer { prompt: "hi".into(), max_tokens: None };
        let result = (sandbox_isolation_rule().evaluate)(&t, &syscall);
        assert!(matches!(result, PolicyResult::Deny { .. }));
    }

    #[test]
    fn sandbox_isolation_allows_fs_from_sandbox() {
        let t = make_token("sandbox:my-app");
        let syscall = IkSyscall::IkOpen { path: "/tmp/x".into(), mode: OpenMode::Read };
        let result = (sandbox_isolation_rule().evaluate)(&t, &syscall);
        assert!(matches!(result, PolicyResult::Allow { .. }));
    }

    #[test]
    fn sandbox_isolation_allows_net_from_normal_principal() {
        let t = make_token("my-app");
        let syscall = IkSyscall::IkNetRequest {
            method: HttpMethod::GET,
            url: "https://example.com".into(),
            headers: vec![],
            body: vec![],
        };
        let result = (sandbox_isolation_rule().evaluate)(&t, &syscall);
        assert!(matches!(result, PolicyResult::Allow { .. }));
    }
}
