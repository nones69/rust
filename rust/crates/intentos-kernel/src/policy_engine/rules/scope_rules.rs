//! Module A — Scope rules.
//!
//! These rules verify that the syscall falls within the scope encoded in the
//! token.  One rule is provided per scope kind; the `CompositeScopeRule` is
//! satisfied when at least one inner scope permits the call.

use crate::capability_schema::TokenScope;
use crate::policy_engine::evidence::Evidence;
use crate::policy_engine::rule::{PolicyResult, PolicyRule};
use crate::syscall_envelope::IkSyscall;
use crate::token_verifier::VerifiedToken;

fn scope_label(scope: &TokenScope) -> String {
    match scope {
        TokenScope::Fs(s) => format!("fs:{}", s.path_prefix),
        TokenScope::Net(s) => format!("net:{}", s.hosts.join(",")),
        TokenScope::Ai(s) => format!("ai:{}", s.model),
        TokenScope::Composite(_) => "composite".into(),
    }
}

fn evaluate_scope(token: &VerifiedToken, syscall: &IkSyscall) -> PolicyResult {
    if token.scope.permits(syscall) {
        PolicyResult::Allow {
            evidence: vec![Evidence::ScopeMatch {
                scope: scope_label(&token.scope),
            }],
        }
    } else {
        let label = scope_label(&token.scope);
        PolicyResult::Deny {
            reason: format!("syscall not permitted by token scope: {label}"),
            evidence: vec![Evidence::ScopeMismatch { scope: label }],
        }
    }
}

/// Evaluates the token's Fs, Net, Ai, or Composite scope against the syscall.
pub fn fs_scope_rule() -> PolicyRule {
    PolicyRule {
        id: "fs-scope".into(),
        description: "Verify the syscall is within the token's filesystem scope".into(),
        evaluate: evaluate_scope,
    }
}

/// Alias — Net scope enforcement uses the same logic as `fs_scope_rule`.
pub fn net_scope_rule() -> PolicyRule {
    PolicyRule {
        id: "net-scope".into(),
        description: "Verify the syscall is within the token's network scope".into(),
        evaluate: evaluate_scope,
    }
}

/// Alias — AI scope enforcement.
pub fn ai_scope_rule() -> PolicyRule {
    PolicyRule {
        id: "ai-scope".into(),
        description: "Verify the syscall is within the token's AI scope".into(),
        evaluate: evaluate_scope,
    }
}

/// Composite scope — satisfied when any inner scope permits the call.
pub fn composite_scope_rule() -> PolicyRule {
    PolicyRule {
        id: "composite-scope".into(),
        description: "Verify the syscall is within at least one of the composite scopes".into(),
        evaluate: evaluate_scope,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_schema::{AiScope, FsOp, FsScope, NetScope, TokenScope};
    use crate::policy_engine::rule::PolicyResult;
    use crate::syscall_envelope::{HttpMethod, OpenMode};
    use std::time::{Duration, SystemTime};
    use uuid::Uuid;

    fn make_token(scope: TokenScope) -> VerifiedToken {
        VerifiedToken {
            id: Uuid::new_v4(),
            issued_to: "test".into(),
            expires_at: SystemTime::now() + Duration::from_secs(3600),
            scope,
            quota: crate::token_verifier::TokenQuota::unlimited_now(),
        }
    }

    #[test]
    fn fs_scope_allows_matching_read() {
        let token = make_token(TokenScope::Fs(FsScope {
            path_prefix: "/tmp".into(),
            ops: vec![FsOp::Read],
        }));
        let syscall = IkSyscall::IkOpen {
            path: "/tmp/a.txt".into(),
            mode: OpenMode::Read,
        };
        let rule = fs_scope_rule();
        assert!(matches!(
            (rule.evaluate)(&token, &syscall),
            PolicyResult::Allow { .. }
        ));
    }

    #[test]
    fn fs_scope_denies_out_of_prefix() {
        let token = make_token(TokenScope::Fs(FsScope {
            path_prefix: "/tmp/safe".into(),
            ops: vec![FsOp::Read],
        }));
        let syscall = IkSyscall::IkOpen {
            path: "/etc/passwd".into(),
            mode: OpenMode::Read,
        };
        let rule = fs_scope_rule();
        assert!(matches!(
            (rule.evaluate)(&token, &syscall),
            PolicyResult::Deny { .. }
        ));
    }

    #[test]
    fn net_scope_allows_matching_host() {
        let token = make_token(TokenScope::Net(NetScope {
            hosts: vec!["example.com".into()],
            methods: vec![HttpMethod::GET],
        }));
        let syscall = IkSyscall::IkNetRequest {
            method: HttpMethod::GET,
            url: "https://example.com/api".into(),
            headers: vec![],
            body: vec![],
        };
        let rule = net_scope_rule();
        assert!(matches!(
            (rule.evaluate)(&token, &syscall),
            PolicyResult::Allow { .. }
        ));
    }

    #[test]
    fn ai_scope_allows_under_token_limit() {
        let token = make_token(TokenScope::Ai(AiScope {
            model: "gpt-4".into(),
            max_tokens: Some(1000),
        }));
        let syscall = IkSyscall::IkAiInfer {
            model: "gpt-4".into(),
            prompt: "hello".into(),
            max_tokens: Some(500),
        };
        let rule = ai_scope_rule();
        assert!(matches!(
            (rule.evaluate)(&token, &syscall),
            PolicyResult::Allow { .. }
        ));
    }

    #[test]
    fn composite_scope_allows_when_one_scope_matches() {
        let token = make_token(TokenScope::Composite(vec![
            TokenScope::Fs(FsScope {
                path_prefix: "/tmp".into(),
                ops: vec![FsOp::Read],
            }),
            TokenScope::Net(NetScope {
                hosts: vec!["example.com".into()],
                methods: vec![HttpMethod::GET],
            }),
        ]));
        let syscall = IkSyscall::IkOpen {
            path: "/tmp/a.txt".into(),
            mode: OpenMode::Read,
        };
        let rule = composite_scope_rule();
        assert!(matches!(
            (rule.evaluate)(&token, &syscall),
            PolicyResult::Allow { .. }
        ));
    }
}
