use serde_json::json;

use crate::capability_schema::{AiScope, TokenScope};
use crate::policy_engine::{build_default_registry, evaluate, RuleRegistry};
use crate::quota::{apply_quota, enforce_quota};
use crate::syscall_envelope::{IkCallEnvelope, IkSyscall};
use crate::table::CapabilityTable;
use crate::token_verifier::{verify_with_table, VerifiedToken};
use crate::utilities;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use intentos_audit::{AuditEventKind, AuditLog};

/// Dispatch using an already-verified token after IKPE + quota enforcement.
///
/// When `registry` is `None`, the default IKPE rule stack is used (fail-closed
/// if empty). Quota counters from capability-hardening still apply after IKPE.
pub fn dispatch_call(
    env: IkCallEnvelope,
    token: &mut VerifiedToken,
    audit: Option<&AuditLog>,
    registry: Option<&RuleRegistry>,
) -> Result<serde_json::Value, String> {
    let owned;
    let reg = match registry {
        Some(r) => r,
        None => {
            owned = build_default_registry();
            &owned
        }
    };

    let decision = evaluate(reg, token, &env.call);
    if !decision.allow {
        if let Some(log) = audit {
            let _ = log.record(
                AuditEventKind::Syscall,
                &token.issued_to,
                format!(
                    "syscall={} token={} outcome=ikpe_deny reason={}",
                    syscall_name(&env.call),
                    token.id,
                    decision.deny_reason
                ),
            );
        }
        return Err(format!("ikpe deny: {}", decision.deny_reason));
    }

    enforce_quota(token, &env.call)?;

    let syscall_name = syscall_name(&env.call);
    let result = match &env.call {
        IkSyscall::IkOpen { path, mode } => {
            match utilities::host_vfs::vfs_open(&token.id, path, *mode) {
                Ok(handle) => Ok(json!({"handle": handle.to_string()})),
                Err(e) => Err(format!("vfs_open error: {e}")),
            }
        }
        IkSyscall::IkRead { handle, len } => {
            match utilities::host_vfs::vfs_read(&token.id, *handle, *len) {
                Ok(bytes) => Ok(json!({"data": BASE64.encode(&bytes)})),
                Err(e) => Err(format!("vfs_read error: {e}")),
            }
        }
        IkSyscall::IkWrite { handle, data } => {
            match utilities::host_vfs::vfs_write(&token.id, *handle, data) {
                Ok(()) => Ok(json!({"written": data.len()})),
                Err(e) => Err(format!("vfs_write error: {e}")),
            }
        }
        IkSyscall::IkClose { handle } => match utilities::host_vfs::vfs_close(&token.id, *handle) {
            Ok(()) => Ok(json!({"closed": true})),
            Err(e) => Err(format!("vfs_close error: {e}")),
        },
        IkSyscall::IkAiInfer {
            model,
            prompt,
            max_tokens,
        } => {
            let scope = ai_scope_for_model(&token.scope, model)
                .ok_or_else(|| "ai scope not found for model".to_string())?;
            match utilities::ai_backend::infer_scoped(&token.id, scope, prompt, *max_tokens) {
                Ok(output) => Ok(json!({ "output": output })),
                Err(e) => Err(format!("ai_infer error: {e}")),
            }
        }
        IkSyscall::IkNetRequest { .. } => Err("network syscall not implemented in demo".into()),
        IkSyscall::IkFederationHello { .. }
        | IkSyscall::IkFederationWelcome { .. }
        | IkSyscall::IkForward { .. }
        | IkSyscall::IkTaskDelegate { .. } => {
            Err("federation syscall requires FederationCluster context".into())
        }
    };

    apply_quota(token, &env.call, &result);

    if let Some(log) = audit {
        let outcome = match &result {
            Ok(_) => "ok".to_string(),
            Err(e) => format!("err: {e}"),
        };
        // Audit failures are intentionally non-fatal.
        let _ = log.record(
            AuditEventKind::Syscall,
            &token.issued_to,
            format!(
                "syscall={syscall_name} token={} outcome={outcome} ikpe={}",
                token.id,
                decision.summary()
            ),
        );
    }

    result
}

/// Verify `env.token_id` against the capability table, then dispatch.
pub fn dispatch_with_table(
    env: IkCallEnvelope,
    table: &CapabilityTable,
    audit: Option<&AuditLog>,
) -> Result<serde_json::Value, String> {
    let mut token = verify_with_table(table, &env.token_id)
        .map_err(|e| format!("token verification failed: {e}"))?;
    dispatch_call(env, &mut token, audit, None)
}

fn ai_scope_for_model<'a>(scope: &'a TokenScope, model: &str) -> Option<&'a AiScope> {
    match scope {
        TokenScope::Ai(ai) => {
            if ai.model == "*" || ai.model.eq_ignore_ascii_case(model) {
                Some(ai)
            } else {
                None
            }
        }
        TokenScope::Composite(scopes) => scopes.iter().find_map(|s| ai_scope_for_model(s, model)),
        _ => None,
    }
}

fn syscall_name(call: &IkSyscall) -> &'static str {
    match call {
        IkSyscall::IkOpen { .. } => "IkOpen",
        IkSyscall::IkRead { .. } => "IkRead",
        IkSyscall::IkWrite { .. } => "IkWrite",
        IkSyscall::IkClose { .. } => "IkClose",
        IkSyscall::IkAiInfer { .. } => "IkAiInfer",
        IkSyscall::IkNetRequest { .. } => "IkNetRequest",
        IkSyscall::IkFederationHello { .. } => "IkFederationHello",
        IkSyscall::IkFederationWelcome { .. } => "IkFederationWelcome",
        IkSyscall::IkForward { .. } => "IkForward",
        IkSyscall::IkTaskDelegate { .. } => "IkTaskDelegate",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_schema::{FsOp, FsScope};
    use crate::syscall_envelope::OpenMode;
    use crate::token_verifier::{TokenQuota, VerifiedToken};
    use std::time::{Duration, SystemTime};
    use uuid::Uuid;

    #[test]
    fn finds_model_in_composite_scope() {
        let scope = TokenScope::Composite(vec![
            TokenScope::Fs(FsScope {
                path_prefix: "/tmp/intentos_root".to_string(),
                ops: vec![FsOp::Read],
            }),
            TokenScope::Ai(crate::capability_schema::AiScope {
                model: "gpt-4o-mini".to_string(),
                max_tokens: Some(64),
            }),
        ]);
        assert!(ai_scope_for_model(&scope, "GPT-4O-mini").is_some());
    }

    #[test]
    fn default_deny_unknown_net_without_scope() {
        let mut token = VerifiedToken {
            id: Uuid::new_v4(),
            issued_to: "t".into(),
            expires_at: SystemTime::now() + Duration::from_secs(60),
            scope: TokenScope::Fs(FsScope {
                path_prefix: "/tmp/intentos_root".into(),
                ops: vec![FsOp::Read],
            }),
            quota: TokenQuota::unlimited_now(),
        };
        let env = IkCallEnvelope {
            token_id: token.id,
            call: IkSyscall::IkOpen {
                path: "/etc/passwd".into(),
                mode: OpenMode::Read,
            },
            call_id: Uuid::new_v4(),
            timestamp_ms: 0,
        };
        let err = dispatch_call(env, &mut token, None, None).unwrap_err();
        assert!(
            err.contains("ikpe deny") || err.contains("scope") || err.contains("path"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn ikpe_blocks_out_of_scope_before_vfs() {
        let mut token = VerifiedToken {
            id: Uuid::new_v4(),
            issued_to: "app".into(),
            expires_at: SystemTime::now() + Duration::from_secs(3600),
            scope: TokenScope::Fs(FsScope {
                path_prefix: "/tmp".into(),
                ops: vec![FsOp::Read],
            }),
            quota: TokenQuota::unlimited_now(),
        };
        let env = IkCallEnvelope {
            token_id: token.id,
            call: IkSyscall::IkOpen {
                path: "/etc/passwd".into(),
                mode: OpenMode::Read,
            },
            call_id: Uuid::new_v4(),
            timestamp_ms: 0,
        };
        let err = dispatch_call(env, &mut token, None, None).unwrap_err();
        assert!(err.contains("ikpe deny"), "{err}");
    }
}
