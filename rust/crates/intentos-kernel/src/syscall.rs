use serde_json::json;

use crate::syscall_envelope::{IkCallEnvelope, IkSyscall};
use crate::token_verifier::{verify_token_scope, VerifiedToken};
use crate::utilities;
use crate::policy_engine::{evaluate as ikpe_evaluate, RuleRegistry};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

/// Dispatch a kernel syscall after scope and policy-engine validation.
///
/// The caller is responsible for providing a pre-built `RuleRegistry`.  In
/// production the registry is created once at kernel boot via
/// [`build_default_registry`](crate::policy_engine::build_default_registry) and
/// reused for every syscall, avoiding per-call allocation overhead.
pub fn dispatch_call(
    env: IkCallEnvelope,
    token: &VerifiedToken,
    registry: &RuleRegistry,
) -> Result<serde_json::Value, String> {
    verify_token_scope(token, &env.call)?;

    // ── Policy engine evaluation ──────────────────────────────────────────────
    // Evaluate every registered rule before executing the syscall.  A denial
    // short-circuits dispatch and the full evidence chain is returned in the
    // error so callers can surface it to the audit log.
    let decision = ikpe_evaluate(registry, token, &env.call);
    if !decision.allow {
        return Err(format!("policy denied syscall: {}", decision.summary()));
    }

    match env.call {
        IkSyscall::IkOpen { path, mode } => {
            match utilities::host_vfs::vfs_open(&token.id, &path, mode) {
                Ok(handle) => Ok(json!({"handle": handle.to_string()})),
                Err(e) => Err(format!("vfs_open error: {}", e)),
            }
        }
        IkSyscall::IkRead { handle, len } => {
            match utilities::host_vfs::vfs_read(&token.id, handle, len) {
                Ok(bytes) => Ok(json!({"data": BASE64.encode(&bytes)})),
                Err(e) => Err(format!("vfs_read error: {}", e)),
            }
        }
        IkSyscall::IkWrite { handle, data } => {
            match utilities::host_vfs::vfs_write(&token.id, handle, &data) {
                Ok(()) => Ok(json!({"written": data.len()})),
                Err(e) => Err(format!("vfs_write error: {}", e)),
            }
        }
        _ => Err("syscall not implemented in demo".to_string()),
    }
}
