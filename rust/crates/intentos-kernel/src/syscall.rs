use serde_json::json;

use crate::syscall_envelope::{IkCallEnvelope, IkSyscall};
use crate::token_verifier::{verify_token_scope, VerifiedToken};
use crate::utilities;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use intentos_audit::{AuditEventKind, AuditLog};

pub fn dispatch_call(
    env: IkCallEnvelope,
    token: &VerifiedToken,
    audit: Option<&AuditLog>,
) -> Result<serde_json::Value, String> {
    verify_token_scope(token, &env.call)?;

    let syscall_name = syscall_name(&env.call);

    let result = match env.call {
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
    };

    if let Some(log) = audit {
        let outcome = match &result {
            Ok(_) => "ok".to_string(),
            Err(e) => format!("err: {e}"),
        };
        // Audit failures are intentionally non-fatal: the syscall result
        // must be delivered regardless of whether the log write succeeds
        // (e.g. disk full).  Silencing the error here is by design.
        let _ = log.record(
            AuditEventKind::Syscall,
            &token.issued_to,
            format!("syscall={syscall_name} token={} outcome={outcome}", token.id),
        );
    }

    result
}

fn syscall_name(call: &IkSyscall) -> &'static str {
    match call {
        IkSyscall::IkOpen { .. } => "IkOpen",
        IkSyscall::IkRead { .. } => "IkRead",
        IkSyscall::IkWrite { .. } => "IkWrite",
        IkSyscall::IkClose { .. } => "IkClose",
        IkSyscall::IkAiInfer { .. } => "IkAiInfer",
        IkSyscall::IkNetRequest { .. } => "IkNetRequest",
    }
}
