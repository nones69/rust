use serde_json::json;

use crate::policy_inspector;
use crate::syscall_envelope::{IkCallEnvelope, IkSyscall};
use crate::token_verifier::{verify_token_scope, VerifiedToken};
use crate::utilities;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

pub fn dispatch_call(
    env: IkCallEnvelope,
    token: &VerifiedToken,
) -> Result<serde_json::Value, String> {
    match env.call {
        IkSyscall::IkPolicyExplain { syscall } => {
            Ok(policy_inspector::explain(token, syscall.as_ref()))
        }
        call => {
            verify_token_scope(token, &call)?;

            match call {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    use crate::capability_schema::{FsOp, FsScope, TokenScope};
    use uuid::Uuid;

    #[test]
    fn policy_explain_returns_structured_denial_without_executing_syscall() {
        let token = VerifiedToken {
            id: Uuid::new_v4(),
            issued_to: "demo-principal".to_string(),
            expires_at: SystemTime::now() + Duration::from_secs(60),
            scope: TokenScope::Fs(FsScope {
                path_prefix: "/tmp/intentos_root".to_string(),
                ops: vec![FsOp::Read],
            }),
            remaining_uses: Some(4),
        };
        let env = IkCallEnvelope {
            token_id: token.id,
            call: IkSyscall::IkPolicyExplain {
                syscall: Box::new(IkSyscall::IkWrite {
                    handle: Uuid::new_v4(),
                    data: b"hello".to_vec(),
                }),
            },
            call_id: Uuid::new_v4(),
            timestamp_ms: 0,
        };
        let resp = dispatch_call(env, &token).unwrap();
        assert_eq!(resp["decision"], "deny");
        assert_eq!(resp["steps"][1]["step"], "scope_check");
    }
}
