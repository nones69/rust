use serde_json::json;

use crate::syscall_envelope::{IkCallEnvelope, IkSyscall};
use crate::token_verifier::{verify_token_scope, VerifiedToken};
use crate::utilities;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

pub fn dispatch_call(env: IkCallEnvelope, token: &VerifiedToken) -> Result<serde_json::Value, String> {
    verify_token_scope(token, &env.call)?;

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
        IkSyscall::IkFederationHello { .. }
        | IkSyscall::IkFederationWelcome { .. }
        | IkSyscall::IkForward { .. }
        | IkSyscall::IkTaskDelegate { .. } => {
            Err("federation syscalls require a FederationCluster context".to_string())
        }
        _ => Err("syscall not implemented in demo".to_string()),
    }
}
