use serde_json::json;

use crate::quota::{apply_quota, enforce_quota};
use crate::syscall_envelope::{IkCallEnvelope, IkSyscall};
use crate::token_verifier::{verify_token_scope, VerifiedToken};
use crate::utilities;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

pub fn dispatch_call(env: IkCallEnvelope, token: &mut VerifiedToken) -> Result<serde_json::Value, String> {
    verify_token_scope(token, &env.call)?;
    enforce_quota(token, &env.call)?;

    let result = match env.call {
        IkSyscall::IkOpen { ref path, ref mode } => {
            match utilities::host_vfs::vfs_open(&token.id, path.as_str(), mode.clone()) {
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
        IkSyscall::IkWrite { handle, ref data } => {
            match utilities::host_vfs::vfs_write(&token.id, handle, data) {
                Ok(()) => Ok(json!({"written": data.len()})),
                Err(e) => Err(format!("vfs_write error: {}", e)),
            }
        }
        _ => Err("syscall not implemented in demo".to_string()),
    };

    apply_quota(token, &env.call, &result);
    result
}
