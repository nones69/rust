use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde_json::json;

use crate::syscall_envelope::{IkCallEnvelope, IkSyscall};
use crate::table::CapabilityTable;
use crate::token_verifier::verify_with_table;
use crate::utilities;

/// Verify the token in `env` against the capability table, then dispatch
/// the requested syscall.  Returns a JSON response or an error string.
pub fn dispatch_call(env: IkCallEnvelope, table: &CapabilityTable) -> Result<serde_json::Value, String> {
    let token = verify_with_table(table, &env.token_id)
        .map_err(|e| format!("token verification failed: {e}"))?;

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
        IkSyscall::IkClose { handle } => {
            match utilities::host_vfs::vfs_close(&token.id, handle) {
                Ok(()) => Ok(json!({"closed": true})),
                Err(e) => Err(format!("vfs_close error: {}", e)),
            }
        }
        _ => Err("syscall not implemented in demo".to_string()),
    }
}
