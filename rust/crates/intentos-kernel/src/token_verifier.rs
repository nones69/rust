//! Token verification stub for the kernel dispatch layer.

use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};
use uuid::Uuid;

use crate::capability_schema::{FsOp, FsScope, TokenScope};
use crate::syscall_envelope::IkSyscall;

/// A verified capability token with its core identity fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedToken {
    pub id: Uuid,
    pub issued_to: String,
    pub expires_at: SystemTime,
    pub scope: TokenScope,
}

pub fn verify_token_scope(token: &VerifiedToken, syscall: &IkSyscall) -> Result<(), String> {
    if token.expires_at <= SystemTime::now() {
        return Err("token expired".to_string());
    }
    if !token.scope.permits(syscall) {
        return Err("scope does not permit syscall".to_string());
    }
    Ok(())
}

/// Simple verification stub for local testing.
/// Replace with real lookup and signature verification in production.
pub fn verify_token(token_id: &Uuid) -> Result<VerifiedToken, String> {
    // TODO: replace with real lookup + signature verification.
    let test_token = Uuid::parse_str("11111111-2222-3333-4444-555555555555")
        .map_err(|e| format!("uuid parse error: {}", e))?;

    if token_id == &test_token {
        Ok(VerifiedToken {
            id: *token_id,
            issued_to: "demo-principal".to_string(),
            expires_at: SystemTime::now() + Duration::from_secs(60 * 60),
            scope: TokenScope::Fs(FsScope {
                path_prefix: "/tmp/intentos_root".to_string(),
                ops: vec![FsOp::Read, FsOp::Write],
            }),
        })
    } else {
        Err("unknown token".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscall_envelope::{IkSyscall, OpenMode};

    #[test]
    fn scoped_stub_token_allows_read_open() {
        let id = Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap();
        let t = verify_token(&id).unwrap();
        assert_eq!(t.id, id);
        verify_token_scope(
            &t,
            &IkSyscall::IkOpen {
                path: "/tmp/intentos_root/file.txt".to_string(),
                mode: OpenMode::Read,
            },
        )
        .unwrap();
    }
}
