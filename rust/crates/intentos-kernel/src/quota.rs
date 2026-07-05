//! Per-token quota enforcement for the syscall dispatch layer.

use crate::syscall_envelope::IkSyscall;
use crate::token_verifier::VerifiedToken;
use std::time::{SystemTime, UNIX_EPOCH};

/// Check quota limits **before** executing a syscall.
///
/// Returns `Err` with a denial reason if any limit would be exceeded or the TTL
/// has expired.  The token's counters are *not* modified by this function;
/// call [`apply_quota`] after a successful dispatch to update them.
pub fn enforce_quota(token: &VerifiedToken, syscall: &IkSyscall) -> Result<(), String> {
    // TTL enforcement
    if let Some(ttl) = token.quota.ttl_ms {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("time error: {e}"))?
            .as_millis() as u64;

        let expires_at = token
            .quota
            .issued_at_ms
            .checked_add(ttl)
            .ok_or_else(|| "quota TTL overflow".to_string())?;

        if now > expires_at {
            return Err("quota TTL expired".into());
        }
    }

    // Request count enforcement
    if let Some(max) = token.quota.max_requests {
        if token.quota.requests_used >= max {
            return Err("quota max_requests exceeded".into());
        }
    }

    // Byte enforcement (only for read/write syscalls)
    match syscall {
        IkSyscall::IkRead { len, .. } => {
            if let Some(max) = token.quota.max_bytes {
                let projected = token
                    .quota
                    .bytes_used
                    .checked_add(*len)
                    .ok_or_else(|| "quota bytes_used overflow".to_string())?;
                if projected > max {
                    return Err("quota max_bytes exceeded".into());
                }
            }
        }
        IkSyscall::IkWrite { data, .. } => {
            let len = data.len() as u64;
            if let Some(max) = token.quota.max_bytes {
                let projected = token
                    .quota
                    .bytes_used
                    .checked_add(len)
                    .ok_or_else(|| "quota bytes_used overflow".to_string())?;
                if projected > max {
                    return Err("quota max_bytes exceeded".into());
                }
            }
        }
        _ => {}
    }

    Ok(())
}

/// Update the token's usage counters **after** a syscall completes successfully.
///
/// Call this only when the syscall returned `Ok`; on errors the resources were
/// not consumed so counters should not be incremented.
pub fn apply_quota(token: &mut VerifiedToken, syscall: &IkSyscall, result: &Result<serde_json::Value, String>) {
    if result.is_err() {
        return;
    }

    token.quota.requests_used += 1;

    match syscall {
        IkSyscall::IkRead { len, .. } => {
            token.quota.bytes_used += len;
        }
        IkSyscall::IkWrite { data, .. } => {
            token.quota.bytes_used += data.len() as u64;
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_schema::{FsOp, FsScope, TokenScope};
    use crate::token_verifier::TokenQuota;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use uuid::Uuid;

    fn make_token(quota: TokenQuota) -> VerifiedToken {
        VerifiedToken {
            id: Uuid::new_v4(),
            issued_to: "test".into(),
            expires_at: SystemTime::now() + Duration::from_secs(3600),
            scope: TokenScope::Fs(FsScope {
                path_prefix: "/tmp".into(),
                ops: vec![FsOp::Read, FsOp::Write],
            }),
            quota,
        }
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    #[test]
    fn quota_allows_within_limits() {
        let token = make_token(TokenQuota {
            max_bytes: Some(1000),
            max_requests: Some(10),
            ttl_ms: Some(60_000),
            bytes_used: 0,
            requests_used: 0,
            issued_at_ms: now_ms(),
        });
        let syscall = IkSyscall::IkRead { handle: Uuid::new_v4(), len: 100 };
        assert!(enforce_quota(&token, &syscall).is_ok());
    }

    #[test]
    fn quota_denies_max_requests_exceeded() {
        let token = make_token(TokenQuota {
            max_bytes: None,
            max_requests: Some(5),
            ttl_ms: None,
            bytes_used: 0,
            requests_used: 5,
            issued_at_ms: now_ms(),
        });
        let syscall = IkSyscall::IkClose { handle: Uuid::new_v4() };
        let err = enforce_quota(&token, &syscall).unwrap_err();
        assert_eq!(err, "quota max_requests exceeded");
    }

    #[test]
    fn quota_denies_max_bytes_exceeded_on_read() {
        let token = make_token(TokenQuota {
            max_bytes: Some(500),
            max_requests: None,
            ttl_ms: None,
            bytes_used: 450,
            requests_used: 0,
            issued_at_ms: now_ms(),
        });
        let syscall = IkSyscall::IkRead { handle: Uuid::new_v4(), len: 100 };
        let err = enforce_quota(&token, &syscall).unwrap_err();
        assert_eq!(err, "quota max_bytes exceeded");
    }

    #[test]
    fn quota_denies_ttl_expired() {
        let token = make_token(TokenQuota {
            max_bytes: None,
            max_requests: None,
            ttl_ms: Some(1),
            bytes_used: 0,
            requests_used: 0,
            issued_at_ms: now_ms() - 2,
        });
        let syscall = IkSyscall::IkClose { handle: Uuid::new_v4() };
        let err = enforce_quota(&token, &syscall).unwrap_err();
        assert_eq!(err, "quota TTL expired");
    }

    #[test]
    fn apply_quota_increments_counters_on_success() {
        let mut token = make_token(TokenQuota {
            max_bytes: Some(1000),
            max_requests: Some(10),
            ttl_ms: None,
            bytes_used: 0,
            requests_used: 0,
            issued_at_ms: now_ms(),
        });
        let syscall = IkSyscall::IkRead { handle: Uuid::new_v4(), len: 256 };
        let ok: Result<serde_json::Value, String> = Ok(serde_json::json!({}));
        apply_quota(&mut token, &syscall, &ok);
        assert_eq!(token.quota.requests_used, 1);
        assert_eq!(token.quota.bytes_used, 256);
    }

    #[test]
    fn apply_quota_does_not_increment_on_error() {
        let mut token = make_token(TokenQuota {
            max_bytes: Some(1000),
            max_requests: Some(10),
            ttl_ms: None,
            bytes_used: 0,
            requests_used: 0,
            issued_at_ms: now_ms(),
        });
        let syscall = IkSyscall::IkRead { handle: Uuid::new_v4(), len: 256 };
        let err: Result<serde_json::Value, String> = Err("vfs error".into());
        apply_quota(&mut token, &syscall, &err);
        assert_eq!(token.quota.requests_used, 0);
        assert_eq!(token.quota.bytes_used, 0);
    }
}
