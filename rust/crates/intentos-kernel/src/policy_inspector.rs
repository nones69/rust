use serde_json::{json, Value};
use sha3::{Digest, Sha3_256};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::syscall_envelope::IkSyscall;
use crate::token_verifier::VerifiedToken;

pub fn explain(token: &VerifiedToken, syscall: &IkSyscall) -> Value {
    let now = SystemTime::now();
    let expires_at_ms = unix_ms(token.expires_at);
    let ttl_ms_remaining = token
        .expires_at
        .duration_since(now)
        .ok()
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0);
    let mut steps = vec![];

    let token_valid = token.expires_at > now;
    steps.push(json!({
        "step": "token_expiry",
        "result": if token_valid { "allow" } else { "deny" },
        "reason": if token_valid { "token still valid" } else { "token expired" },
        "expires_at_ms": expires_at_ms,
        "ttl_ms_remaining": ttl_ms_remaining,
    }));
    if !token_valid {
        return finalize("deny", steps);
    }

    let scope_ok = token.scope.permits(syscall);
    steps.push(json!({
        "step": "scope_check",
        "result": if scope_ok { "allow" } else { "deny" },
        "matched_scope": format!("{:?}", token.scope),
        "requested_syscall": format!("{:?}", syscall),
    }));
    if !scope_ok {
        return finalize("deny", steps);
    }

    let quota_ok = !matches!(token.remaining_uses, Some(0));
    steps.push(json!({
        "step": "quota_check",
        "result": if quota_ok { "allow" } else { "deny" },
        "remaining_uses": token.remaining_uses,
        "reason": if quota_ok { "quota available" } else { "token quota exhausted" },
    }));
    if !quota_ok {
        return finalize("deny", steps);
    }

    steps.push(json!({
        "step": "policy_modules",
        "result": "allow",
        "modules": ["token_verifier", "default"],
    }));
    steps.push(json!({
        "step": "evidence",
        "result": "allow",
        "evidence": {
            "token_id": token.id,
            "issued_to": token.issued_to,
            "scope": format!("{:?}", token.scope),
            "syscall": format!("{:?}", syscall),
        },
    }));

    finalize("allow", steps)
}

fn finalize(decision: &str, steps: Vec<Value>) -> Value {
    let payload = json!({
        "decision": decision,
        "steps": steps,
    });
    let encoded = serde_json::to_vec(&payload).expect("policy explanation serializes");
    let audit_hash = hex_hash(&encoded);

    json!({
        "decision": decision,
        "steps": payload["steps"].clone(),
        "audit_hash": audit_hash,
    })
}

fn unix_ms(ts: SystemTime) -> u64 {
    ts.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn hex_hash(bytes: &[u8]) -> String {
    let digest = Sha3_256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};
    use uuid::Uuid;

    use crate::capability_schema::{FsOp, FsScope, TokenScope};

    fn demo_token(
        expires_at: SystemTime,
        ops: Vec<FsOp>,
        remaining_uses: Option<u32>,
    ) -> VerifiedToken {
        VerifiedToken {
            id: Uuid::new_v4(),
            issued_to: "demo-principal".to_string(),
            expires_at,
            scope: TokenScope::Fs(FsScope {
                path_prefix: "/tmp/intentos_root".to_string(),
                ops,
            }),
            remaining_uses,
        }
    }

    #[test]
    fn explain_denies_expired_tokens() {
        let token = demo_token(
            SystemTime::now() - Duration::from_secs(1),
            vec![FsOp::Read],
            Some(1),
        );
        let resp = explain(
            &token,
            &IkSyscall::IkRead {
                handle: Uuid::new_v4(),
                len: 1,
            },
        );
        assert_eq!(resp["decision"], "deny");
        assert_eq!(resp["steps"][0]["step"], "token_expiry");
    }

    #[test]
    fn explain_denies_exhausted_quota() {
        let token = demo_token(
            SystemTime::now() + Duration::from_secs(60),
            vec![FsOp::Read],
            Some(0),
        );
        let resp = explain(
            &token,
            &IkSyscall::IkRead {
                handle: Uuid::new_v4(),
                len: 1,
            },
        );
        assert_eq!(resp["decision"], "deny");
        assert_eq!(resp["steps"][2]["step"], "quota_check");
    }

    #[test]
    fn explain_returns_audit_hash_for_allowed_calls() {
        let token = demo_token(
            SystemTime::now() + Duration::from_secs(60),
            vec![FsOp::Read],
            Some(8),
        );
        let resp = explain(
            &token,
            &IkSyscall::IkRead {
                handle: Uuid::new_v4(),
                len: 32,
            },
        );
        assert_eq!(resp["decision"], "allow");
        assert!(resp["audit_hash"].as_str().unwrap().len() == 64);
        assert_eq!(resp["steps"][3]["step"], "policy_modules");
        assert_eq!(resp["steps"][4]["step"], "evidence");
    }
}
