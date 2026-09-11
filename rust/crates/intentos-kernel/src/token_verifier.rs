//! Token verification for the kernel dispatch layer.

use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::capability_schema::{AiScope, FsOp, FsScope, NetScope, TokenScope};
use crate::syscall_envelope::{HttpMethod, IkSyscall};
use crate::table::CapabilityTable;
use crate::types::{wall_ms, CapabilityKind, CapabilityScope, SlotEntry};

lazy_static! {
    static ref TEST_TOKEN_ID: Uuid =
        Uuid::parse_str("11111111-2222-3333-4444-555555555555").expect("valid test token UUID");
}

/// Per-token resource quota limits and usage counters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenQuota {
    pub max_bytes: Option<u64>,
    pub max_requests: Option<u64>,
    pub ttl_ms: Option<u64>,
    pub bytes_used: u64,
    pub requests_used: u64,
    pub issued_at_ms: u64,
}

impl TokenQuota {
    pub fn unlimited_now() -> Self {
        Self {
            max_bytes: None,
            max_requests: None,
            ttl_ms: None,
            bytes_used: 0,
            requests_used: 0,
            issued_at_ms: wall_ms(),
        }
    }

    pub fn demo_defaults() -> Self {
        Self {
            max_bytes: Some(10_000),
            max_requests: Some(100),
            ttl_ms: Some(60_000),
            bytes_used: 0,
            requests_used: 0,
            issued_at_ms: wall_ms(),
        }
    }
}

/// A verified capability token with identity, scope, and quota.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedToken {
    pub id: Uuid,
    pub issued_to: String,
    pub expires_at: SystemTime,
    pub scope: TokenScope,
    pub quota: TokenQuota,
}

impl VerifiedToken {
    pub fn is_expired(&self) -> bool {
        self.expires_at <= SystemTime::now()
    }
}

pub fn verify_token_scope(token: &VerifiedToken, syscall: &IkSyscall) -> Result<(), String> {
    if token.is_expired() {
        return Err("token expired".to_string());
    }
    if !token.scope.permits(syscall) {
        return Err("scope does not permit syscall".to_string());
    }
    Ok(())
}

/// Demo stub used by local harnesses that mint a fixed UUID.
pub fn verify_token(token_id: &Uuid) -> Result<VerifiedToken, String> {
    if token_id == &*TEST_TOKEN_ID {
        Ok(VerifiedToken {
            id: *token_id,
            issued_to: "demo-principal".to_string(),
            expires_at: SystemTime::now() + Duration::from_secs(60 * 60),
            scope: TokenScope::Composite(vec![
                TokenScope::Fs(FsScope {
                    path_prefix: "/tmp/intentos_root".to_string(),
                    ops: vec![FsOp::Read, FsOp::Write, FsOp::Create],
                }),
                TokenScope::Ai(AiScope {
                    model: "*".to_string(),
                    max_tokens: Some(256),
                }),
            ]),
            quota: TokenQuota::demo_defaults(),
        })
    } else {
        Err("unknown token".to_string())
    }
}

/// Verify a token ID against the live capability table.
pub fn verify_with_table(
    table: &CapabilityTable,
    token_id: &Uuid,
) -> Result<VerifiedToken, String> {
    let jti = token_id.to_string();
    if !table.jti_was_registered(&jti) {
        return Err(format!("token {token_id} is not registered"));
    }
    let entry = table
        .lookup_active_by_jti(&jti)
        .ok_or_else(|| format!("token {token_id} is expired or exhausted"))?;
    Ok(verified_from_slot(token_id, entry))
}

fn verified_from_slot(token_id: &Uuid, entry: &SlotEntry) -> VerifiedToken {
    let expires_at = UNIX_EPOCH + Duration::from_millis(entry.expires_wall_ms);
    VerifiedToken {
        id: *token_id,
        issued_to: entry.subject.clone(),
        expires_at,
        scope: token_scope_from_capability(&entry.kind, &entry.scope),
        quota: TokenQuota::unlimited_now(),
    }
}

fn token_scope_from_capability(kind: &CapabilityKind, scope: &CapabilityScope) -> TokenScope {
    match kind {
        CapabilityKind::FileRead => TokenScope::Fs(FsScope {
            path_prefix: scope
                .constraints
                .get("path_prefix")
                .cloned()
                .unwrap_or_else(|| "/tmp/intentos_root".into()),
            ops: vec![FsOp::Read],
        }),
        CapabilityKind::FileWrite => TokenScope::Fs(FsScope {
            path_prefix: scope
                .constraints
                .get("path_prefix")
                .cloned()
                .unwrap_or_else(|| "/tmp/intentos_root".into()),
            ops: vec![FsOp::Write, FsOp::Create],
        }),
        CapabilityKind::DirList => TokenScope::Fs(FsScope {
            path_prefix: scope
                .constraints
                .get("path_prefix")
                .cloned()
                .unwrap_or_else(|| "/tmp/intentos_root".into()),
            ops: vec![FsOp::Read],
        }),
        CapabilityKind::NetSend => TokenScope::Net(NetScope {
            hosts: scope
                .constraints
                .get("hosts")
                .map(|h| {
                    h.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_else(|| vec!["*".into()]),
            methods: vec![HttpMethod::GET, HttpMethod::POST],
        }),
        CapabilityKind::AiInfer => TokenScope::Ai(AiScope {
            model: scope
                .constraints
                .get("model")
                .cloned()
                .unwrap_or_else(|| "*".into()),
            max_tokens: scope
                .constraints
                .get("max_tokens")
                .and_then(|v| v.parse().ok()),
        }),
        _ => TokenScope::Fs(FsScope {
            path_prefix: "/tmp/intentos_root".into(),
            ops: vec![],
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PolicyEngine;
    use crate::table::CapabilityTable;
    use crate::token::TokenBroker;
    use crate::types::{Intent, TrustAnchor};

    #[test]
    fn scoped_stub_token_allows_read_syscall() {
        let id = Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap();
        let t = verify_token(&id).unwrap();
        assert_eq!(t.id, id);
        verify_token_scope(
            &t,
            &IkSyscall::IkRead {
                handle: Uuid::new_v4(),
                len: 1,
            },
        )
        .unwrap();
    }

    #[test]
    fn verify_with_table_finds_registered_token() {
        let broker = TokenBroker::generate("test-broker").unwrap();
        let intent = Intent {
            actor: "alice".into(),
            resource: "file".into(),
            action: "read".into(),
            anchor: TrustAnchor::UiEvent,
            timestamp_ms: wall_ms(),
            metadata: Default::default(),
        };
        let decision = PolicyEngine::evaluate(&intent);
        let token = broker.mint(&intent, &decision).unwrap();
        let jti_uuid = Uuid::parse_str(&token.jti).unwrap();
        let mut table = CapabilityTable::new();
        table.register(&token).unwrap();
        let verified = verify_with_table(&table, &jti_uuid).unwrap();
        assert_eq!(verified.id, jti_uuid);
        assert_eq!(verified.issued_to, "alice");
        assert!(!verified.is_expired());
    }

    #[test]
    fn verify_with_table_rejects_unknown_jti() {
        let table = CapabilityTable::new();
        let err = verify_with_table(&table, &Uuid::new_v4()).unwrap_err();
        assert!(err.contains("not registered"), "unexpected: {err}");
    }
}
