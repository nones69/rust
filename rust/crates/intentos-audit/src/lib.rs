//! # intentos-audit — Immutable Compliance Log
//!
//! Append-only audit trail with hash chaining for tamper evidence. Records
//! kernel boot, policy decisions, intent recognition, and syscall events.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::sync::Mutex;
use thiserror::Error;
use uuid::Uuid;

/// Category of audited event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventKind {
    Boot,
    Policy,
    IntentRecognized,
    TokenMinted,
    HandleRegistered,
    Syscall,
    SectorMap,
    Bench,
}

/// Single immutable audit record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: u64,
    pub id: String,
    pub ts_ms: u64,
    pub kind: AuditEventKind,
    pub actor: String,
    pub detail: String,
    pub prev_hash: String,
    pub entry_hash: String,
}

/// Append-only audit log with SHA3-256 hash chain.
pub struct AuditLog {
    inner: Mutex<AuditState>,
}

struct AuditState {
    entries: Vec<AuditEntry>,
    last_hash: String,
}

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("audit log lock poisoned")]
    LockPoisoned,
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(AuditState {
                entries: Vec::new(),
                last_hash: genesis_hash(),
            }),
        }
    }

    pub fn record(
        &self,
        kind: AuditEventKind,
        actor: &str,
        detail: impl Into<String>,
    ) -> Result<AuditEntry, AuditError> {
        let mut state = self.inner.lock().map_err(|_| AuditError::LockPoisoned)?;
        let seq = state.entries.len() as u64 + 1;
        let prev_hash = state.last_hash.clone();
        let ts_ms = Utc::now().timestamp_millis() as u64;
        let detail = detail.into();
        let id = Uuid::new_v4().to_string();

        let entry_hash = hash_entry(seq, &id, ts_ms, &kind, actor, &detail, &prev_hash);
        let entry = AuditEntry {
            seq,
            id,
            ts_ms,
            kind,
            actor: actor.to_string(),
            detail,
            prev_hash,
            entry_hash: entry_hash.clone(),
        };

        state.last_hash = entry_hash;
        state.entries.push(entry.clone());
        Ok(entry)
    }

    pub fn len(&self) -> Result<usize, AuditError> {
        let state = self.inner.lock().map_err(|_| AuditError::LockPoisoned)?;
        Ok(state.entries.len())
    }

    pub fn tail(&self, n: usize) -> Result<Vec<AuditEntry>, AuditError> {
        let state = self.inner.lock().map_err(|_| AuditError::LockPoisoned)?;
        let start = state.entries.len().saturating_sub(n);
        Ok(state.entries[start..].to_vec())
    }

    pub fn verify_chain(&self) -> Result<bool, AuditError> {
        let state = self.inner.lock().map_err(|_| AuditError::LockPoisoned)?;
        let mut expected_prev = genesis_hash();
        for entry in &state.entries {
            if entry.prev_hash != expected_prev {
                return Ok(false);
            }
            let recomputed = hash_entry(
                entry.seq,
                &entry.id,
                entry.ts_ms,
                &entry.kind,
                &entry.actor,
                &entry.detail,
                &entry.prev_hash,
            );
            if recomputed != entry.entry_hash {
                return Ok(false);
            }
            expected_prev = entry.entry_hash.clone();
        }
        Ok(true)
    }

    pub fn head_hash(&self) -> Result<String, AuditError> {
        let state = self.inner.lock().map_err(|_| AuditError::LockPoisoned)?;
        Ok(state.last_hash.clone())
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

fn genesis_hash() -> String {
    hex_hash(b"intentos-audit-genesis")
}

fn hash_entry(
    seq: u64,
    id: &str,
    ts_ms: u64,
    kind: &AuditEventKind,
    actor: &str,
    detail: &str,
    prev_hash: &str,
) -> String {
    let kind_s = serde_json::to_string(kind).unwrap_or_else(|_| "\"unknown\"".into());
    let payload = format!("{seq}|{id}|{ts_ms}|{kind_s}|{actor}|{detail}|{prev_hash}");
    hex_hash(payload.as_bytes())
}

fn hex_hash(data: &[u8]) -> String {
    let digest = Sha3_256::digest(data);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_verifies_after_appends() {
        let log = AuditLog::new();
        log.record(AuditEventKind::Boot, "kernel", "boot ok").unwrap();
        log.record(AuditEventKind::Policy, "shell", "allowed file read").unwrap();
        assert!(log.verify_chain().unwrap());
        assert_eq!(log.len().unwrap(), 2);
    }
}