//! # intentos-audit — Immutable Compliance Log
//!
//! Append-only audit trail with hash chaining for tamper evidence. Records
//! kernel boot, policy decisions, intent recognition, and syscall events.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
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
    RollbackCheckpoint,
    TokenRevoked,
    CardCreated,
    CardExecuted,
    UserConfirmed,
    UserDenied,
    FieldSwitched,
    OobeComplete,
    LoomRecovery,
    LoomExported,
    LoomImported,
    AiEnabled,
    AiDisabled,
    TelemetryEnabled,
    TelemetryDisabled,
    AuditRecovery,
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
    persist_path: Option<PathBuf>,
    recovered: Mutex<bool>,
}

struct AuditState {
    entries: Vec<AuditEntry>,
    last_hash: String,
}

/// Structured detail for card lifecycle audit events (FR-07).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CardAuditDetail {
    pub field_id: String,
    pub card_id: String,
    pub decision: String,
    pub reason: String,
    pub cap_summary: String,
}

impl CardAuditDetail {
    pub fn to_detail_string(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            format!(
                "field={} card={} decision={} caps={}",
                self.field_id, self.card_id, self.decision, self.cap_summary
            )
        })
    }
}

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("audit log lock poisoned")]
    LockPoisoned,
    #[error("audit I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("audit JSON: {0}")]
    Json(#[from] serde_json::Error),
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(AuditState {
                entries: Vec::new(),
                last_hash: genesis_hash(),
            }),
            persist_path: None,
            recovered: Mutex::new(false),
        }
    }

    /// Open or create a file-backed append-only audit log.
    pub fn open_persisted(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut log = Self {
            inner: Mutex::new(AuditState {
                entries: Vec::new(),
                last_hash: genesis_hash(),
            }),
            persist_path: Some(path.clone()),
            recovered: Mutex::new(false),
        };
        if path.exists() {
            if let Err(_err) = log.reload_from_disk() {
                *log.inner.lock().map_err(|_| AuditError::LockPoisoned)? = AuditState {
                    entries: Vec::new(),
                    last_hash: genesis_hash(),
                };
                *log.recovered.lock().map_err(|_| AuditError::LockPoisoned)? = true;
            } else if !log.verify_chain().unwrap_or(false) {
                *log.inner.lock().map_err(|_| AuditError::LockPoisoned)? = AuditState {
                    entries: Vec::new(),
                    last_hash: genesis_hash(),
                };
                *log.recovered.lock().map_err(|_| AuditError::LockPoisoned)? = true;
            }
        }
        Ok(log)
    }

    pub fn open_default() -> Result<Self, AuditError> {
        Self::open_persisted(default_audit_path())
    }

    pub fn corruption_recovered(&self) -> Result<bool, AuditError> {
        Ok(*self.recovered.lock().map_err(|_| AuditError::LockPoisoned)?)
    }

    fn reload_from_disk(&mut self) -> Result<(), AuditError> {
        let path = self.persist_path.as_ref().expect("persist path");
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut state = AuditState {
            entries: Vec::new(),
            last_hash: genesis_hash(),
        };
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let entry: AuditEntry = serde_json::from_str(&line)?;
            state.last_hash = entry.entry_hash.clone();
            state.entries.push(entry);
        }
        *self.inner.lock().map_err(|_| AuditError::LockPoisoned)? = state;
        Ok(())
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
        drop(state);

        if let Some(path) = &self.persist_path {
            self.append_to_disk(path, &entry)?;
        }
        Ok(entry)
    }

    fn append_to_disk(&self, path: &Path, entry: &AuditEntry) -> Result<(), AuditError> {
        let line = serde_json::to_string(entry)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        writeln!(file, "{line}")?;
        file.flush()?;
        Ok(())
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

    pub fn has_kind(&self, kind: AuditEventKind) -> Result<bool, AuditError> {
        let state = self.inner.lock().map_err(|_| AuditError::LockPoisoned)?;
        Ok(state.entries.iter().any(|e| e.kind == kind))
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

    /// Format an audit entry for display, optionally redacting sensitive resource names.
    pub fn format_entry(entry: &AuditEntry, redact: bool) -> String {
        let detail = if redact {
            redact_detail(&entry.detail)
        } else {
            entry.detail.clone()
        };
        format!(
            "[{}] {:?} actor={} {}",
            entry.ts_ms, entry.kind, entry.actor, detail
        )
    }
}

/// Redact path-like segments, IPs, and resource/cap identifiers in audit detail strings.
pub fn redact_detail(detail: &str) -> String {
    let mut out = detail.to_string();
    let tokens: Vec<String> = detail
        .split_whitespace()
        .map(str::to_string)
        .collect();
    for token in tokens {
        if looks_sensitive_token(&token) {
            let redacted = "[REDACTED]";
            if token.contains('=') {
                let key = token.split('=').next().unwrap_or(&token);
                let replacement = format!("{key}={redacted}");
                out = out.replace(&token, &replacement);
            } else {
                out = out.replace(&token, redacted);
            }
        }
    }
    out
}

fn looks_sensitive_token(token: &str) -> bool {
    let value = token.split_once('=').map(|(_, v)| v).unwrap_or(token);
    if value.eq_ignore_ascii_case("[REDACTED]") {
        return false;
    }
    if value.contains('/') || value.contains('\\') {
        return true;
    }
    if value.contains('.') && value.chars().all(|c| c.is_ascii_digit() || c == '.') {
        let parts: Vec<_> = value.split('.').collect();
        if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
            return true;
        }
    }
    let sensitive_keys = [
        "resource",
        "caps",
        "cap_summary",
        "path",
        "file",
        "patient",
        "account",
        "pan",
        "ssn",
    ];
    if let Some((key, val)) = token.split_once('=') {
        if sensitive_keys.iter().any(|k| key.eq_ignore_ascii_case(k)) && !val.is_empty() {
            return true;
        }
    }
    if value.contains('/') && !value.starts_with("http") {
        return true;
    }
    false
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

fn default_audit_path() -> PathBuf {
    if let Ok(dir) = std::env::var("INTENTOS_STATE_DIR") {
        return PathBuf::from(dir).join("audit.jsonl");
    }
    if let Ok(home) = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")) {
        return PathBuf::from(home).join(".intentos").join("audit.jsonl");
    }
    PathBuf::from(".intentos").join("audit.jsonl")
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

    #[test]
    fn empty_log_is_valid_and_starts_at_genesis() {
        let log = AuditLog::new();
        assert_eq!(log.len().unwrap(), 0);
        assert!(log.verify_chain().unwrap());
        assert_eq!(log.head_hash().unwrap(), genesis_hash());
    }

    #[test]
    fn records_link_seq_and_prev_hash() {
        let log = AuditLog::new();
        let first = log.record(AuditEventKind::Boot, "kernel", "boot").unwrap();
        let second = log.record(AuditEventKind::Syscall, "kernel", "read").unwrap();
        assert_eq!(first.seq, 1);
        assert_eq!(second.seq, 2);
        // genesis -> first -> second forms an unbroken chain.
        assert_eq!(first.prev_hash, genesis_hash());
        assert_eq!(second.prev_hash, first.entry_hash);
        // head_hash tracks the most recent entry.
        assert_eq!(log.head_hash().unwrap(), second.entry_hash);
    }

    #[test]
    fn tail_returns_most_recent_entries() {
        let log = AuditLog::new();
        for i in 0..5 {
            log.record(AuditEventKind::Bench, "bench", format!("run-{i}"))
                .unwrap();
        }
        let tail = log.tail(2).unwrap();
        assert_eq!(tail.len(), 2);
        assert_eq!(tail[0].detail, "run-3");
        assert_eq!(tail[1].detail, "run-4");
        // Requesting more than available is saturating, not panicking.
        assert_eq!(log.tail(100).unwrap().len(), 5);
    }

    #[test]
    fn has_kind_reflects_recorded_events() {
        let log = AuditLog::new();
        assert!(!log.has_kind(AuditEventKind::Policy).unwrap());
        log.record(AuditEventKind::Policy, "shell", "deny").unwrap();
        assert!(log.has_kind(AuditEventKind::Policy).unwrap());
        assert!(!log.has_kind(AuditEventKind::Boot).unwrap());
    }

    #[test]
    fn corrupt_audit_file_recovers_on_open() {
        let dir = std::env::temp_dir().join(format!("intentos-audit-bad-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        std::fs::write(&path, b"{not valid jsonl}\n").unwrap();
        let log = AuditLog::open_persisted(&path).unwrap();
        assert!(log.corruption_recovered().unwrap());
        assert_eq!(log.len().unwrap(), 0);
        log.record(AuditEventKind::Boot, "kernel", "after recovery").unwrap();
        assert_eq!(log.len().unwrap(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn persisted_log_survives_reload() {
        let dir = std::env::temp_dir().join(format!(
            "intentos-audit-{}",
            Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        {
            let log = AuditLog::open_persisted(&path).unwrap();
            log.record(AuditEventKind::Boot, "kernel", "boot").unwrap();
            log.record(AuditEventKind::Policy, "shell", "allow").unwrap();
        }
        let log2 = AuditLog::open_persisted(&path).unwrap();
        assert_eq!(log2.len().unwrap(), 2);
        assert!(log2.verify_chain().unwrap());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn card_audit_detail_serializes() {
        let d = CardAuditDetail {
            field_id: "fld-1".into(),
            card_id: "card-1".into(),
            decision: "allow".into(),
            reason: "ok".into(),
            cap_summary: "file/read".into(),
        };
        assert!(d.to_detail_string().contains("card-1"));
    }

    #[test]
    fn redact_detail_masks_paths_and_caps() {
        let raw = "card=card-1 field=fld-1 caps=file/read path=C:\\Users\\secret\\doc.txt";
        let redacted = redact_detail(raw);
        assert!(redacted.contains("caps=[REDACTED]"));
        assert!(redacted.contains("path=[REDACTED]"));
        assert!(redacted.contains("card=card-1"));
    }

    #[test]
    fn entry_hashes_are_unique_per_record() {
        let log = AuditLog::new();
        let a = log.record(AuditEventKind::Boot, "kernel", "same").unwrap();
        let b = log.record(AuditEventKind::Boot, "kernel", "same").unwrap();
        // Identical kind/actor/detail still differ via seq, id, ts, and prev_hash.
        assert_ne!(a.entry_hash, b.entry_hash);
    }
}