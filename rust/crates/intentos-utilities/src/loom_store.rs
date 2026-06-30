//! Local Loom persistence — atomic writes with checksum recovery.

use intentos_audit::{AuditEventKind, AuditLog, CardAuditDetail};
use intentos_hal::{DevicePosture, PlatformInfo};
use intentos_kernel::{
    BrokerPeer, Intent, IntentCard, LoomSession, PolicyEngine, PolicyOutcome, PolicyPack,
    ThresholdLevel, ThresholdSignals, TrustAnchor, wall_ms, Handle, Kernel, KernelError,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LoomError {
    #[error("loom I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("loom JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("loom state: {0}")]
    State(String),
    #[error("kernel: {0}")]
    Kernel(#[from] KernelError),
}

/// On-disk envelope with checksum for corruption detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LoomEnvelope {
    session: LoomSession,
}

/// Preview of a card execution without minting a token.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CardPreview {
    pub card_id: String,
    pub field_id: String,
    pub title: String,
    pub cap_summary: String,
    pub ttl_ms: u64,
    pub uses: u32,
    pub risk_level: ThresholdLevel,
    pub outcome: PolicyOutcome,
    pub requires_confirmation: bool,
    pub reason: String,
}

/// Thread-safe local Loom store.
pub struct LoomStore {
    path: PathBuf,
    inner: Mutex<LoomSession>,
    corruption_recovered: Mutex<bool>,
}

impl LoomStore {
    pub fn open() -> Result<Self, LoomError> {
        let path = state_file_path();
        if path.exists() {
            Self::load_from(&path)
        } else {
            let store = Self {
                path,
                inner: Mutex::new(LoomSession::default()),
                corruption_recovered: Mutex::new(false),
            };
            store.save()?;
            Ok(store)
        }
    }

    pub fn open_in(dir: impl AsRef<Path>) -> Result<Self, LoomError> {
        let path = dir.as_ref().join("loom_state.json");
        if path.exists() {
            Self::load_from(&path)
        } else {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let store = Self {
                path,
                inner: Mutex::new(LoomSession::default()),
                corruption_recovered: Mutex::new(false),
            };
            store.save()?;
            Ok(store)
        }
    }

    pub fn corruption_recovered(&self) -> bool {
        *self.corruption_recovered.lock().unwrap()
    }

    fn load_from(path: &Path) -> Result<Self, LoomError> {
        let bytes = fs::read(path)?;
        let envelope: LoomEnvelope = serde_json::from_slice(&bytes)?;
        let mut session = envelope.session;
        let recovered = !session.verify_checksum();
        if recovered {
            session = LoomSession::default();
        }
        let store = Self {
            path: path.to_path_buf(),
            inner: Mutex::new(session),
            corruption_recovered: Mutex::new(recovered),
        };
        if recovered {
            store.save()?;
        }
        Ok(store)
    }

    pub fn session(&self) -> LoomSession {
        self.inner.lock().unwrap().clone()
    }

    pub fn is_oobe_complete(&self) -> bool {
        self.inner.lock().unwrap().oobe_complete
    }

    pub fn set_policy_pack(&self, pack: PolicyPack) -> Result<(), LoomError> {
        let mut session = self.inner.lock().unwrap();
        session.policy_pack = pack;
        session.default_threshold = pack.default_threshold();
        session.refresh_checksum();
        drop(session);
        self.save()
    }

    pub fn preview_card(
        &self,
        card_id: &str,
        signals: Option<&intentos_kernel::ThresholdSignals>,
    ) -> Result<CardPreview, LoomError> {
        let session = self.inner.lock().unwrap();
        let active_field = session.active_field_id.as_deref();
        let card = session
            .find_card(card_id)
            .ok_or_else(|| LoomError::State(format!("unknown card: {card_id}")))?
            .clone();
        let profile = session.default_threshold;
        if active_field != Some(card.field_id.as_str()) {
            return Err(LoomError::State(format!(
                "card field {} != active field {:?}",
                card.field_id, active_field
            )));
        }
        let cap = card
            .primary_cap()
            .ok_or_else(|| LoomError::State("card has no capability".into()))?;
        let intent = Intent {
            actor: "preview".into(),
            resource: cap.resource.clone(),
            action: cap.action.clone(),
            anchor: TrustAnchor::UiEvent,
            timestamp_ms: wall_ms(),
            metadata: Default::default(),
        };
        let decision = PolicyEngine::evaluate_with_signals(&intent, profile, signals);
        Ok(CardPreview {
            card_id: card.id.clone(),
            field_id: card.field_id.clone(),
            title: card.title.clone(),
            cap_summary: card.cap_summary(),
            ttl_ms: card.ttl_ms,
            uses: card.uses,
            risk_level: card.risk_level,
            outcome: decision.outcome,
            requires_confirmation: decision.requires_confirmation,
            reason: decision.reason,
        })
    }

    pub fn complete_oobe(&self, threshold: ThresholdLevel) -> Result<(), LoomError> {
        self.ensure_signing_keys()?;
        let mut session = self.inner.lock().unwrap();
        session.oobe_complete = true;
        session.default_threshold = threshold;
        session.telemetry_enabled = false;
        session.ai_enabled = false;
        session.ensure_default_field(wall_ms());
        session.refresh_checksum();
        drop(session);
        self.save()
    }

    pub fn reset_oobe(&self) -> Result<(), LoomError> {
        let mut session = self.inner.lock().unwrap();
        *session = LoomSession::default();
        session.refresh_checksum();
        drop(session);
        self.save()
    }

    pub fn create_field(&self, name: &str) -> Result<intentos_kernel::Field, LoomError> {
        let mut session = self.inner.lock().unwrap();
        let field = session.add_field(name, wall_ms());
        drop(session);
        self.save()?;
        Ok(field)
    }

    pub fn use_field(&self, field_id: &str) -> Result<(), LoomError> {
        let mut session = self.inner.lock().unwrap();
        session
            .set_active_field(field_id)
            .map_err(LoomError::State)?;
        drop(session);
        self.save()
    }

    pub fn create_card(
        &self,
        title: &str,
        resource: &str,
        action: &str,
    ) -> Result<IntentCard, LoomError> {
        let mut session = self.inner.lock().unwrap();
        session.ensure_default_field(wall_ms());
        let field_id = session
            .active_field_id
            .clone()
            .ok_or_else(|| LoomError::State("no active field".into()))?;
        let risk = intentos_kernel::risk_for(resource, action);
        let card = IntentCard::new(title, &field_id, resource, action, risk);
        session
            .add_card(card.clone())
            .map_err(LoomError::State)?;
        drop(session);
        self.save()?;
        Ok(card)
    }

    pub fn threshold_signals(platform: &PlatformInfo) -> ThresholdSignals {
        let posture = DevicePosture::probe();
        ThresholdSignals::from_platform_and_posture(
            &format!("{:?}", platform.arch),
            &format!("{:?}", platform.os),
            platform.logical_cpus,
            platform.backend,
            posture.developer_mode,
            posture.secure_boot_attested,
            posture.biometric_available,
            posture.trust_score(),
        )
    }

    pub fn record_recent_command(&self, command: &str) -> Result<(), LoomError> {
        if command.is_empty() || matches!(command, "exit" | "quit") {
            return Ok(());
        }
        let mut session = self.inner.lock().unwrap();
        session.recent_commands.retain(|c| c != command);
        session.recent_commands.insert(0, command.to_string());
        session.recent_commands.truncate(32);
        session.refresh_checksum();
        drop(session);
        self.save()
    }

    pub fn register_broker_peer(&self, peer: BrokerPeer) -> Result<(), LoomError> {
        let mut session = self.inner.lock().unwrap();
        if let Some(existing) = session
            .broker_peers
            .iter_mut()
            .find(|p| p.peer_id == peer.peer_id)
        {
            *existing = peer;
        } else {
            session.broker_peers.push(peer);
        }
        session.refresh_checksum();
        drop(session);
        self.save()
    }

    pub fn run_card(
        &self,
        kernel: &Kernel,
        audit: &AuditLog,
        card_id: &str,
        actor: &str,
        user_confirmed: bool,
        signals: Option<&ThresholdSignals>,
    ) -> Result<(Handle, intentos_kernel::PolicyDecision), LoomError> {
        let session = self.inner.lock().unwrap();
        let active_field = session.active_field_id.as_deref();
        let card = session
            .find_card(card_id)
            .ok_or_else(|| LoomError::State(format!("unknown card: {card_id}")))?
            .clone();
        let profile = session.default_threshold;
        if active_field != Some(card.field_id.as_str()) {
            return Err(LoomError::State(format!(
                "card field {} != active field {:?}",
                card.field_id, active_field
            )));
        }
        drop(session);

        let cap = card
            .primary_cap()
            .ok_or_else(|| LoomError::State("card has no capability".into()))?;
        let intent = Intent {
            actor: actor.into(),
            resource: cap.resource.clone(),
            action: cap.action.clone(),
            anchor: TrustAnchor::UiEvent,
            timestamp_ms: wall_ms(),
            metadata: Default::default(),
        };

        let decision = PolicyEngine::evaluate_with_signals(&intent, profile, signals);

        if decision.requires_confirmation && !user_confirmed {
            let detail = CardAuditDetail {
                field_id: card.field_id.clone(),
                card_id: card_id.to_string(),
                decision: "confirm_required".into(),
                reason: "confirmation required — run with --confirm".into(),
                cap_summary: card.cap_summary(),
            };
            let _ = audit.record(AuditEventKind::UserDenied, actor, detail.to_detail_string());
            return Err(LoomError::State(
                "high-risk card requires confirmation — re-run with --confirm".into(),
            ));
        }

        if !decision.can_mint(user_confirmed) {
            let _ = audit.record(
                AuditEventKind::UserDenied,
                actor,
                format!(
                    "card={card_id} outcome={} — {}",
                    decision.outcome.as_str(),
                    decision.reason
                ),
            );
            return Err(LoomError::State(decision.reason.clone()));
        }

        if user_confirmed {
            let _ = audit.record(
                AuditEventKind::UserConfirmed,
                actor,
                format!(
                    "card={card_id} caps={} ttl={}ms uses={}",
                    card.cap_summary(),
                    card.ttl_ms,
                    card.uses
                ),
            );
        }

        let handle =
            kernel.intent_to_handle_with_profile(intent, profile, user_confirmed)?;
        let detail = CardAuditDetail {
            field_id: card.field_id.clone(),
            card_id: card_id.to_string(),
            decision: decision.outcome.as_str().into(),
            reason: decision.reason.clone(),
            cap_summary: card.cap_summary(),
        };
        let _ = audit.record(
            AuditEventKind::CardExecuted,
            actor,
            format!(
                "{} handle=0x{:X}",
                detail.to_detail_string(),
                handle.as_u64()
            ),
        );
        Ok((handle, decision))
    }

    pub fn ensure_signing_keys(&self) -> Result<(), LoomError> {
        let mut session = self.inner.lock().unwrap();
        if !session.signing_secret_key_hex.is_empty() {
            return Ok(());
        }
        let keys = intentos_kernel::generate_broker_keys()
            .map_err(|e| LoomError::State(format!("keygen: {e}")))?;
        session.signing_public_key_hex =
            hex_bytes(&keys.public_key_bytes()[..32]);
        session.signing_secret_key_hex = hex_bytes(keys.secret_key_bytes());
        session.refresh_checksum();
        drop(session);
        self.save()
    }

    pub fn set_ai_enabled(&self, enabled: bool) -> Result<(), LoomError> {
        let mut session = self.inner.lock().unwrap();
        session.ai_enabled = enabled;
        session.refresh_checksum();
        drop(session);
        self.save()
    }

    pub fn is_ai_enabled(&self) -> bool {
        self.inner.lock().unwrap().ai_enabled
    }

    pub fn set_telemetry_enabled(&self, enabled: bool) -> Result<(), LoomError> {
        let mut session = self.inner.lock().unwrap();
        session.telemetry_enabled = enabled;
        session.refresh_checksum();
        drop(session);
        self.save()
    }

    pub fn is_telemetry_enabled(&self) -> bool {
        self.inner.lock().unwrap().telemetry_enabled
    }

    pub fn set_pqc_tokens_enabled(&self, enabled: bool) -> Result<(), LoomError> {
        let mut session = self.inner.lock().unwrap();
        session.pqc_tokens_enabled = enabled;
        session.refresh_checksum();
        drop(session);
        self.save()
    }

    pub fn is_pqc_tokens_enabled(&self) -> bool {
        self.inner.lock().unwrap().pqc_tokens_enabled
    }

    pub fn signing_secret_key_hex(&self) -> String {
        self.inner.lock().unwrap().signing_secret_key_hex.clone()
    }

    pub fn profile_id(&self) -> String {
        self.inner.lock().unwrap().profile_id.clone()
    }

    pub fn merge_import_payload(
        &self,
        payload: &crate::loom_export::LoomExportPayload,
    ) -> Result<(), LoomError> {
        let mut session = self.inner.lock().unwrap();
        for field in &payload.fields {
            if !session.fields.iter().any(|f| f.id == field.id) {
                session.fields.push(field.clone());
            }
        }
        for card in &payload.cards {
            if session.cards.iter().any(|c| c.id == card.id) {
                continue;
            }
            if session.fields.iter().any(|f| f.id == card.field_id) {
                let _ = session.add_card(card.clone());
            }
        }
        if session.active_field_id.is_none() {
            session.active_field_id = payload.active_field_id.clone();
        }
        session.refresh_checksum();
        drop(session);
        self.save()
    }

    pub fn suggest_cards(&self, n: usize) -> Vec<IntentCard> {
        let session = self.inner.lock().unwrap();
        let mut ranked: Vec<IntentCard> = session.cards.clone();
        for cmd in &session.recent_commands {
            ranked.sort_by(|a, b| {
                let a_match = Self::card_matches_command(a, cmd);
                let b_match = Self::card_matches_command(b, cmd);
                b_match.cmp(&a_match)
            });
        }
        if ranked.len() >= n {
            return ranked.into_iter().take(n).collect();
        }
        let mut out = ranked;
        let field_id = session
            .active_field_id
            .clone()
            .unwrap_or_else(|| "default".into());
        let defaults = [
            ("List workspace", "dir", "list"),
            ("Read a file", "file", "read"),
            ("Write a file", "file", "write"),
        ];
        for (title, res, act) in defaults {
            if out.len() >= n {
                break;
            }
            if out.iter().any(|c| {
                c.primary_cap()
                    .map(|p| p.resource == res && p.action == act)
                    .unwrap_or(false)
            }) {
                continue;
            }
            out.push(IntentCard::new(
                title,
                &field_id,
                res,
                act,
                intentos_kernel::risk_for(res, act),
            ));
        }
        out.truncate(n);
        out
    }

    fn card_matches_command(card: &IntentCard, cmd: &str) -> bool {
        let cmd = cmd.to_lowercase();
        let cap = card.cap_summary().to_lowercase();
        if cmd.contains(&cap) {
            return true;
        }
        card.title
            .to_lowercase()
            .split_whitespace()
            .any(|w| w.len() > 3 && cmd.contains(w))
    }

    pub(crate) fn save(&self) -> Result<(), LoomError> {
        let session = self.inner.lock().unwrap();
        let mut copy = session.clone();
        copy.refresh_checksum();
        let envelope = LoomEnvelope { session: copy };
        let bytes = serde_json::to_vec_pretty(&envelope)?;
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        fs::write(&tmp, &bytes)?;
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

pub(crate) fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn state_file_path() -> PathBuf {
    if let Ok(dir) = std::env::var("INTENTOS_STATE_DIR") {
        return PathBuf::from(dir).join("loom_state.json");
    }
    if let Ok(home) = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")) {
        return PathBuf::from(home).join(".intentos").join("loom_state.json");
    }
    PathBuf::from(".intentos").join("loom_state.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("intentos-loom-test-{nanos}"))
    }

    #[test]
    fn round_trip_persistence() {
        let dir = temp_dir();
        let store = LoomStore::open_in(&dir).unwrap();
        store.complete_oobe(ThresholdLevel::Medium).unwrap();
        let field = store.create_field("work").unwrap();
        store.use_field(&field.id).unwrap();
        let card = store.create_card("Read doc", "file", "read").unwrap();
        drop(store);

        let store2 = LoomStore::open_in(&dir).unwrap();
        let session = store2.session();
        assert!(session.oobe_complete);
        assert!(session.find_card(&card.id).is_some());
        let _ = fs::remove_dir_all(dir);
    }
}