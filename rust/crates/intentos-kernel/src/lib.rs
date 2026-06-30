//! # intentos-kernel — Tier 3
//!
//! The kernel is **component #3** in IntentOS:
//!
//! 1. Utilities (`intentos-utilities`)
//! 2. Shell (`intentos-shell`)
//! 3. **Kernel** (`intentos-kernel`) ← this crate
//!
//! Owns policy, token minting, capability tables, leases, syscall
//! enforcement, and pluggable intent recognition in-process.

mod broker;
mod card;
mod crypto;
mod error;
mod field;
mod ip_policy;
mod lease;
mod loom;
mod policy;
mod policy_pack;
mod recognizer;
mod signals;
mod revocation;
mod table;
mod threshold;
mod token;
mod types;

pub use broker::BrokerPeer;
pub use card::IntentCard;
pub use crypto::{
    generate_broker_keys, sign, verify, BrokerKeys, CryptoError, PUBLIC_KEY_LEN, SECRET_KEY_LEN,
    SIGNATURE_LEN,
};
pub use field::Field;
pub use error::KernelError;
pub use loom::LoomSession;
pub use threshold::{gate_outcome, risk_for, PolicyOutcome, ThresholdLevel};
pub use lease::LeaseManager;
pub use ip_policy::{
    apply_ip_policy, evaluate_ip, extract_ipv4_literals, verdict_from_threat_score, IpVerdict,
    ThreatLevel, META_DEST_IP, META_THREAT_SCORE,
};
pub use policy::PolicyEngine;
pub use policy_pack::PolicyPack;
pub use signals::ThresholdSignals;
pub use recognizer::{IntentRecognizer, RecognizedIntent, StubRecognizer};
pub use revocation::RevocationList;
pub use table::CapabilityTable;
pub use token::TokenBroker;
pub use types::*;

use intentos_audit::{AuditEventKind, AuditLog};
use std::sync::{Arc, Mutex};

/// IntentOS tier number for the kernel.
pub const TIER: u8 = 3;

/// Boot-time kernel configuration.
pub struct KernelConfig {
    pub audit: Option<Arc<AuditLog>>,
    pub recognizer: Option<Arc<dyn IntentRecognizer>>,
}

impl Default for KernelConfig {
    fn default() -> Self {
        Self {
            audit: None,
            recognizer: None,
        }
    }
}

/// The IntentOS kernel — single in-process authority for the whole OS.
pub struct Kernel {
    inner: Arc<Mutex<KernelState>>,
    audit: Option<Arc<AuditLog>>,
    recognizer: Arc<dyn IntentRecognizer>,
}

struct KernelState {
    broker: TokenBroker,
    table: CapabilityTable,
    leases: LeaseManager,
    revocations: RevocationList,
    boot_ms: u64,
}

impl Kernel {
    /// Boot a fresh kernel with a newly generated broker identity.
    pub fn boot() -> Result<Self, KernelError> {
        Self::boot_with(KernelConfig::default())
    }

    /// Boot with audit log and/or custom intent recognizer.
    pub fn boot_with(config: KernelConfig) -> Result<Self, KernelError> {
        let recognizer: Arc<dyn IntentRecognizer> = config
            .recognizer
            .unwrap_or_else(|| Arc::new(StubRecognizer));

        let kernel = Self {
            inner: Arc::new(Mutex::new(KernelState {
                broker: TokenBroker::generate("intentos-kernel")?,
                table: CapabilityTable::new(),
                leases: LeaseManager::new(),
                revocations: RevocationList::new(),
                boot_ms: wall_ms(),
            })),
            audit: config.audit,
            recognizer,
        };

        kernel.audit_record(
            AuditEventKind::Boot,
            "kernel",
            format!("boot_ms={}", kernel.boot_ms()),
        );
        Ok(kernel)
    }

    pub fn tier() -> u8 {
        TIER
    }

    pub fn boot_ms(&self) -> u64 {
        self.inner.lock().unwrap().boot_ms
    }

    pub fn recognizer_name(&self) -> String {
        self.recognizer.name().to_string()
    }

    pub fn recognize(&self, text: &str) -> RecognizedIntent {
        let out = self.recognizer.recognize(text);
        self.audit_record(
            AuditEventKind::IntentRecognized,
            "recognizer",
            format!(
                "{} {} conf={:.2} backend={}",
                out.resource,
                out.action,
                out.confidence,
                self.recognizer_name()
            ),
        );
        out
    }

    pub fn submit_intent(&self, intent: Intent) -> PolicyDecision {
        self.submit_intent_with_threshold(intent, ThresholdLevel::Medium)
    }

    pub fn submit_intent_with_threshold(
        &self,
        intent: Intent,
        profile: ThresholdLevel,
    ) -> PolicyDecision {
        let decision = PolicyEngine::evaluate_with_threshold(&intent, profile);
        self.audit_record(
            AuditEventKind::Policy,
            &intent.actor,
            format!(
                "outcome={} allowed={} {} {} — {}",
                decision.outcome.as_str(),
                decision.allowed,
                intent.resource,
                intent.action,
                decision.reason
            ),
        );
        decision
    }

    pub fn mint_token(&self, intent: Intent) -> Result<Token, KernelError> {
        self.mint_token_confirmed(intent, false)
    }

    pub fn mint_token_confirmed(
        &self,
        intent: Intent,
        user_confirmed: bool,
    ) -> Result<Token, KernelError> {
        self.mint_token_with_profile(intent, ThresholdLevel::Medium, user_confirmed)
    }

    pub fn mint_token_with_profile(
        &self,
        intent: Intent,
        profile: ThresholdLevel,
        user_confirmed: bool,
    ) -> Result<Token, KernelError> {
        let token = {
            let state = self.inner.lock().unwrap();
            let decision = PolicyEngine::evaluate_with_threshold(&intent, profile);
            if !decision.can_mint(user_confirmed) {
                return Err(KernelError::PolicyDenied(decision.reason.clone()));
            }
            state.broker.mint(&intent, &decision)?
        };
        self.audit_record(
            AuditEventKind::TokenMinted,
            &intent.actor,
            format!("jti={} scope={}/{}", token.jti, intent.resource, intent.action),
        );
        Ok(token)
    }

    pub fn register_token(&self, token: Token) -> Result<Handle, KernelError> {
        {
            let state = self.inner.lock().unwrap();
            state.broker.verify(&token)?;
            if state.revocations.is_revoked(&token.jti) {
                return Err(KernelError::Revoked);
            }
        }
        let handle = {
            let mut state = self.inner.lock().unwrap();
            state.table.register(&token)?
        };
        self.audit_record(
            AuditEventKind::HandleRegistered,
            &token.sub,
            format!("handle=0x{:X} jti={}", handle.as_u64(), token.jti),
        );
        Ok(handle)
    }

    pub fn intent_to_handle(&self, intent: Intent) -> Result<Handle, KernelError> {
        self.intent_to_handle_confirmed(intent, false)
    }

    pub fn intent_to_handle_confirmed(
        &self,
        intent: Intent,
        user_confirmed: bool,
    ) -> Result<Handle, KernelError> {
        self.intent_to_handle_with_profile(intent, ThresholdLevel::Medium, user_confirmed)
    }

    pub fn intent_to_handle_with_profile(
        &self,
        intent: Intent,
        profile: ThresholdLevel,
        user_confirmed: bool,
    ) -> Result<Handle, KernelError> {
        let token = self.mint_token_with_profile(intent, profile, user_confirmed)?;
        self.register_token(token)
    }

    pub fn syscall(&self, handle: Handle, req: SyscallRequest) -> SyscallResult {
        let mut state = self.inner.lock().unwrap();
        if let Some(jti) = state.table.jti_for_handle(handle) {
            if state.revocations.is_revoked(&jti) {
                return SyscallResult::Denied("capability token revoked".into());
            }
        }
        let result = state.table.syscall(handle, &req);
        let detail = match &result {
            SyscallResult::Allowed { kind, remaining_uses } => {
                format!("allowed {:?} target={} uses_left={}", kind, req.target, remaining_uses)
            }
            SyscallResult::Denied(reason) => format!("denied {reason} target={}", req.target),
        };
        drop(state);
        self.audit_record(AuditEventKind::Syscall, "syscall", detail);
        result
    }

    pub fn grant_lease(&self, pid: u32, ttl_ms: u64) -> ProcessLease {
        let mut state = self.inner.lock().unwrap();
        state.leases.grant(pid, ttl_ms)
    }

    pub fn renew_lease(&self, lease_id: &str, ttl_ms: u64) -> Option<ProcessLease> {
        let mut state = self.inner.lock().unwrap();
        state.leases.renew(lease_id, ttl_ms)
    }

    pub fn tick_leases(&self) -> Vec<u32> {
        let mut state = self.inner.lock().unwrap();
        state.leases.tick()
    }

    pub fn list_leases(&self) -> Vec<ProcessLease> {
        let state = self.inner.lock().unwrap();
        state.leases.list().into_iter().cloned().collect()
    }

    pub fn active_capabilities(&self) -> usize {
        let state = self.inner.lock().unwrap();
        state.table.slot_count_active()
    }

    /// Revoke a capability token by `jti`. Returns false if already revoked.
    pub fn revoke_jti(&self, jti: &str, actor: &str) -> bool {
        let inserted = {
            let mut state = self.inner.lock().unwrap();
            state.revocations.revoke(jti)
        };
        if inserted {
            self.audit_record(
                AuditEventKind::TokenRevoked,
                actor,
                format!("jti={jti}"),
            );
        }
        inserted
    }

    /// Resolve the token JTI bound to an active capability handle.
    pub fn jti_for_handle(&self, handle: Handle) -> Option<String> {
        let state = self.inner.lock().unwrap();
        state.table.jti_for_handle(handle)
    }

    pub fn revocation_count(&self) -> usize {
        let state = self.inner.lock().unwrap();
        state.revocations.len()
    }

    pub fn stats(&self) -> KernelStats {
        let state = self.inner.lock().unwrap();
        KernelStats {
            uptime_ms: wall_ms().saturating_sub(state.boot_ms),
            active_capabilities: state.table.slot_count_active(),
            active_leases: state
                .leases
                .list()
                .iter()
                .filter(|l| l.state == LeaseState::Granted)
                .count(),
            revoked_tokens: state.revocations.len(),
            recognizer: self.recognizer.name().to_string(),
        }
    }

    fn audit_record(&self, kind: AuditEventKind, actor: &str, detail: String) {
        if let Some(audit) = &self.audit {
            let _ = audit.record(kind, actor, detail);
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct KernelStats {
    pub uptime_ms: u64,
    pub active_capabilities: usize,
    pub active_leases: usize,
    pub revoked_tokens: usize,
    pub recognizer: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_is_tier_3() {
        assert_eq!(Kernel::tier(), 3);
    }

    #[test]
    fn end_to_end_flow() {
        let k = Kernel::boot().unwrap();
        let intent = Intent {
            actor: "shell".into(),
            resource: "file".into(),
            action: "read".into(),
            anchor: TrustAnchor::UiEvent,
            timestamp_ms: wall_ms(),
            metadata: Default::default(),
        };
        let handle = k.intent_to_handle(intent).unwrap();
        let result = k.syscall(
            handle,
            SyscallRequest {
                op: SyscallOp::Read,
                target: "notes.txt".into(),
                payload: vec![],
            },
        );
        assert!(matches!(result, SyscallResult::Allowed { .. }));
    }

    #[test]
    fn low_trust_intent_is_denied() {
        let k = Kernel::boot().unwrap();
        let intent = Intent {
            actor: "shell".into(),
            resource: "file".into(),
            action: "read".into(),
            anchor: TrustAnchor::None,
            timestamp_ms: wall_ms(),
            metadata: Default::default(),
        };

        let err = k.mint_token(intent).unwrap_err();

        assert!(matches!(err, KernelError::PolicyDenied(_)));
    }

    #[test]
    fn revoked_jti_blocks_syscall() {
        let k = Kernel::boot().unwrap();
        let intent = Intent {
            actor: "shell".into(),
            resource: "file".into(),
            action: "read".into(),
            anchor: TrustAnchor::UiEvent,
            timestamp_ms: wall_ms(),
            metadata: Default::default(),
        };
        let token = k.mint_token(intent).unwrap();
        let jti = token.jti.clone();
        let handle = k.register_token(token).unwrap();
        assert!(k.revoke_jti(&jti, "admin"));
        let result = k.syscall(
            handle,
            SyscallRequest {
                op: SyscallOp::Read,
                target: "x".into(),
                payload: vec![],
            },
        );
        assert!(matches!(result, SyscallResult::Denied(_)));
        assert_eq!(k.revocation_count(), 1);
    }

    #[test]
    fn recognize_wires_through_kernel() {
        let audit = Arc::new(AuditLog::new());
        let k = Kernel::boot_with(KernelConfig {
            audit: Some(Arc::clone(&audit)),
            recognizer: None,
        })
        .unwrap();
        let out = k.recognize("list files in /tmp");
        assert_eq!(out.resource, "dir");
        assert_eq!(out.action, "list");
        assert!(audit.len().unwrap() >= 2);
    }
}