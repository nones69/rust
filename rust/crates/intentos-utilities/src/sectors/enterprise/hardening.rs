//! Phase 3 enterprise hardening — Wave 1 pilot exit gates and rollback checkpoints.

use super::compatibility::CompatibilityMatrix;
use super::identity::IdentityBridge;
use super::migration::MigrationAssessor;
use intentos_audit::{AuditEventKind, AuditLog};
use intentos_hal::PlatformInfo;
use serde::{Deserialize, Serialize};

/// Tier-1 compatibility threshold from Market Deployment Framework (enterprise pilot exit).
pub const TARGET_COMPAT_PASS_PCT: u8 = 95;

/// Minimum migration readiness before hardening sign-off.
pub const TARGET_MIGRATION_READINESS: u8 = 55;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardeningGate {
    pub name: String,
    pub met: bool,
    pub threshold: String,
    pub evidence: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnterpriseHardeningReport {
    pub phase: u8,
    pub wave: u8,
    pub sector: String,
    pub gates_met: usize,
    pub gates_total: usize,
    pub pilot_exit_ready: bool,
    pub gates: Vec<HardeningGate>,
    pub blockers: Vec<String>,
}

pub struct EnterpriseHardeningAssessor;

impl EnterpriseHardeningAssessor {
    pub fn assess(
        platform: &PlatformInfo,
        audit: &AuditLog,
        identity: &IdentityBridge,
    ) -> EnterpriseHardeningReport {
        let compat = CompatibilityMatrix::run_default();
        let migration = MigrationAssessor::assess(platform);
        let chain_ok = audit.verify_chain().unwrap_or(false);
        let principal = identity.whoami();
        let actor_ok = !principal.upn.is_empty();

        let rollback_ok = audit
            .has_kind(AuditEventKind::RollbackCheckpoint)
            .unwrap_or(false);

        let gates = vec![
            HardeningGate {
                name: "tier1_compat".into(),
                met: compat.pass_rate_pct >= TARGET_COMPAT_PASS_PCT,
                threshold: format!(">={TARGET_COMPAT_PASS_PCT}% pass rate"),
                evidence: format!(
                    "{}% ({}/{})",
                    compat.pass_rate_pct, compat.passed, compat.total
                ),
            },
            HardeningGate {
                name: "audit_chain".into(),
                met: chain_ok,
                threshold: "verify_chain() == true".into(),
                evidence: format!("chain_ok={chain_ok} entries={}", audit.len().unwrap_or(0)),
            },
            HardeningGate {
                name: "identity_bridge".into(),
                met: actor_ok,
                threshold: "identity whoami resolves principal".into(),
                evidence: format!(
                    "backend={:?} upn={}",
                    principal.backend, principal.upn
                ),
            },
            HardeningGate {
                name: "rollback_checkpoint".into(),
                met: rollback_ok,
                threshold: "≥1 RollbackCheckpoint audit event".into(),
                evidence: if rollback_ok {
                    "rollback checkpoint recorded".into()
                } else {
                    "run: enterprise rollback <label>".into()
                },
            },
            HardeningGate {
                name: "migration_readiness".into(),
                met: migration.readiness_score >= TARGET_MIGRATION_READINESS,
                threshold: format!("readiness_score >= {TARGET_MIGRATION_READINESS}"),
                evidence: format!("score={}", migration.readiness_score),
            },
        ];

        let gates_met = gates.iter().filter(|g| g.met).count();
        let blockers: Vec<String> = gates
            .iter()
            .filter(|g| !g.met)
            .map(|g| format!("{}: need {}", g.name, g.threshold))
            .collect();

        let pilot_exit_ready = gates_met == gates.len();

        EnterpriseHardeningReport {
            phase: 3,
            wave: 1,
            sector: "enterprise".into(),
            gates_met,
            gates_total: gates.len(),
            pilot_exit_ready,
            gates,
            blockers,
        }
    }
}

/// Record a rollback checkpoint for Wave 1 go/no-go evidence packages.
pub struct RollbackCheckpoint;

impl RollbackCheckpoint {
    pub fn record(
        audit: &AuditLog,
        actor: &str,
        label: &str,
        snapshot: &str,
    ) -> Result<String, intentos_audit::AuditError> {
        let entry = audit.record(
            AuditEventKind::RollbackCheckpoint,
            actor,
            format!("rollback checkpoint label={label} snapshot={snapshot}"),
        )?;
        Ok(entry.entry_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use intentos_hal::native_hal;

    #[test]
    fn hardening_reports_gates() {
        let platform = native_hal().probe();
        let audit = AuditLog::new();
        let identity = IdentityBridge::from_env();
        let report = EnterpriseHardeningAssessor::assess(&platform, &audit, &identity);
        assert_eq!(report.phase, 3);
        assert_eq!(report.gates_total, 5);
        assert!(!report.pilot_exit_ready);
    }

    #[test]
    fn rollback_checkpoint_satisfies_gate() {
        let platform = native_hal().probe();
        let audit = AuditLog::new();
        RollbackCheckpoint::record(&audit, "admin", "pre-pilot", "v0.1.0-baseline").unwrap();
        let identity = IdentityBridge::from_env();
        let report = EnterpriseHardeningAssessor::assess(&platform, &audit, &identity);
        assert!(report.gates.iter().any(|g| g.name == "rollback_checkpoint" && g.met));
    }
}