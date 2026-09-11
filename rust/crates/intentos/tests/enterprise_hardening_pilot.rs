//! Phase 3 enterprise hardening gate tests.

use intentos_audit::AuditLog;
use intentos_hal::native_hal;
use intentos_utilities::{
    EnterpriseHardeningAssessor, IdentityBridge, RollbackCheckpoint, TARGET_COMPAT_PASS_PCT,
};

#[test]
fn hardening_gates_include_compat_threshold() {
    // Avoid OsRuntime::boot_ephemeral() — shared ~/.intentos loom state races under parallel tests.
    let platform = native_hal().probe();
    let audit = AuditLog::new();
    let identity = IdentityBridge::from_env();
    let report = EnterpriseHardeningAssessor::assess(&platform, &audit, &identity);
    assert_eq!(report.phase, 3);
    assert_eq!(report.wave, 1);
    let compat = report
        .gates
        .iter()
        .find(|g| g.name == "tier1_compat")
        .expect("compat gate");
    assert!(compat
        .threshold
        .contains(&TARGET_COMPAT_PASS_PCT.to_string()));
}

#[test]
fn rollback_checkpoint_enables_pilot_exit_when_other_gates_met() {
    let platform = native_hal().probe();
    let audit = AuditLog::new();
    let identity = IdentityBridge::from_env();
    RollbackCheckpoint::record(&audit, "admin", "wave1-baseline", "intentos-0.1.0").unwrap();
    let report = EnterpriseHardeningAssessor::assess(&platform, &audit, &identity);
    assert!(report
        .gates
        .iter()
        .any(|g| g.name == "rollback_checkpoint" && g.met));
}
