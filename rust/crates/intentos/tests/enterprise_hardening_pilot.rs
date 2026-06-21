//! Phase 3 enterprise hardening gate tests.

use intentos_utilities::{
    EnterpriseHardeningAssessor, OsRuntime, RollbackCheckpoint, TARGET_COMPAT_PASS_PCT,
};

#[test]
fn hardening_gates_include_compat_threshold() {
    let rt = OsRuntime::boot().expect("boot");
    let report = EnterpriseHardeningAssessor::assess(&rt.platform, &rt.audit, &rt.identity);
    assert_eq!(report.phase, 3);
    assert_eq!(report.wave, 1);
    let compat = report
        .gates
        .iter()
        .find(|g| g.name == "tier1_compat")
        .expect("compat gate");
    assert!(compat.threshold.contains(&TARGET_COMPAT_PASS_PCT.to_string()));
}

#[test]
fn rollback_checkpoint_enables_pilot_exit_when_other_gates_met() {
    let rt = OsRuntime::boot().expect("boot");
    RollbackCheckpoint::record(&rt.audit, "admin", "wave1-baseline", "intentos-0.1.0").unwrap();
    let report = EnterpriseHardeningAssessor::assess(&rt.platform, &rt.audit, &rt.identity);
    assert!(
        report
            .gates
            .iter()
            .any(|g| g.name == "rollback_checkpoint" && g.met)
    );
}