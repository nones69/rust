//! Market deployment cross-sector status smoke test.

use intentos_utilities::{MarketDeploymentReporter, OsRuntime};

#[test]
fn market_status_lists_all_six_sectors() {
    let rt = OsRuntime::boot().expect("boot");
    let report = MarketDeploymentReporter::status(&rt.platform, &rt.audit, &rt.identity);
    assert!(report.phase2_scaffolds_complete);
    assert_eq!(report.sectors.len(), 6);
    // Boot records a rollback checkpoint, so Wave 1 hardening gates may pass.
    assert!(report.wave1_pilot_exit_ready || !report.enterprise_hardening.blockers.is_empty());
    let names: Vec<_> = report.sectors.iter().map(|s| s.sector.as_str()).collect();
    assert!(names.contains(&"enterprise"));
    assert!(names.contains(&"financial_markets"));
}