//! Financial markets latency harness integration smoke test.

use intentos_bench::{run_markets_latency_bench, TARGET_RISK_PRECHECK_P99_US};

#[test]
fn markets_latency_harness_reports_percentiles() {
    let report = run_markets_latency_bench(500);
    assert_eq!(report.sector, "financial_markets");
    assert_eq!(report.risk_precheck.samples, 500);
    assert_eq!(
        report.targets.risk_precheck_p99_us,
        TARGET_RISK_PRECHECK_P99_US
    );
    assert!(!report.notes.is_empty());
}