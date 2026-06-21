//! Phase 2 financial markets sector scaffold tests.

use intentos_utilities::{MarketsAssessor, MarketsMapper, OsRuntime};

#[test]
fn markets_mapper_fix_order() {
    let mapped = MarketsMapper::map("FIX.order").expect("map");
    assert_eq!(mapped.domain, "fix");
    assert_eq!(mapped.action, "order");
}

#[test]
fn markets_assessor_not_pilot_ready() {
    let rt = OsRuntime::boot().expect("boot");
    let report = MarketsAssessor::assess(&rt.platform);
    assert_eq!(report.sector, "financial_markets");
    assert!(!report.pilot_ready);
    assert!(report.blockers.iter().any(|b| b.contains("MiFID")));
}

#[test]
fn markets_map_and_audit() {
    let rt = OsRuntime::boot().expect("boot");
    let intent = MarketsMapper::map_and_audit("Risk.killswitch", "trader", &rt.audit).expect("map");
    assert_eq!(intent.resource, "risk");
    assert_eq!(
        intent.metadata.get("sector").map(String::as_str),
        Some("financial_markets")
    );
}