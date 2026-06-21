//! Phase 2 banking/ATM sector scaffold tests.

use intentos_utilities::{BankingAssessor, BankingMapper, OsRuntime};

#[test]
fn banking_mapper_emv_authorize() {
    let mapped = BankingMapper::map("EMV.authorize").expect("map");
    assert_eq!(mapped.domain, "emv");
    assert_eq!(mapped.action, "authorize");
}

#[test]
fn banking_assessor_not_pilot_ready() {
    let rt = OsRuntime::boot().expect("boot");
    let report = BankingAssessor::assess(&rt.platform);
    assert_eq!(report.sector, "banking");
    assert!(!report.pilot_ready);
    assert!(report.blockers.iter().any(|b| b.contains("PCI")));
}

#[test]
fn banking_map_and_audit() {
    let rt = OsRuntime::boot().expect("boot");
    let intent = BankingMapper::map_and_audit("ATM.withdraw", "teller", &rt.audit).expect("map");
    assert_eq!(intent.resource, "atm");
    assert_eq!(
        intent.metadata.get("sector").map(String::as_str),
        Some("banking")
    );
}