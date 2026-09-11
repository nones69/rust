//! Phase 2 banking/ATM sector scaffold tests.

use intentos_audit::AuditLog;
use intentos_hal::native_hal;
use intentos_utilities::{BankingAssessor, BankingMapper};

#[test]
fn banking_mapper_emv_authorize() {
    let mapped = BankingMapper::map("EMV.authorize").expect("map");
    assert_eq!(mapped.domain, "emv");
    assert_eq!(mapped.action, "authorize");
}

#[test]
fn banking_assessor_not_pilot_ready() {
    // Avoid OsRuntime::boot_ephemeral(): it shares ~/.intentos loom state across parallel tests.
    let platform = native_hal().probe();
    let report = BankingAssessor::assess(&platform);
    assert_eq!(report.sector, "banking");
    assert!(!report.pilot_ready);
    assert!(report.blockers.iter().any(|b| b.contains("PCI")));
}

#[test]
fn banking_map_and_audit() {
    let audit = AuditLog::new();
    let intent = BankingMapper::map_and_audit("ATM.withdraw", "teller", &audit).expect("map");
    assert_eq!(intent.resource, "atm");
    assert_eq!(
        intent.metadata.get("sector").map(String::as_str),
        Some("banking")
    );
}
