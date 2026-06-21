//! Phase 2 public safety sector scaffold tests.

use intentos_utilities::{OsRuntime, PublicSafetyAssessor, PublicSafetyMapper};

#[test]
fn public_safety_mapper_ncic_lookup() {
    let mapped = PublicSafetyMapper::map("NCIC.lookup").expect("map");
    assert_eq!(mapped.domain, "ncic");
    assert_eq!(mapped.action, "lookup");
}

#[test]
fn public_safety_assessor_not_pilot_ready() {
    let rt = OsRuntime::boot().expect("boot");
    let report = PublicSafetyAssessor::assess(&rt.platform);
    assert_eq!(report.sector, "public_safety");
    assert!(!report.pilot_ready);
    assert!(report.blockers.iter().any(|b| b.contains("CJIS")));
}

#[test]
fn public_safety_map_and_audit() {
    let rt = OsRuntime::boot().expect("boot");
    let intent = PublicSafetyMapper::map_and_audit("CAD.dispatch.create", "dispatcher", &rt.audit)
        .expect("map");
    assert_eq!(intent.resource, "dispatch");
    assert_eq!(
        intent.metadata.get("sector").map(String::as_str),
        Some("public_safety")
    );
}