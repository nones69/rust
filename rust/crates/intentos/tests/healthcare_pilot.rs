//! Phase 2 healthcare sector scaffold tests.

use intentos_utilities::{HealthcareAssessor, HealthcareMapper, OsRuntime};

#[test]
fn healthcare_mapper_patient_read() {
    let intent = HealthcareMapper::map("Patient.read").expect("map");
    assert_eq!(intent.fhir_resource, "patient");
    assert_eq!(intent.action, "read");
}

#[test]
fn healthcare_assessor_not_pilot_ready() {
    let rt = OsRuntime::boot().expect("boot");
    let report = HealthcareAssessor::assess(&rt.platform);
    assert_eq!(report.sector, "healthcare");
    assert!(!report.pilot_ready);
    assert!(report.blockers.iter().any(|b| b.contains("HIPAA")));
}

#[test]
fn healthcare_map_and_audit() {
    let rt = OsRuntime::boot().expect("boot");
    let intent = HealthcareMapper::map_and_audit("Observation.list", "clinician", &rt.audit)
        .expect("map");
    assert_eq!(intent.resource, "observation");
    assert_eq!(intent.metadata.get("sector").map(String::as_str), Some("healthcare"));
}