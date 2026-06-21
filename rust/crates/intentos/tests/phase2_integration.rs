//! Phase 2 integration tests — healthcare, compat matrix, LDAP config.

use intentos_audit::AuditLog;
use intentos_hal::native_hal;
use intentos_utilities::{
    CompatibilityMatrix, HealthcareAssessor, HealthcareMapper, IdentityBridge, LdapConfig,
};

#[test]
fn healthcare_maps_patient_read_and_assess_with_audit() {
    let mapped = HealthcareMapper::map("Patient.read").expect("patient.read");
    assert_eq!(mapped.fhir_resource, "patient");
    assert_eq!(mapped.action, "read");

    let audit = AuditLog::new();
    let _ = audit.record(
        intentos_audit::AuditEventKind::Boot,
        "test",
        "healthcare integration",
    );
    let platform = native_hal().probe();
    let report = HealthcareAssessor::assess_with_audit(&platform, Some(&audit));
    assert_eq!(report.audit_chain_ok, Some(true));
    assert!(report.readiness_score >= 45);
}

#[test]
fn enterprise_compat_matrix_meets_pilot_gate() {
    let report = CompatibilityMatrix::run_default();
    assert!(report.pilot_gate_met);
    assert_eq!(report.passed, 10);
}

#[test]
fn ldap_config_absent_without_url() {
    std::env::remove_var("INTENTOS_LDAP_URL");
    assert!(LdapConfig::from_env().is_none());
}

#[test]
fn identity_falls_back_to_stub_without_ldap() {
    std::env::remove_var("INTENTOS_LDAP_URL");
    let bridge = IdentityBridge::from_env();
    assert!(!bridge.is_live_ldap());
    let admin = bridge.lookup("admin@corp.local").expect("stub admin");
    assert!(admin.actor_id.contains("Admin"));
}

/// Gated live LDAP test — requires test AD/LDAP and `INTENTOS_LDAP_URL`.
#[test]
fn ldap_live_lookup_when_configured() {
    if std::env::var("INTENTOS_LDAP_URL").is_err() {
        eprintln!("skip: INTENTOS_LDAP_URL not set");
        return;
    }
    let user = std::env::var("INTENTOS_LDAP_TEST_USER").unwrap_or_else(|_| "admin".into());
    let bridge = IdentityBridge::from_env();
    assert!(bridge.is_live_ldap(), "expected live LDAP backend");
    let principal = bridge
        .lookup(&user)
        .unwrap_or_else(|| panic!("live lookup failed for {user}"));
    assert!(!principal.upn.is_empty());
}