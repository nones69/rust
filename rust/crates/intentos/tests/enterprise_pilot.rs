//! Phase 2 enterprise pilot — end-to-end integration smoke test.

use intentos_kernel::{SyscallOp, SyscallRequest};
use intentos_utilities::{AuditEventKind, EnterpriseMapper, MigrationAssessor, OsRuntime};

#[test]
fn enterprise_command_maps_to_gated_handle() {
    let rt = OsRuntime::boot().expect("boot");
    let intent = EnterpriseMapper::map_and_audit(
        "Get-Content C:\\logs\\app.log",
        "pilot-user",
        &rt.audit,
    )
    .expect("map");

    assert_eq!(intent.resource, "file");
    assert_eq!(intent.action, "read");

    let decision = rt.kernel().submit_intent(intent.clone());
    assert!(decision.allowed);

    let handle = rt.kernel().intent_to_handle(intent).expect("handle");
    let result = rt.kernel().syscall(
        handle,
        SyscallRequest {
            op: SyscallOp::Read,
            target: "app.log".into(),
            payload: vec![],
        },
    );
    assert!(matches!(result, intentos_kernel::SyscallResult::Allowed { .. }));
}

#[test]
fn composite_recognizer_names_enterprise_backend() {
    let rt = OsRuntime::boot().expect("boot");
    assert_eq!(rt.kernel().recognizer_name(), "enterprise+stub");
    let out = rt.kernel().recognize("docker ps");
    assert_eq!(out.resource, "dir");
    assert_eq!(out.action, "list");
}

#[test]
fn migration_assessor_reports_pilot_blockers() {
    let rt = OsRuntime::boot().expect("boot");
    let report = MigrationAssessor::assess(&rt.platform);
    assert_eq!(report.sector, "enterprise");
    assert!(report.readiness_score > 0);
    assert!(!report.blockers.is_empty());
}

#[test]
fn enterprise_flow_leaves_audit_trail() {
    let rt = OsRuntime::boot().expect("boot");
    let before = rt.audit.len().unwrap();
    let _ = EnterpriseMapper::map_and_audit("ls /var/log", "pilot", &rt.audit);
    let entries = rt.audit.tail(5).unwrap();
    assert!(rt.audit.len().unwrap() > before);
    assert!(entries.iter().any(|e| e.kind == AuditEventKind::SectorMap));
    assert!(rt.audit.verify_chain().unwrap());
}