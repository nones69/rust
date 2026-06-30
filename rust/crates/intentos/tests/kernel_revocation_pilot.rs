//! Kernel JTI revocation and boot baseline checkpoint tests.

use intentos_audit::AuditEventKind;
use intentos_kernel::{Handle, Intent, SyscallOp, SyscallRequest, TrustAnchor, wall_ms};
use intentos_utilities::OsRuntime;

#[test]
fn boot_records_rollback_baseline_checkpoint() {
    let rt = OsRuntime::boot().expect("boot");
    assert!(
        rt.audit
            .has_kind(AuditEventKind::RollbackCheckpoint)
            .unwrap()
    );
}

#[test]
fn revoke_blocks_active_capability() {
    let rt = OsRuntime::boot().expect("boot");
    let intent = Intent {
        actor: "trader".into(),
        resource: "file".into(),
        action: "read".into(),
        anchor: TrustAnchor::UiEvent,
        timestamp_ms: wall_ms(),
        metadata: Default::default(),
    };
    let token = rt.kernel().mint_token(intent).expect("mint");
    let jti = token.jti.clone();
    let handle = rt.kernel().register_token(token).expect("register");
    assert!(rt.kernel().revoke_jti(&jti, "admin"));
    let result = rt.kernel().syscall(
        handle,
        SyscallRequest {
            op: SyscallOp::Read,
            target: "x".into(),
            payload: vec![],
        },
    );
    assert!(matches!(result, intentos_kernel::SyscallResult::Denied(_)));
}

#[test]
fn revoke_by_handle_hex() {
    let rt = OsRuntime::boot().expect("boot");
    let intent = Intent {
        actor: "trader".into(),
        resource: "file".into(),
        action: "read".into(),
        anchor: TrustAnchor::UiEvent,
        timestamp_ms: wall_ms(),
        metadata: Default::default(),
    };
    let handle = rt.kernel().intent_to_handle(intent).expect("handle");
    let jti = rt
        .kernel()
        .jti_for_handle(handle)
        .expect("jti");
    assert!(rt.kernel().revoke_jti(&jti, "admin"));
    let _ = Handle::from_u64(handle.as_u64());
}