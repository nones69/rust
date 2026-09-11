//! End-to-end in-process happy path: intent → policy → mint → register → burn.
//!
//! Minimum “it works as intended” check for the IntentOS prototype
//! (not a host-wide security proof).

use intentos_kernel::{
    wall_ms, Intent, Kernel, SyscallOp, SyscallRequest, SyscallResult, TrustAnchor,
};
use intentos_utilities::OsRuntime;

#[test]
fn boot_runtime_and_kernel_status() {
    let rt = OsRuntime::boot_ephemeral().expect("boot ephemeral runtime");
    let s = rt.kernel().stats();
    assert_eq!(s.active_capabilities, 0);
    assert_eq!(s.revoked_tokens, 0);
}

#[test]
fn intent_mint_register_syscall_and_burn() {
    let k = Kernel::boot().expect("boot kernel");

    let intent = Intent {
        actor: "demo".into(),
        resource: "file".into(),
        action: "write".into(),
        anchor: TrustAnchor::UiEvent,
        timestamp_ms: wall_ms(),
        metadata: Default::default(),
    };
    let decision = k.submit_intent(intent.clone());
    assert!(
        decision.allowed,
        "known file/write should be allowed: {}",
        decision.reason
    );

    let token = k.mint_token(intent).expect("mint development-signed token");
    let handle = k.register_token(token).expect("register");

    let first = k.syscall(
        handle,
        SyscallRequest {
            op: SyscallOp::Write,
            target: "notes.txt".into(),
            payload: b"ok".to_vec(),
        },
    );
    assert!(
        matches!(
            first,
            SyscallResult::Allowed {
                remaining_uses: 0,
                ..
            }
        ),
        "first write should burn the single-use token: {first:?}"
    );

    let again = k.syscall(
        handle,
        SyscallRequest {
            op: SyscallOp::Write,
            target: "notes.txt".into(),
            payload: b"nope".to_vec(),
        },
    );
    assert!(
        matches!(again, SyscallResult::Denied(_)),
        "second use must be denied after burn: {again:?}"
    );
}

#[test]
fn default_deny_unknown_intent() {
    let k = Kernel::boot().expect("boot kernel");
    let intent = Intent {
        actor: "demo".into(),
        resource: "totally-unknown-resource".into(),
        action: "explode".into(),
        anchor: TrustAnchor::UiEvent,
        timestamp_ms: wall_ms(),
        metadata: Default::default(),
    };
    let decision = k.submit_intent(intent.clone());
    assert!(!decision.allowed, "unknown intents must default-deny");
    assert!(
        k.mint_token(intent).is_err(),
        "mint must fail when policy denies"
    );
}
