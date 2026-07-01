//! Ensures IntentOS crates never depend on IKRL / legacy daemon stack.

use intentos_audit::AuditLog;
use intentos_kernel::{Intent, Kernel, SyscallOp, SyscallRequest, SyscallResult, TrustAnchor, wall_ms};
use intentos_shell::Shell;
use intentos_utilities::OsRuntime;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

const FORBIDDEN: &[&str] = &[
    "intentkernel-core",
    "intentkernel-crypto",
    "intentkernel-os",
    "ikrl-transport",
    "ikrl-init",
    "ikrl-cli",
    "ikrl-shell",
    "capd",
    "intentd",
    "eventscope",
    "leasebroker",
];

const INTENTOS_CRATES: &[&str] = &[
    "intentos-audit",
    "intentos-bench",
    "intentos-hal",
    "intentos-kernel",
    "intentos-shell",
    "intentos-utilities",
    "intentos",
];

fn manifest_path(crate_name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(crate_name)
        .join("Cargo.toml")
}

#[test]
fn intentos_has_no_legacy_dependencies() {
    for crate_name in INTENTOS_CRATES {
        let text = fs::read_to_string(manifest_path(crate_name))
            .unwrap_or_else(|e| panic!("read {crate_name}/Cargo.toml: {e}"));
        for dep in FORBIDDEN {
            assert!(
                !text.contains(&format!("{dep} =")),
                "{crate_name} must not depend on legacy `{dep}` — IntentOS is ground-up"
            );
        }
    }
}

#[test]
fn only_intentos_kernel_owns_crypto_deps() {
    let kernel = fs::read_to_string(manifest_path("intentos-kernel")).unwrap();
    assert!(kernel.contains("ed25519-dalek"), "kernel owns native crypto");
    let shell = fs::read_to_string(manifest_path("intentos-shell")).unwrap();
    assert!(!shell.contains("ed25519"), "shell must not embed crypto");
}

#[test]
fn phase1_crates_exist() {
    for name in ["intentos-hal", "intentos-audit", "intentos-bench"] {
        assert!(
            manifest_path(name).exists(),
            "Phase 1 crate missing: {name}"
        );
    }
}

fn make_intent(actor: &str, resource: &str, action: &str) -> Intent {
    Intent {
        actor: actor.into(),
        resource: resource.into(),
        action: action.into(),
        anchor: TrustAnchor::UiEvent,
        timestamp_ms: wall_ms(),
        metadata: Default::default(),
    }
}

#[test]
fn test_full_email_send_scenario() {
    let audit = Arc::new(AuditLog::new());
    let runtime = Arc::new(OsRuntime::boot_with_audit(Arc::clone(&audit)).unwrap());
    let mut shell = Shell::open(runtime);

    shell
        .run_script(
            r#"
            flow network send
            syscall send smtp://mail.example
            syscall send smtp://mail.example
            "#,
        )
        .unwrap();

    let entries = audit.tail(16).unwrap();
    assert!(entries.iter().any(|entry| {
        entry.detail.contains("\"resource\":\"network\"")
            && entry.detail.contains("\"action\":\"send\"")
            && entry.detail.contains("\"decision\":\"grant\"")
    }));
    assert!(entries.iter().any(|entry| entry.detail.contains("allowed NetSend")));
    assert!(entries
        .iter()
        .any(|entry| entry.detail.contains("denied capability expired")));
}

#[test]
fn test_direct_bypass_attempt_denied() {
    let runtime = OsRuntime::boot_with_audit(Arc::new(AuditLog::new())).unwrap();
    let kernel = runtime.kernel();
    let vfs_handle = kernel.intent_to_handle(make_intent("test", "dir", "list")).unwrap();
    let err = {
        let utils = runtime.utilities.lock().unwrap();
        utils.vfs.read(&kernel, vfs_handle, "/readme.txt").unwrap_err()
    };
    assert!(matches!(err, intentos_utilities::VfsError::Denied(_)));
}

#[test]
fn test_reuse_burned_token_denied() {
    let kernel = Kernel::boot().unwrap();
    let handle = kernel
        .intent_to_handle_confirmed(make_intent("mailer", "network", "send"), true)
        .unwrap();

    let first = kernel.syscall(
        handle,
        SyscallRequest {
            op: SyscallOp::Send,
            target: "smtp://mail.example".into(),
            payload: vec![],
        },
    );
    assert!(matches!(first, SyscallResult::Allowed { .. }));

    let second = kernel.syscall(
        handle,
        SyscallRequest {
            op: SyscallOp::Send,
            target: "smtp://mail.example".into(),
            payload: vec![],
        },
    );
    assert!(matches!(second, SyscallResult::Denied(_)));
}