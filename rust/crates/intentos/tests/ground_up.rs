//! Ensures IntentOS crates never depend on IKRL / legacy daemon stack.

use std::fs;
use std::path::PathBuf;

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