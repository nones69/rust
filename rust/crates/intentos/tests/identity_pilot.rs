//! Phase 2 AD/LDAP identity stub tests.

use intentos_shell::ShellSession;
use intentos_utilities::{IdentityBridge, OsRuntime};
use std::sync::Arc;

#[test]
fn runtime_boots_with_identity_bridge() {
    let rt = OsRuntime::boot().expect("boot");
    assert_eq!(rt.identity.domain(), "corp.local");
}

#[test]
fn lookup_admin_principal() {
    let bridge = IdentityBridge::from_env();
    let p = bridge.lookup("admin@corp.local").expect("admin");
    assert_eq!(p.actor_id, "CORP\\Domain-Admins");
    assert_eq!(bridge.trust_hint(&p), "elevated-stub");
}

#[test]
fn whoami_sets_resolvable_actor() {
    let bridge = IdentityBridge::from_env();
    let p = bridge.whoami();
    assert!(!bridge.actor_id(&p).is_empty());
}

#[test]
fn shell_boot_wires_identity_actor() {
    let rt = Arc::new(OsRuntime::boot().expect("boot"));
    let expected = rt.boot_actor();
    let session = ShellSession::new(rt);
    assert_eq!(session.actor(), expected);
    assert_ne!(session.actor(), "intentos-user");
}