//! MVP AI OS integration — Field, Kernel Bar, Threshold, Loom, OOBE.

use intentos_audit::AuditEventKind;
use intentos_kernel::ThresholdLevel;
use intentos_utilities::{LoomStore, OsRuntime};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_loom_dir() -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("intentos-mvp-{nanos}"))
}

fn boot_with_temp_loom() -> (OsRuntime, std::path::PathBuf) {
    let dir = temp_loom_dir();
    let loom = Arc::new(LoomStore::open_in(&dir).expect("loom"));
    let audit = Arc::new(intentos_audit::AuditLog::new());
    let rt = OsRuntime::boot_with_loom(audit, loom).expect("boot");
    (rt, dir)
}

#[test]
fn oobe_initializes_profile_and_privacy_defaults() {
    let (rt, dir) = boot_with_temp_loom();
    assert!(!rt.loom.is_oobe_complete());
    rt.loom.complete_oobe(ThresholdLevel::High).unwrap();
    let session = rt.loom.session();
    assert!(session.oobe_complete);
    assert!(!session.telemetry_enabled);
    assert!(!session.ai_enabled);
    assert_eq!(session.default_threshold, ThresholdLevel::High);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn field_isolation_blocks_cross_field_card_execution() {
    let (rt, dir) = boot_with_temp_loom();
    rt.loom.complete_oobe(ThresholdLevel::Medium).unwrap();
    let a = rt.loom.create_field("alpha").unwrap();
    let b = rt.loom.create_field("beta").unwrap();
    rt.loom.use_field(&a.id).unwrap();
    let card = rt.loom.create_card("Read", "file", "read").unwrap();
    rt.loom.use_field(&b.id).unwrap();
    let err = rt
        .loom
        .run_card(&rt.kernel(), &rt.audit, &card.id, "user", false)
        .unwrap_err();
    assert!(err.to_string().contains("field"));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn high_risk_card_requires_confirmation() {
    let (rt, dir) = boot_with_temp_loom();
    rt.loom.complete_oobe(ThresholdLevel::High).unwrap();
    let card = rt.loom.create_card("Send packet", "network", "send").unwrap();
    assert!(rt
        .loom
        .run_card(&rt.kernel(), &rt.audit, &card.id, "user", false)
        .is_err());
    assert!(rt.audit.has_kind(AuditEventKind::UserDenied).unwrap());
    let (handle, _) = rt
        .loom
        .run_card(&rt.kernel(), &rt.audit, &card.id, "user", true)
        .unwrap();
    assert!(handle.as_u64() > 0);
    assert!(rt.audit.has_kind(AuditEventKind::UserConfirmed).unwrap());
    assert!(rt.audit.has_kind(AuditEventKind::CardExecuted).unwrap());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn loom_restores_cards_after_reload() {
    let dir = temp_loom_dir();
    let card_id = {
        let loom = Arc::new(LoomStore::open_in(&dir).unwrap());
        loom.complete_oobe(ThresholdLevel::Medium).unwrap();
        let card = loom.create_card("List dir", "dir", "list").unwrap();
        card.id.clone()
    };
    let loom2 = LoomStore::open_in(&dir).unwrap();
    assert!(loom2.session().find_card(&card_id).is_some());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn kb_suggest_returns_at_least_three_cards() {
    let (rt, dir) = boot_with_temp_loom();
    rt.loom.complete_oobe(ThresholdLevel::Medium).unwrap();
    let cards = rt.loom.suggest_cards(3);
    assert!(cards.len() >= 3);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn ai_gateway_blocked_until_enabled() {
    let (rt, dir) = boot_with_temp_loom();
    rt.loom.complete_oobe(ThresholdLevel::Medium).unwrap();
    assert!(!rt.loom.is_ai_enabled());
    rt.loom.set_ai_enabled(true).unwrap();
    assert!(rt.loom.is_ai_enabled());
    rt.loom.set_ai_enabled(false).unwrap();
    assert!(!rt.loom.is_ai_enabled());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn signed_loom_export_import_merges_cards() {
    let dir = temp_loom_dir();
    let export_path = dir.join("bundle.json");
    let store = LoomStore::open_in(&dir).unwrap();
    store.complete_oobe(ThresholdLevel::Medium).unwrap();
    let card = store.create_card("Export me", "file", "read").unwrap();
    store.export_signed(&export_path).unwrap();

    let dir2 = temp_loom_dir();
    let store2 = LoomStore::open_in(&dir2).unwrap();
    store2.complete_oobe(ThresholdLevel::Low).unwrap();
    store2.import_signed(&export_path).unwrap();
    assert!(store2.session().find_card(&card.id).is_some());

    let _ = std::fs::remove_dir_all(dir);
    let _ = std::fs::remove_dir_all(dir2);
}

#[test]
fn auto_oobe_runs_on_shell_open() {
    std::env::set_var("INTENTOS_SKIP_OOBE", "0");
    let dir = temp_loom_dir();
    let loom = Arc::new(LoomStore::open_in(&dir).unwrap());
    assert!(!loom.is_oobe_complete());
    let audit = Arc::new(intentos_audit::AuditLog::new());
    let rt = Arc::new(OsRuntime::boot_with_loom(audit, loom).expect("boot"));
    let _shell = intentos_shell::Shell::open(Arc::clone(&rt));
    assert!(rt.loom.is_oobe_complete());
    let _ = std::fs::remove_dir_all(dir);
}