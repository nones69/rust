//! Virtual-environment sandbox — isolated state dirs mimic a fresh VM install.

use intentos_shell::ShellSession;
use intentos_utilities::{LoomStore, OsRuntime};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Serializes env-var mutation — parallel pilot tests also touch `INTENTOS_*`.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn sandbox_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("intentos-vm-{nanos}"))
}

fn boot_in(dir: &PathBuf) -> Arc<OsRuntime> {
    let loom = Arc::new(LoomStore::open_in(dir).expect("loom"));
    let audit = Arc::new(
        intentos_audit::AuditLog::open_persisted(dir.join("audit.jsonl")).expect("audit"),
    );
    Arc::new(OsRuntime::boot_with_loom(audit, loom).expect("boot"))
}

fn eval_ok(session: &mut ShellSession, cmd: &str) {
    session
        .eval(cmd)
        .unwrap_or_else(|e| panic!("eval `{cmd}` failed: {e:#}"));
}

#[test]
fn sandbox_fresh_boot_creates_state_files() {
    let dir = sandbox_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let _rt = boot_in(&dir);
    assert!(dir.join("loom_state.json").exists());
    assert!(dir.join("audit.jsonl").exists());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn sandbox_auto_oobe_on_first_shell_open() {
    let _guard = ENV_LOCK.lock().unwrap();
    std::env::remove_var("INTENTOS_SKIP_OOBE");
    let dir = sandbox_dir();
    let rt = boot_in(&dir);
    assert!(!rt.loom.is_oobe_complete());
    let _session = ShellSession::new(Arc::clone(&rt));
    assert!(rt.loom.is_oobe_complete());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn sandbox_shell_tier_and_kernel_commands() {
    let _guard = ENV_LOCK.lock().unwrap();
    std::env::set_var("INTENTOS_SKIP_OOBE", "1");
    let dir = sandbox_dir();
    let rt = boot_in(&dir);
    rt.loom.complete_oobe(intentos_kernel::ThresholdLevel::Medium)
        .unwrap();
    let mut session = ShellSession::new(rt);
    for cmd in [
        "1",
        "2",
        "3",
        "tier",
        "status",
        "hal",
        "posture",
        "kernel stats",
        "kernel crypto status",
        "audit verify",
        "broker status",
        "telemetry status",
        "ai status",
        "identity whoami",
        "market status",
        "enterprise compat",
    ] {
        eval_ok(&mut session, cmd);
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn sandbox_kernel_bar_and_vfs_flow() {
    let _guard = ENV_LOCK.lock().unwrap();
    std::env::set_var("INTENTOS_SKIP_OOBE", "1");
    let dir = sandbox_dir();
    let rt = boot_in(&dir);
    rt.loom.complete_oobe(intentos_kernel::ThresholdLevel::Medium)
        .unwrap();
    let mut session = ShellSession::new(Arc::clone(&rt));
    eval_ok(&mut session, "field list");
    eval_ok(&mut session, "kb suggest");
    eval_ok(&mut session, "flow file read");
    eval_ok(&mut session, "syscall read /readme.txt");
    eval_ok(&mut session, "audit tail 5");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn sandbox_pqc_and_broker_wire() {
    use intentos_kernel::{BrokerPeer, TOKEN_SIG_V2_PQC_HYBRID};
    use intentos_utilities::BrokerWireHub;
    let _guard = ENV_LOCK.lock().unwrap();
    std::env::set_var("INTENTOS_SKIP_OOBE", "1");
    let dir = sandbox_dir();
    let rt = boot_in(&dir);
    rt.loom.complete_oobe(intentos_kernel::ThresholdLevel::Medium)
        .unwrap();
    rt.loom.set_pqc_tokens_enabled(true).unwrap();
    rt.sync_pqc_tokens_from_loom();
    assert_eq!(rt.kernel().token_sig_version(), TOKEN_SIG_V2_PQC_HYBRID);

    rt.loom.ensure_signing_keys().unwrap();
    let public_hex = rt.loom.session().signing_public_key_hex.clone();
    rt.loom
        .register_broker_peer(BrokerPeer::new("sandbox-peer", public_hex, 1))
        .unwrap();

    let mut session = ShellSession::new(Arc::clone(&rt));
    eval_ok(&mut session, "kernel crypto enable-pqc");
    eval_ok(&mut session, "broker list");

    let wire = BrokerWireHub::open_in(dir.join("broker"));
    let secret = rt.loom.signing_secret_key_hex();
    let device = rt.loom.profile_id();
    let mut msg = BrokerWireHub::build_delegate(&device, "sandbox-peer", b"sandbox", 1);
    BrokerWireHub::sign_message(&mut msg, &secret).unwrap();
    let peer = rt.loom.session().broker_peers[0].clone();
    wire.enqueue_to_peer(&peer, &msg).unwrap();
    let inbox = wire.recv_inbox("sandbox-peer", 3).unwrap();
    assert_eq!(inbox.len(), 1);

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn sandbox_intentos_state_dir_env_boot() {
    let _guard = ENV_LOCK.lock().unwrap();
    let dir = sandbox_dir();
    std::fs::create_dir_all(&dir).unwrap();
    std::env::set_var("INTENTOS_STATE_DIR", dir.to_string_lossy().as_ref());
    std::env::set_var("INTENTOS_SKIP_OOBE", "1");
    let _rt = OsRuntime::boot().expect("env boot");
    assert!(dir.join("loom_state.json").exists());
    assert!(dir.join("audit.jsonl").exists());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn sandbox_audit_chain_stays_valid_after_session() {
    let _guard = ENV_LOCK.lock().unwrap();
    std::env::set_var("INTENTOS_SKIP_OOBE", "1");
    let dir = sandbox_dir();
    let rt = boot_in(&dir);
    rt.loom.complete_oobe(intentos_kernel::ThresholdLevel::Medium)
        .unwrap();
    let mut session = ShellSession::new(Arc::clone(&rt));
    eval_ok(&mut session, "flow dir list");
    eval_ok(&mut session, "telemetry enable");
    eval_ok(&mut session, "telemetry disable");
    assert!(rt.audit.verify_chain().unwrap());
    assert!(rt.audit.len().unwrap() > 0);
    let _ = std::fs::remove_dir_all(dir);
}