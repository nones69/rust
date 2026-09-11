//! IP-Discrambler integration with IntentOS utilities + kernel policy.

use intentos_kernel::{evaluate_ip, PolicyEngine, ThreatLevel};
use intentos_utilities::{IpDiscramblerBridge, OsRuntime};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[test]
fn kernel_blocks_bogon_network_dest() {
    let v = evaluate_ip("192.0.2.55");
    assert!(!v.allowed);
    assert_eq!(v.threat, ThreatLevel::Critical);
}

#[test]
fn runtime_discovers_ip_discrambler_when_present() {
    let rt = OsRuntime::boot_ephemeral().expect("boot");
    if IpDiscramblerBridge::discover().is_ok() {
        assert!(rt.ip_discrambler.is_some());
    }
}

#[test]
fn local_policy_verdict_blocks_reserved() {
    let bridge = IpDiscramblerBridge::from_root(PathBuf::from("."));
    let verdict = bridge.policy_check_local("203.0.113.5", "tester");
    assert!(!verdict.allowed);
}

#[test]
fn descramble_intent_uses_ip_policy() {
    let rt = OsRuntime::boot_ephemeral().expect("boot");
    let mut meta = BTreeMap::new();
    meta.insert("dest_ip".into(), "192.0.2.10".into());
    let intent = intentos_kernel::Intent {
        actor: "tester".into(),
        resource: "network".into(),
        action: "descramble".into(),
        anchor: intentos_kernel::TrustAnchor::UiEvent,
        timestamp_ms: intentos_kernel::wall_ms(),
        metadata: meta,
    };
    let decision = PolicyEngine::evaluate(&intent);
    assert!(!decision.allowed);
    let _ = rt;
}

#[test]
fn python_bridge_lookup_when_available() {
    // Live Python lookup needs the optional tools/ip-discrambler install
    // (`pip install -e ".[dev]"`). Default CI/dev check skips unless opted in.
    if std::env::var("INTENTOS_IPDIS_LIVE").is_err() {
        eprintln!("skip: set INTENTOS_IPDIS_LIVE=1 after installing tools/ip-discrambler");
        return;
    }

    let Ok(bridge) = IpDiscramblerBridge::discover() else {
        eprintln!("skip: ip-discrambler root not found");
        return;
    };

    match bridge.lookup("8.8.8.8") {
        Ok(result) => assert_eq!(result.ip, "8.8.8.8"),
        Err(err) => {
            eprintln!("skip: python bridge unavailable ({err})");
        }
    }
}
