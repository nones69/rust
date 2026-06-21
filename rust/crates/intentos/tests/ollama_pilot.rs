//! Optional Ollama recognizer integration tests (Phase 2).

use intentos_kernel::IntentRecognizer;
use intentos_utilities::{OllamaClient, PilotRecognizer};
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn pilot_recognizer_ollama_disabled_by_default() {
    let _guard = ENV_LOCK.lock().expect("env lock");
    std::env::remove_var("INTENTOS_OLLAMA_ENABLE");
    std::env::remove_var("INTENTOS_OLLAMA_URL");

    let r = PilotRecognizer::boot();
    assert!(!r.ollama_enabled());
    assert_eq!(r.name(), "enterprise+stub");
}

#[test]
fn ollama_client_reports_enabled_when_url_set() {
    let _guard = ENV_LOCK.lock().expect("env lock");
    std::env::remove_var("INTENTOS_OLLAMA_ENABLE");
    std::env::set_var("INTENTOS_OLLAMA_URL", "http://127.0.0.1:11434");

    let client = OllamaClient::from_env();
    assert!(client.is_some());

    std::env::remove_var("INTENTOS_OLLAMA_URL");
}

#[test]
#[ignore = "requires INTENTOS_OLLAMA_ENABLE=1 and a reachable Ollama server"]
fn ollama_recognizes_natural_language_when_enabled() {
    let _guard = ENV_LOCK.lock().expect("env lock");
    std::env::set_var("INTENTOS_OLLAMA_ENABLE", "1");

    let r = PilotRecognizer::boot();
    assert!(r.ollama_enabled());

    let out = r.recognize("please list files in my downloads folder");
    assert!(
        out.confidence >= 0.40,
        "expected confident Ollama mapping, got conf={}",
        out.confidence
    );
    assert!(!out.resource.is_empty());
    assert!(!out.action.is_empty());

    std::env::remove_var("INTENTOS_OLLAMA_ENABLE");
}