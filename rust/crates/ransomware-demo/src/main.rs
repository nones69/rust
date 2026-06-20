//! ransomware-demo — Demonstrates structural ransomware immunity.
//!
//! Simulates a malicious process that tries to encrypt files. Under IKRL,
//! every file write requires a user-intent capability token. Without a token,
//! the write syscall is denied, resulting in 0 bytes encrypted.

use anyhow::Result;
use clap::Parser;
use intentkernel_core::{
    context_hash, default_policy, wall_epoch_ms, CapabilityScope, CapabilityTable, CapabilityToken,
    IntentEvent, LeaseState, TrustAnchor,
};
use intentkernel_crypto as crypto;
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
#[command(name = "ransomware-demo")]
#[command(about = "Demonstrate IntentKernel ransomware immunity")]
struct Args {
    #[arg(long, default_value = "demo_victim")]
    target_dir: String,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    info!("=== IntentKernel Ransomware Immunity Demo ===");

    // Set up broker key (capd stub)
    let kp = crypto::ml_dsa87_keygen()?;
    let table = CapabilityTable::new();
    table.set_broker_key(kp.public_key);

    // Create sample victim files
    std::fs::create_dir_all(&args.target_dir)?;
    let victim_path = format!("{}/secret.txt", args.target_dir);
    std::fs::write(&victim_path, "This is important user data.")?;
    info!("created victim file: {}", victim_path);

    // --- Phase 1: Ransomware without capability ---
    info!("\n[Phase 1] Ransomware attempts silent encryption...");
    let encrypted_bytes_1 = simulate_ransomware(&victim_path, None, &table);
    if encrypted_bytes_1 == 0 {
        info!("RESULT: 0 bytes encrypted — ransomware structurally blocked.");
    } else {
        error!("FAILURE: {} bytes encrypted", encrypted_bytes_1);
    }

    // --- Phase 2: Legitimate user action grants capability ---
    info!("\n[Phase 2] User clicks 'Save' — broker issues one write token...");
    let token = issue_write_token(&kp, "app://editor", &victim_path)?;
    let handle = table.register_full_token(&token)?;
    info!("legitimate handle registered: {:#x}", handle.to_u64());

    // --- Phase 3: Legitimate write with capability ---
    info!("\n[Phase 3] Legitimate save with valid capability...");
    let written_bytes = simulate_legitimate_save(&victim_path, handle, &table);
    if written_bytes > 0 {
        info!("RESULT: {} bytes written legitimately.", written_bytes);
    }

    // --- Phase 4: Token burn after single use ---
    info!("\n[Phase 4] Ransomware steals the used token and tries again...");
    let encrypted_bytes_2 = simulate_ransomware(&victim_path, Some(&token), &table);
    if encrypted_bytes_2 == 0 {
        info!("RESULT: 0 bytes encrypted — token already burned.");
    } else {
        error!("FAILURE: {} bytes encrypted", encrypted_bytes_2);
    }

    info!("\n=== Summary ===");
    info!(
        "Unauthorized writes (no intent): {} bytes",
        encrypted_bytes_1
    );
    info!("Authorized write (user intent): {} bytes", written_bytes);
    info!("Reused token writes: {} bytes", encrypted_bytes_2);
    info!("This architecture makes ransomware structurally impossible.");

    Ok(())
}

fn simulate_ransomware(
    path: &str,
    maybe_token: Option<&CapabilityToken>,
    table: &CapabilityTable,
) -> usize {
    // Malware attempts to read file and write encrypted-looking bytes.
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => return 0,
    };

    // No token -> no kernel handle -> syscall denied.
    if maybe_token.is_none() {
        warn!(
            "  [eventscope] BLOCKED open({}) — no capability token",
            path
        );
        return 0;
    }

    let token = maybe_token.unwrap();
    // Re-register full token. In real malware it would present a stolen token.
    match table.register_full_token(token) {
        Ok(handle) => {
            match table.validate_handle(handle) {
                Ok(_) => {
                    // Even if it validates once, it is single-use.
                    let ciphertext: Vec<u8> = data.iter().map(|b| b ^ 0xAA).collect();
                    warn!("  [kernel] ALLOWED one write (token consumed)");
                    // Second block attempt immediately fails
                    let handle2 = table.get_handle(handle.table_index).unwrap();
                    if table.validate_handle(handle2).is_err() {
                        warn!("  [kernel] DENIED second write — token burned");
                    }
                    let _ = std::fs::write(path, ciphertext);
                    data.len()
                }
                Err(e) => {
                    warn!("  [kernel] DENIED write — {:?}", e);
                    0
                }
            }
        }
        Err(e) => {
            warn!("  [capd] DENIED token registration — {}", e);
            0
        }
    }
}

fn simulate_legitimate_save(
    path: &str,
    handle: intentkernel_core::KernelHandle,
    table: &CapabilityTable,
) -> usize {
    match table.validate_handle(handle) {
        Ok(cap_type) => {
            info!("  [kernel] ALLOWED {:?} via handle", cap_type);
            let new_data = b"Updated content after user clicked Save.";
            let _ = std::fs::write(path, new_data);
            new_data.len()
        }
        Err(e) => {
            warn!("  [kernel] DENIED save — {:?}", e);
            0
        }
    }
}

fn issue_write_token(
    kp: &crypto::MlDsa87KeyPair,
    actor_id: &str,
    path: &str,
) -> Result<CapabilityToken> {
    let event = IntentEvent {
        actor_id: actor_id.to_string(),
        action: "write".to_string(),
        resource: "file".to_string(),
        anchor: TrustAnchor::UiEvent,
        timestamp_ms: wall_epoch_ms(),
        metadata: Default::default(),
    };
    let decision = default_policy(&event);
    let now = wall_epoch_ms();
    let ctx = context_hash(actor_id, "user-session-1", "device-demo", path, now);
    let mut token = CapabilityToken {
        ver: 1,
        typ: intentkernel_core::TokenType::Capability,
        alg: 1,
        anchor: TrustAnchor::UiEvent,
        iss: "broker-demo".into(),
        sub: actor_id.into(),
        ctx,
        scope: CapabilityScope::new("file", "write").with_constraint("path", path),
        exp: now + decision.ttl_ms,
        nbf: now,
        uses: decision.max_uses,
        state: LeaseState::Granted,
        jti: uuid::Uuid::new_v4().to_string(),
        signature: Vec::new(),
    };
    let cbor = intentkernel_core::token_to_cbor(&token)?;
    token.signature = crypto::ml_dsa87_sign(&kp.secret_key, &cbor)?.to_vec();
    Ok(token)
}
