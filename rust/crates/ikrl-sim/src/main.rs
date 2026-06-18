//! ikrl-sim — In-process simulator for the IntentKernel ecosystem.
//!
//! Starts stub versions of intentd, capd, leasebroker, and eventscope in a
//! single process so developers can test capability flows without deploying
//! the full daemon stack.

use anyhow::Result;
use clap::Parser;
use intentkernel_core::{
    context_hash, default_policy, wall_epoch_ms, CapabilityScope, CapabilityTable, CapabilityToken,
    IntentEvent, LeaseState, ProcessLease, TrustAnchor,
};
use intentkernel_crypto as crypto;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "ikrl-sim")]
#[command(about = "IntentKernel Relief Layer Simulator")]
struct Args {
    #[arg(long, default_value = "file")]
    resource: String,
    #[arg(long, default_value = "read")]
    action: String,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    info!("starting IntentKernel simulator");

    // 1. Broker key generation (capd stub)
    let kp = crypto::ml_dsa87_keygen()?;
    info!("capd: broker key generated");

    // 2. Intent event (user clicks "Open file")
    let event = IntentEvent {
        actor_id: "app://text-editor".to_string(),
        action: args.action.clone(),
        resource: args.resource.clone(),
        anchor: TrustAnchor::UiEvent,
        timestamp_ms: wall_epoch_ms(),
    };

    // 3. Policy decision (intentd stub)
    let decision = default_policy(&event);
    info!(
        "intentd: policy decision = allowed:{} ttl:{} ms uses:{}",
        decision.allowed, decision.ttl_ms, decision.max_uses
    );
    if !decision.allowed {
        anyhow::bail!("intent denied by policy");
    }

    // 4. Issue signed token (capd stub)
    let now = wall_epoch_ms();
    let ctx = context_hash(
        &event.actor_id,
        "user-session-1",
        "device-sim",
        &format!("{}/{}", args.resource, args.action),
        now,
    );
    let mut token = CapabilityToken {
        ver: 1,
        typ: intentkernel_core::TokenType::Capability,
        alg: 1,
        anchor: event.anchor,
        iss: "broker-sim".into(),
        sub: event.actor_id.clone(),
        ctx,
        scope: CapabilityScope::new(&args.resource, &args.action),
        exp: now + decision.ttl_ms,
        nbf: now,
        uses: decision.max_uses,
        state: LeaseState::Granted,
        jti: uuid::Uuid::new_v4().to_string(),
        signature: Vec::new(),
    };
    let cbor = intentkernel_core::token_to_cbor(&token)?;
    token.signature = crypto::ml_dsa87_sign(&kp.secret_key, &cbor)?.to_vec();
    info!("capd: issued token {}", token.jti);

    // 5. Register token in kernel table (eventscope stub)
    let table = CapabilityTable::new();
    table.set_broker_key(kp.public_key);
    let handle = table.register_full_token(&token)?;
    info!("eventscope: registered handle {:#x}", handle.to_u64());

    // 6. Use the capability
    match table.validate_handle(handle) {
        Ok(cap_type) => info!("kernel: allowed {:?} via handle", cap_type),
        Err(e) => anyhow::bail!("capability validation failed: {:?}", e),
    }

    // 7. Try to use again (single-use should fail)
    match table.validate_handle(handle) {
        Ok(_) => info!("kernel: second use allowed (unexpected)"),
        Err(e) => info!("kernel: second use denied {:?}", e),
    }

    // 8. Lease lifecycle (leasebroker stub)
    let lease = ProcessLease {
        lease_id: "lease-1".into(),
        pid: 1234,
        state: LeaseState::Granted,
        granted_at: now,
        expires_at: now + 30_000,
        renew_interval_ms: 15_000,
    };
    info!(
        "leasebroker: granted lease {} for {} ms",
        lease.lease_id,
        lease.expires_at - lease.granted_at
    );

    Ok(())
}
