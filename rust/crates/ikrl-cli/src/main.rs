//! ikrl-cli — Command-line interface for the IntentKernel daemon stack.
//!
//! Useful for integration testing, demos, and manual administration:
//!
//!   ikrl-cli intent --resource file --action read --actor myapp
//!   ikrl-cli register --token-file token.cbor
//!   ikrl-cli syscall --handle 0x20202 --syscall write

use anyhow::Result;
use clap::{Parser, Subcommand};
use ikrl_transport::rpc;
use intentkernel_core::{wall_epoch_ms, CapabilityToken, IntentEvent, TrustAnchor};
use serde_json::json;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "ikrl-cli")]
#[command(about = "IntentKernel command-line interface")]
struct Args {
    #[arg(long, default_value = "tcp://127.0.0.1:9100")]
    intentd: String,

    #[arg(long, default_value = "tcp://127.0.0.1:9101")]
    capd: String,

    #[arg(long, default_value = "tcp://127.0.0.1:9103")]
    eventscope: String,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Submit an intent and receive a capability token.
    Intent {
        #[arg(short, long)]
        resource: String,
        #[arg(short, long)]
        action: String,
        #[arg(short, long, default_value = "ikrl-cli")]
        actor: String,
        #[arg(short, long, default_value = "UiEvent")]
        anchor: String,
    },
    /// Register a token at eventscope and return a kernel handle.
    Register {
        #[arg(short, long)]
        token_cbor_hex: String,
    },
    /// Invoke a syscall using a kernel handle.
    Syscall {
        #[arg(short, long)]
        handle: u64,
        #[arg(short, long)]
        syscall: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Verify a token signature at capd.
    Verify {
        #[arg(short, long)]
        token_cbor_hex: String,
    },
    /// Submit intent, verify, register, and invoke in one shot.
    FullFlow {
        #[arg(short, long)]
        resource: String,
        #[arg(short, long)]
        action: String,
        #[arg(short, long, default_value = "ikrl-cli")]
        actor: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    match args.cmd {
        Command::Intent {
            resource,
            action,
            actor,
            anchor,
        } => {
            let anchor = parse_anchor(&anchor);
            let event = IntentEvent {
                actor_id: actor,
                action: action.clone(),
                resource: resource.clone(),
                anchor,
                timestamp_ms: wall_epoch_ms(),
                metadata: Default::default(),
            };
            let req = json!({"method": "SubmitIntent", "params": event});
            let resp: serde_json::Value = rpc(&args.intentd, &req).await?;
            info!("response: {}", serde_json::to_string_pretty(&resp)?);
            if let Some(token) = resp.get("data") {
                let token: CapabilityToken = serde_json::from_value(token.clone())?;
                let cbor = token.to_cbor()?;
                println!("TOKEN_CBOR_HEX={}", hex::encode(&cbor));
            }
        }
        Command::Register { token_cbor_hex } => {
            let cbor = hex::decode(token_cbor_hex)?;
            let req = json!({"method": "RegisterToken", "params": {"token_cbor": cbor}});
            let resp: serde_json::Value = rpc(&args.eventscope, &req).await?;
            info!("response: {}", serde_json::to_string_pretty(&resp)?);
        }
        Command::Syscall {
            handle,
            syscall,
            args: syscall_args,
        } => {
            let req = json!({
                "method": "Syscall",
                "params": {"handle": handle, "syscall": syscall, "args": syscall_args}
            });
            let resp: serde_json::Value = rpc(&args.eventscope, &req).await?;
            info!("response: {}", serde_json::to_string_pretty(&resp)?);
        }
        Command::Verify { token_cbor_hex } => {
            let cbor = hex::decode(token_cbor_hex)?;
            let req = json!({"method": "VerifyToken", "params": {"token_cbor": cbor}});
            let resp: serde_json::Value = rpc(&args.capd, &req).await?;
            info!("response: {}", serde_json::to_string_pretty(&resp)?);
        }
        Command::FullFlow {
            resource,
            action,
            actor,
        } => {
            let anchor = TrustAnchor::UiEvent;
            let event = IntentEvent {
                actor_id: actor,
                action: action.clone(),
                resource: resource.clone(),
                anchor,
                timestamp_ms: wall_epoch_ms(),
                metadata: Default::default(),
            };
            let req = json!({"method": "SubmitIntent", "params": event});
            let resp: serde_json::Value = rpc(&args.intentd, &req).await?;
            let token: CapabilityToken = serde_json::from_value(resp["data"].clone())?;
            let cbor = token.to_cbor()?;
            let token_hex = hex::encode(&cbor);
            println!("TOKEN_CBOR_HEX={}", token_hex);

            let verify_req =
                json!({"method": "VerifyToken", "params": {"token_cbor": cbor.clone()}});
            let verify_resp: serde_json::Value = rpc(&args.capd, &verify_req).await?;
            info!(
                "capd verify: {}",
                serde_json::to_string_pretty(&verify_resp)?
            );

            let register_req = json!({"method": "RegisterToken", "params": {"token_cbor": cbor}});
            let register_resp: serde_json::Value = rpc(&args.eventscope, &register_req).await?;
            info!(
                "eventscope register: {}",
                serde_json::to_string_pretty(&register_resp)?
            );
        }
    }

    Ok(())
}

fn parse_anchor(s: &str) -> TrustAnchor {
    match s {
        "Biometric" => TrustAnchor::Biometric,
        "Hardware" => TrustAnchor::Hardware,
        "Federated" => TrustAnchor::Federated,
        _ => TrustAnchor::UiEvent,
    }
}
