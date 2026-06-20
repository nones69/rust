//! intentd — Intent Broker daemon.
//!
//! Correlates verified user intent with application requests, applies policy,
//! and asks capd to mint signed capability tokens.

use anyhow::Result;
use clap::Parser;
use ikrl_transport::{rpc, Channel, Listener};
use intentkernel_core::{
    context_hash, default_policy, evaluate_ip, wall_epoch_ms, IntentEvent,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "intentd")]
#[command(about = "IntentKernel Intent Broker")]
struct Args {
    #[arg(long, default_value = "tcp://127.0.0.1:9100")]
    listen: String,

    #[arg(long, default_value = "tcp://127.0.0.1:9101")]
    capd_addr: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "method", content = "params")]
enum Request {
    SubmitIntent(IntentEvent),
    ConfirmIntent { jti: String },
    GetPolicy(IntentEvent),
    AnalyzeIp { ip: String },
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "status")]
enum Response {
    Ok { data: serde_json::Value },
    Denied { reason: String },
    Error { message: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let listener = Listener::bind(&args.listen).await?;
    info!("intentd listening on {}", args.listen);

    loop {
        let mut ch = listener.accept().await?;
        let capd_addr = args.capd_addr.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(&mut ch, &capd_addr).await {
                warn!("client error: {}", e);
            }
        });
    }
}

async fn handle_client(ch: &mut Channel, capd_addr: &str) -> Result<()> {
    let req: Request = ch.recv_json().await?;

    let resp = match req {
        Request::GetPolicy(event) => {
            let decision = default_policy(&event);
            Response::Ok {
                data: serde_json::to_value(decision)?,
            }
        }
        Request::SubmitIntent(event) => {
            let decision = default_policy(&event);
            if !decision.allowed {
                return respond(
                    ch,
                    Response::Denied {
                        reason: decision.reason,
                    },
                )
                .await;
            }
            if decision.requires_confirmation {
                info!("intent requires confirmation: {:?}", event);
            }
            let token =
                issue_token_from_event(&event, decision.ttl_ms, decision.max_uses, capd_addr)
                    .await?;
            info!(
                "issued token {} for {} on {}",
                token.jti, event.action, event.resource
            );
            Response::Ok {
                data: serde_json::to_value(token)?,
            }
        }
        Request::ConfirmIntent { jti } => {
            info!("confirmed intent for token {}", jti);
            Response::Ok {
                data: serde_json::json!({"confirmed": true}),
            }
        }
        Request::AnalyzeIp { ip } => {
            let verdict = evaluate_ip(&ip);
            Response::Ok {
                data: serde_json::to_value(verdict)?,
            }
        }
    };

    respond(ch, resp).await
}

async fn respond(ch: &mut Channel, resp: Response) -> Result<()> {
    ch.send_json(&resp).await?;
    Ok(())
}

async fn issue_token_from_event(
    event: &IntentEvent,
    ttl_ms: u64,
    uses: u32,
    capd_addr: &str,
) -> Result<intentkernel_core::CapabilityToken> {
    let now = wall_epoch_ms();
    let ctx = context_hash(
        &event.actor_id,
        "user-session-1",
        "device-1",
        &event.resource,
        now,
    );

    let mut constraints = BTreeMap::<String, String>::new();
    constraints.insert("actor".into(), event.actor_id.clone());
    constraints.insert("action".into(), event.action.clone());

    let issue_req = serde_json::json!({
        "method": "IssueToken",
        "params": {
            "iss": "broker-1",
            "sub": event.actor_id,
            "ctx": ctx,
            "resource": event.resource,
            "action": event.action,
            "constraints": constraints,
            "exp": now + ttl_ms,
            "nbf": now,
            "uses": uses,
            "anchor": event.anchor,
            "typ": "Capability"
        }
    });

    let resp: serde_json::Value = rpc(capd_addr, &issue_req).await?;

    let cbor = resp["data"]["token_cbor"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("missing token_cbor"))?
        .iter()
        .map(|v| v.as_u64().unwrap_or(0) as u8)
        .collect::<Vec<_>>();

    let token = intentkernel_core::token_from_cbor(&cbor)?;
    Ok(token)
}
