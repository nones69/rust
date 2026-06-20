//! ikrl-ai — Capability-gated AI inference gateway.
//!
//! Every LLM inference, tool use, or agent action requires an
//! event-scoped capability token. This makes AI agents structurally
//! unable to exfiltrate data, call tools, or spend compute without
//! explicit user intent.

use anyhow::Result;
use async_trait::async_trait;
use clap::Parser;
use ikrl_transport::{Channel, Listener};
use intentkernel_core::{ai_prompt_ip_allowed, token_from_cbor, CapabilityTable};
use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "ikrl-ai")]
#[command(about = "IntentKernel AI Capability Gateway")]
struct Args {
    #[arg(long, default_value = "tcp://127.0.0.1:9200")]
    listen: String,

    #[arg(long, default_value = "tcp://127.0.0.1:9103")]
    eventscope_addr: String,

    #[arg(long, default_value = "http://localhost:11434")]
    ollama_url: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "method", content = "params")]
enum Request {
    Infer(InferParams),
    ToolUse(ToolUseParams),
}

#[derive(Serialize, Deserialize, Debug)]
struct InferParams {
    model: String,
    prompt: String,
    token_cbor: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
struct ToolUseParams {
    tool_name: String,
    arguments: serde_json::Value,
    token_cbor: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "status")]
enum Response {
    Ok { data: serde_json::Value },
    Denied { reason: String },
    Error { message: String },
}

#[async_trait]
trait ModelBackend: Send + Sync {
    async fn infer(&self, model: &str, prompt: &str) -> Result<serde_json::Value>;
}

struct OllamaBackend {
    base_url: String,
    client: reqwest::Client,
}

#[async_trait]
impl ModelBackend for OllamaBackend {
    async fn infer(&self, model: &str, prompt: &str) -> Result<serde_json::Value> {
        let url = format!("{}/api/generate", self.base_url);
        let body = serde_json::json!({
            "model": model,
            "prompt": prompt,
            "stream": false,
        });
        let resp = self.client.post(&url).json(&body).send().await?;
        let json = resp.json().await?;
        Ok(json)
    }
}

struct State {
    table: CapabilityTable,
    backend: Arc<dyn ModelBackend>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let state = Arc::new(Mutex::new(State {
        table: CapabilityTable::new(),
        backend: Arc::new(OllamaBackend {
            base_url: args.ollama_url.clone(),
            client: reqwest::Client::new(),
        }),
    }));

    // Fetch broker key from eventscope.
    if let Ok(pk_hex) = fetch_broker_key(&args.eventscope_addr).await {
        let pk_bytes = hex::decode(pk_hex)?;
        let pk: [u8; 2592] = pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("bad public key length"))?;
        state.lock().await.table.set_broker_key(pk);
        info!("installed broker public key");
    } else {
        warn!("could not fetch broker key; token registration will fail");
    }

    let listener = Listener::bind(&args.listen).await?;
    info!("ikrl-ai listening on {}", args.listen);

    loop {
        let mut ch = listener.accept().await?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = handle_client(&mut ch, state).await {
                warn!("client error: {}", e);
            }
        });
    }
}

async fn handle_client(ch: &mut Channel, state: Arc<Mutex<State>>) -> Result<()> {
    let req: Request = ch.recv_json().await?;

    let resp = match req {
        Request::Infer(p) => {
            let meta = BTreeMap::new();
            if let Err(reason) = ai_prompt_ip_allowed(&p.prompt, &meta) {
                return respond_denied(ch, &reason).await;
            }
            let token = token_from_cbor(&p.token_cbor)?;
            let s = state.lock().await;
            match s.table.register_full_token(&token) {
                Ok(handle) => {
                    if s.table.validate_handle(handle).is_ok() {
                        match s.backend.infer(&p.model, &p.prompt).await {
                            Ok(data) => Response::Ok { data },
                            Err(e) => Response::Error {
                                message: e.to_string(),
                            },
                        }
                    } else {
                        Response::Denied {
                            reason: "invalid or exhausted capability".into(),
                        }
                    }
                }
                Err(e) => Response::Denied {
                    reason: e.to_string(),
                },
            }
        }
        Request::ToolUse(p) => {
            let token = token_from_cbor(&p.token_cbor)?;
            let s = state.lock().await;
            match s.table.register_full_token(&token) {
                Ok(handle) => {
                    if s.table.validate_handle(handle).is_ok() {
                        let result = serde_json::json!({
                            "tool": p.tool_name,
                            "arguments": p.arguments,
                            "status": "would execute under capability scope"
                        });
                        Response::Ok { data: result }
                    } else {
                        Response::Denied {
                            reason: "invalid or exhausted capability".into(),
                        }
                    }
                }
                Err(e) => Response::Denied {
                    reason: e.to_string(),
                },
            }
        }
    };

    ch.send_json(&resp).await?;
    Ok(())
}

async fn respond_denied(ch: &mut Channel, reason: &str) -> Result<()> {
    ch.send_json(&Response::Denied {
        reason: reason.to_string(),
    })
    .await?;
    Ok(())
}

async fn fetch_broker_key(eventscope_addr: &str) -> Result<String> {
    let req = serde_json::json!({"method": "GetPublicKey"});
    let resp: serde_json::Value = ikrl_transport::rpc(eventscope_addr, &req).await?;
    Ok(resp["data"]["public_key"]
        .as_str()
        .unwrap_or("")
        .to_string())
}
