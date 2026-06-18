//! ikrl-fs — Filesystem capability mediator.
//!
//! All filesystem access goes through this daemon. Legacy `open()`/`write()`
//! calls are shadowed by the runtime wrapper and replaced with capability-
//! gated RPCs to this service. Each operation checks that the presented
//! token's scope matches the requested path and action.

use anyhow::Result;
use clap::Parser;
use ikrl_transport::{Channel, Listener};
use intentkernel_core::{token_from_cbor, CapabilityTable, CapabilityType};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use tokio::fs;
use tokio::sync::Mutex;
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "ikrl-fs")]
#[command(about = "IntentKernel Filesystem Capability Mediator")]
struct Args {
    #[arg(long, default_value = "tcp://127.0.0.1:9400")]
    listen: String,

    #[arg(long, default_value = "tcp://127.0.0.1:9103")]
    eventscope_addr: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "method", content = "params")]
enum Request {
    Read {
        path: String,
        token_cbor: Vec<u8>,
    },
    Write {
        path: String,
        data: Vec<u8>,
        token_cbor: Vec<u8>,
    },
    List {
        path: String,
        token_cbor: Vec<u8>,
    },
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

    let table = Arc::new(Mutex::new(CapabilityTable::new()));
    {
        let t = table.lock().await;
        if let Ok(pk_hex) = fetch_broker_key(&args.eventscope_addr).await {
            let pk_bytes = hex::decode(pk_hex)?;
            let pk: [u8; 2592] = pk_bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("bad public key length"))?;
            t.set_broker_key(pk);
            info!("installed broker public key");
        } else {
            warn!("could not fetch broker key");
        }
    }

    let listener = Listener::bind(&args.listen).await?;
    info!("ikrl-fs listening on {}", args.listen);

    loop {
        let mut ch = listener.accept().await?;
        let table = Arc::clone(&table);
        tokio::spawn(async move {
            if let Err(e) = handle_client(&mut ch, table).await {
                warn!("client error: {}", e);
            }
        });
    }
}

async fn handle_client(ch: &mut Channel, table: Arc<Mutex<CapabilityTable>>) -> Result<()> {
    let req: Request = ch.recv_json().await?;
    let table = table.lock().await;

    let resp = match req {
        Request::Read { path, token_cbor } => {
            let token = token_from_cbor(&token_cbor)?;
            if !scope_allows(&token.scope.constraints, &path, "read") {
                Response::Denied {
                    reason: "path not in capability scope".into(),
                }
            } else {
                match table.register_full_token(&token) {
                    Ok(handle) => match table.validate_handle(handle) {
                        Ok(CapabilityType::FileReadOnce) | Ok(_) => match fs::read(&path).await {
                            Ok(bytes) => Response::Ok {
                                data: serde_json::json!({
                                    "path": path,
                                    "bytes": hex::encode(bytes),
                                }),
                            },
                            Err(e) => Response::Error {
                                message: e.to_string(),
                            },
                        },
                        Err(e) => Response::Denied {
                            reason: format!("{:?}", e),
                        },
                    },
                    Err(e) => Response::Denied {
                        reason: e.to_string(),
                    },
                }
            }
        }
        Request::Write {
            path,
            data,
            token_cbor,
        } => {
            let token = token_from_cbor(&token_cbor)?;
            if !scope_allows(&token.scope.constraints, &path, "write") {
                Response::Denied {
                    reason: "path not in capability scope".into(),
                }
            } else {
                match table.register_full_token(&token) {
                    Ok(handle) => match table.validate_handle(handle) {
                        Ok(_) => match fs::write(&path, &data).await {
                            Ok(_) => Response::Ok {
                                data: serde_json::json!({
                                    "path": path,
                                    "written": data.len(),
                                }),
                            },
                            Err(e) => Response::Error {
                                message: e.to_string(),
                            },
                        },
                        Err(e) => Response::Denied {
                            reason: format!("{:?}", e),
                        },
                    },
                    Err(e) => Response::Denied {
                        reason: e.to_string(),
                    },
                }
            }
        }
        Request::List { path, token_cbor } => {
            let token = token_from_cbor(&token_cbor)?;
            if !scope_allows(&token.scope.constraints, &path, "list") {
                Response::Denied {
                    reason: "path not in capability scope".into(),
                }
            } else {
                match table.register_full_token(&token) {
                    Ok(handle) => match table.validate_handle(handle) {
                        Ok(_) => {
                            let mut entries = Vec::new();
                            match fs::read_dir(&path).await {
                                Ok(mut dir) => {
                                    while let Ok(Some(entry)) = dir.next_entry().await {
                                        if let Ok(meta) = entry.metadata().await {
                                            entries.push(serde_json::json!({
                                                "name": entry.file_name().to_string_lossy(),
                                                "is_file": meta.is_file(),
                                                "is_dir": meta.is_dir(),
                                            }));
                                        }
                                    }
                                    Response::Ok {
                                        data: serde_json::json!({
                                            "path": path,
                                            "entries": entries,
                                        }),
                                    }
                                }
                                Err(e) => Response::Error {
                                    message: e.to_string(),
                                },
                            }
                        }
                        Err(e) => Response::Denied {
                            reason: format!("{:?}", e),
                        },
                    },
                    Err(e) => Response::Denied {
                        reason: e.to_string(),
                    },
                }
            }
        }
    };

    ch.send_json(&resp).await?;
    Ok(())
}

fn scope_allows(
    constraints: &std::collections::BTreeMap<String, String>,
    path: &str,
    action: &str,
) -> bool {
    let scope_path = constraints.get("path").map(|s| s.as_str()).unwrap_or("");
    let scope_action = constraints.get("action").map(|s| s.as_str()).unwrap_or("");
    let requested = Path::new(path)
        .canonicalize()
        .unwrap_or_else(|_| Path::new(path).into());
    let allowed = Path::new(scope_path)
        .canonicalize()
        .unwrap_or_else(|_| Path::new(scope_path).into());
    requested.starts_with(&allowed) && (scope_action.is_empty() || scope_action == action)
}

async fn fetch_broker_key(eventscope_addr: &str) -> Result<String> {
    let req = serde_json::json!({"method": "GetPublicKey"});
    let resp: serde_json::Value = ikrl_transport::rpc(eventscope_addr, &req).await?;
    Ok(resp["data"]["public_key"]
        .as_str()
        .unwrap_or("")
        .to_string())
}
