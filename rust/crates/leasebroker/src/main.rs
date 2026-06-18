//! leasebroker — Process lease watchdog.
//!
//! Issues renewable background execution leases and suspends/kills processes
//! that fail to renew within their TTL.

use anyhow::Result;
use clap::Parser;
use ikrl_transport::{Channel, Listener};
use intentkernel_core::{wall_epoch_ms, LeaseState, ProcessLease};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "leasebroker")]
#[command(about = "IntentKernel Lease Watchdog")]
struct Args {
    #[arg(long, default_value = "tcp://127.0.0.1:9102")]
    listen: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "method", content = "params")]
enum Request {
    RequestLease { pid: u32, duration_ms: u64 },
    RenewLease { lease_id: String },
    GetLease { lease_id: String },
    ListLeases,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "status")]
enum Response {
    Ok { data: serde_json::Value },
    Error { message: String },
}

struct State {
    leases: HashMap<String, ProcessLease>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let state = Arc::new(Mutex::new(State {
        leases: HashMap::new(),
    }));

    let state_clone = Arc::clone(&state);
    tokio::task::spawn_blocking(move || watch_loop(state_clone));

    let listener = Listener::bind(&args.listen).await?;
    info!("leasebroker listening on {}", args.listen);

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
        Request::RequestLease { pid, duration_ms } => {
            let lease_id = format!("lease-{}", uuid::Uuid::new_v4());
            let now = wall_epoch_ms();
            let lease = ProcessLease {
                lease_id: lease_id.clone(),
                pid,
                state: LeaseState::Granted,
                granted_at: now,
                expires_at: now + duration_ms,
                renew_interval_ms: duration_ms / 2,
            };
            state
                .lock()
                .unwrap()
                .leases
                .insert(lease_id.clone(), lease.clone());
            info!(
                "granted lease {} to pid {} for {} ms",
                lease_id, pid, duration_ms
            );
            Response::Ok {
                data: serde_json::to_value(lease)?,
            }
        }
        Request::RenewLease { lease_id } => {
            let mut s = state.lock().unwrap();
            match s.leases.get_mut(&lease_id) {
                Some(lease) => {
                    let now = wall_epoch_ms();
                    if lease.state == LeaseState::Revoked || lease.state == LeaseState::Expired {
                        Response::Error {
                            message: "lease cannot be renewed".into(),
                        }
                    } else {
                        lease.expires_at = now + lease.renew_interval_ms * 2;
                        lease.state = LeaseState::Granted;
                        info!("renewed lease {} until {}", lease_id, lease.expires_at);
                        Response::Ok {
                            data: serde_json::to_value(lease)?,
                        }
                    }
                }
                None => Response::Error {
                    message: "lease not found".into(),
                },
            }
        }
        Request::GetLease { lease_id } => {
            let s = state.lock().unwrap();
            match s.leases.get(&lease_id) {
                Some(lease) => Response::Ok {
                    data: serde_json::to_value(lease)?,
                },
                None => Response::Error {
                    message: "lease not found".into(),
                },
            }
        }
        Request::ListLeases => {
            let s = state.lock().unwrap();
            Response::Ok {
                data: serde_json::to_value(s.leases.values().collect::<Vec<_>>())?,
            }
        }
    };

    ch.send_json(&resp).await?;
    Ok(())
}

fn watch_loop(state: Arc<Mutex<State>>) {
    loop {
        std::thread::sleep(Duration::from_millis(500));
        let now = wall_epoch_ms();
        let mut s = state.lock().unwrap();
        for lease in s.leases.values_mut() {
            if lease.expires_at < now && lease.state != LeaseState::Expired {
                lease.state = LeaseState::Expired;
                warn!(
                    "lease {} expired; pid {} should be suspended/killed",
                    lease.lease_id, lease.pid
                );
            }
        }
    }
}
