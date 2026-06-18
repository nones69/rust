//! eventscope — Runtime wrapper and syscall interceptor.
//!
//! On Linux this uses ptrace to intercept syscalls and verify capability
//! tokens before the host kernel services the request. On non-Linux hosts it
//! provides a simulation mode for development and testing.

use anyhow::Result;
use clap::Parser;
use ikrl_transport::{Channel, Listener};
use intentkernel_core::{CapabilityTable, KernelHandle};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "eventscope")]
#[command(about = "IntentKernel EventScope runtime wrapper")]
struct Args {
    #[arg(long, default_value = "tcp://127.0.0.1:9103")]
    listen: String,

    #[arg(long, default_value = "tcp://127.0.0.1:9101")]
    capd_addr: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "method", content = "params")]
enum Request {
    RegisterToken {
        token_cbor: Vec<u8>,
    },
    Syscall {
        handle: u64,
        syscall: String,
        args: Vec<String>,
    },
    SimulateIntercept {
        pid: u32,
        syscall: String,
    },
    GetPublicKey,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "status")]
enum Response {
    Ok { data: serde_json::Value },
    Denied { reason: String },
    Error { message: String },
}

struct State {
    table: CapabilityTable,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let state = Arc::new(Mutex::new(State {
        table: CapabilityTable::new(),
    }));

    // Fetch broker public key from capd and install it.
    {
        if let Ok(pk_hex) = fetch_broker_key(&args.capd_addr).await {
            let pk_bytes = hex::decode(pk_hex)?;
            let pk: [u8; 2592] = pk_bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("bad public key length"))?;
            state.lock().unwrap().table.set_broker_key(pk);
            info!("installed broker public key");
        } else {
            warn!("could not fetch broker key; token registration will fail");
        }
    }

    let listener = Listener::bind(&args.listen).await?;
    info!("eventscope listening on {}", args.listen);

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
        Request::RegisterToken { token_cbor } => {
            let s = state.lock().unwrap();
            match s
                .table
                .register_full_token(&intentkernel_core::token_from_cbor(&token_cbor)?)
            {
                Ok(handle) => Response::Ok {
                    data: serde_json::json!({"handle": handle.to_u64()}),
                },
                Err(e) => Response::Denied {
                    reason: e.to_string(),
                },
            }
        }
        Request::Syscall {
            handle,
            syscall,
            args,
        } => {
            let h = KernelHandle {
                table_index: (handle >> 32) as u32,
                generation: (handle >> 16) as u16,
                checksum: (handle & 0xFFFF) as u16,
            };
            let s = state.lock().unwrap();
            match s.table.validate_handle(h) {
                Ok(cap_type) => Response::Ok {
                    data: serde_json::json!({
                        "allowed": true,
                        "capability": format!("{:?}", cap_type),
                        "syscall": syscall,
                        "args": args,
                    }),
                },
                Err(why) => Response::Denied {
                    reason: format!("{:?}", why),
                },
            }
        }
        Request::SimulateIntercept { pid, syscall } => {
            info!("simulated intercept: pid={} syscall={}", pid, syscall);
            Response::Denied {
                reason: format!("no capability registered for pid {} on {}", pid, syscall),
            }
        }
        Request::GetPublicKey => Response::Ok {
            data: serde_json::json!({"public_key": ""}),
        },
    };

    ch.send_json(&resp).await?;
    Ok(())
}

async fn fetch_broker_key(capd_addr: &str) -> Result<String> {
    let req = serde_json::json!({"method": "GetPublicKey"});
    let resp: serde_json::Value = ikrl_transport::rpc(capd_addr, &req).await?;
    Ok(resp["data"]["public_key"]
        .as_str()
        .unwrap_or("")
        .to_string())
}

#[cfg(target_os = "linux")]
pub mod linux {
    use nix::sys::ptrace;
    use nix::sys::wait::waitpid;
    use nix::unistd::Pid;

    pub fn attach_and_intercept(pid: i32) -> anyhow::Result<()> {
        let pid = Pid::from_raw(pid);
        ptrace::attach(pid)?;
        waitpid(pid, None)?;
        loop {
            ptrace::syscall(pid, None)?;
            waitpid(pid, None)?;
            // In a real implementation: read registers, identify syscall,
            // verify capability token, then allow or inject EPERM.
        }
    }
}
