//! ikrl-bridge — TCP gateway between CRASS OS IPC and host IntentKernel daemons.

use anyhow::Result;
use clap::Parser;
use ikrl_bridge::{map_to_host_request, BridgeResponse, CrassIpcMessage};
use ikrl_transport::{Channel, Listener};
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "ikrl-bridge")]
#[command(about = "CRASS OS ↔ IntentKernel protocol bridge")]
struct Args {
    #[arg(long, default_value = "tcp://127.0.0.1:9300")]
    listen: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let listener = Listener::bind(&args.listen).await?;
    info!("ikrl-bridge listening on {}", args.listen);

    loop {
        let mut ch = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_client(&mut ch).await {
                warn!("bridge client error: {e}");
            }
        });
    }
}

async fn handle_client(ch: &mut Channel) -> Result<()> {
    let msg: CrassIpcMessage = ch.recv_json().await?;
    let (channel, host_req) = map_to_host_request(&msg)?;

    if host_req.get("crass_local").is_some() {
        let local = &host_req["crass_local"];
        let resp = if local["allowed"].as_bool().unwrap_or(false) {
            BridgeResponse::Ok {
                data: local.clone(),
            }
        } else {
            BridgeResponse::Denied {
                reason: local["reason"]
                    .as_str()
                    .unwrap_or("denied")
                    .to_string(),
            }
        };
        ch.send_json(&resp).await?;
        return Ok(());
    }

    let addr = channel.default_host_addr();
    match ikrl_transport::rpc(addr, &host_req).await {
        Ok(data) => {
            ch.send_json(&BridgeResponse::Ok { data }).await?;
        }
        Err(e) => {
            ch.send_json(&BridgeResponse::Error {
                message: e.to_string(),
            })
            .await?;
        }
    }
    Ok(())
}