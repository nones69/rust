//! ikrl-federation — Cross-device capability federation.
//!
//! Devices running IntentKernel discover each other via mDNS and exchange
//! short-lived, scoped capability tokens. No accounts, no pairing, no cloud
//! required. A token issued by one device's broker is validated by the peer's
//! broker through pre-shared or federated trust.

use anyhow::Result;
use clap::Parser;
use intentkernel_core::TrustAnchor;
use intentkernel_crypto as crypto;
use mdns_sd::{ServiceDaemon, ServiceEvent};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

const SERVICE_TYPE: &str = "_intentkernel._tcp.local.";

#[derive(Parser, Debug)]
#[command(name = "ikrl-federation")]
#[command(about = "IntentKernel Cross-Device Federation")]
struct Args {
    #[arg(long, default_value = "device-1")]
    device_id: String,

    #[arg(long, default_value = "127.0.0.1:9310")]
    listen: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "method", content = "params")]
enum Request {
    Advertise {
        device_id: String,
        listen_addr: String,
    },
    Delegate(DelegationParams),
    Verify(VerifyParams),
}

#[derive(Serialize, Deserialize, Debug)]
struct DelegationParams {
    token_cbor: Vec<u8>,
    target_device_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct VerifyParams {
    token_cbor: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "status")]
enum Response {
    Ok { data: serde_json::Value },
    Error { message: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    // Generate a device identity keypair (mock).
    let _kp = crypto::ml_dsa87_keygen()?;

    // Start mDNS advertisement.
    let mdns = ServiceDaemon::new()?;
    let service_info = mdns_sd::ServiceInfo::new(
        SERVICE_TYPE,
        &args.device_id,
        &args.listen,
        &args.listen,
        9300,
        None,
    )?;
    mdns.register(service_info)?;
    info!("advertised {} on {}", args.device_id, args.listen);

    // Browse for peers.
    let receiver = mdns.browse(SERVICE_TYPE)?;
    let peers = Arc::new(tokio::sync::Mutex::new(HashMap::<String, String>::new()));

    let peers_clone = Arc::clone(&peers);
    tokio::spawn(async move {
        while let Ok(event) = receiver.recv() {
            match event {
                ServiceEvent::ServiceResolved(info) => {
                    let id = info
                        .get_fullname()
                        .split('.')
                        .next()
                        .unwrap_or("unknown")
                        .to_string();
                    if let Some(addr) = info.get_addresses().iter().next() {
                        let port = info.get_port();
                        let listen = format!("{}:{}", addr, port);
                        info!("discovered peer {} at {}", id, listen);
                        peers_clone.lock().await.insert(id, listen);
                    }
                }
                _ => {}
            }
        }
    });

    // Listen for incoming federation requests.
    let listener = TcpListener::bind(&args.listen).await?;
    info!("federation listening on {}", args.listen);

    loop {
        let (stream, _) = listener.accept().await?;
        let peers = Arc::clone(&peers);
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, peers).await {
                warn!("federation client error: {}", e);
            }
        });
    }
}

async fn handle_client(
    mut stream: TcpStream,
    peers: Arc<tokio::sync::Mutex<HashMap<String, String>>>,
) -> Result<()> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    let req: Request = serde_json::from_slice(&buf)?;

    let resp = match req {
        Request::Advertise {
            device_id,
            listen_addr,
        } => {
            peers.lock().await.insert(device_id, listen_addr);
            Response::Ok {
                data: serde_json::json!({"ack": true}),
            }
        }
        Request::Delegate(p) => {
            // Re-encode token for target device. In production this would
            // re-sign with the target device's broker key.
            let token = intentkernel_core::token_from_cbor(&p.token_cbor)?;
            info!(
                "delegating token {} to device {}",
                token.jti, p.target_device_id
            );
            if let Some(peer_addr) = peers.lock().await.get(&p.target_device_id) {
                match forward_to_peer(peer_addr, &p.token_cbor).await {
                    Ok(_) => Response::Ok {
                        data: serde_json::json!({"forwarded": true}),
                    },
                    Err(e) => Response::Error {
                        message: e.to_string(),
                    },
                }
            } else {
                Response::Error {
                    message: "target device not discovered".into(),
                }
            }
        }
        Request::Verify(p) => {
            // Verify a token presented by a remote device. Real verification
            // checks the federated broker signature.
            let token = intentkernel_core::token_from_cbor(&p.token_cbor)?;
            let valid = token.anchor as u8 >= TrustAnchor::Federated as u8;
            Response::Ok {
                data: serde_json::json!({"valid": valid, "jti": token.jti}),
            }
        }
    };

    let bytes = serde_json::to_vec(&resp)?;
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(&bytes).await?;
    Ok(())
}

async fn forward_to_peer(addr: &str, token_cbor: &[u8]) -> Result<()> {
    let mut stream = TcpStream::connect(addr).await?;
    let req = Request::Verify(VerifyParams {
        token_cbor: token_cbor.to_vec(),
    });
    let bytes = serde_json::to_vec(&req)?;
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(&bytes).await?;
    Ok(())
}
