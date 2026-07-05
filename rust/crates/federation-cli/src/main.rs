//! # federation — IntentKernel Federation CLI
//!
//! Manage multi-kernel mesh clusters from the command line.
//!
//! ## Commands
//!
//! ```text
//! federation status            Print this node's federation status
//! federation peers             List known cluster peers
//! federation join <addr>       Join a federation node at <addr>
//! ```
//!
//! All commands connect to a running `intentos-kernel` federation endpoint
//! (default `tcp://127.0.0.1:9310`) and speak the length-prefixed JSON
//! protocol defined in `ikrl-transport`.

use anyhow::Result;
use clap::{Parser, Subcommand};
use intentos_kernel::{
    FederationCluster, FederationRole, HelloMessage, WelcomeMessage,
    HeartbeatMessage, FederationStatus,
};
use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;

// ─── CLI definition ────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "federation",
    about = "IntentKernel Federation CLI — manage multi-kernel mesh clusters",
    version
)]
struct Cli {
    /// Federation endpoint to connect to (tcp://host:port).
    #[arg(long, default_value = "tcp://127.0.0.1:9310", global = true)]
    endpoint: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Print this node's federation status (role, cluster ID, peer count, policy hash).
    Status,
    /// List all known peers in the cluster.
    Peers,
    /// Join a federation node at the given address and perform the handshake.
    Join {
        /// Address of the target kernel federation endpoint (host:port or tcp://host:port).
        addr: String,
    },
    /// Broadcast a heartbeat to all peers and report any policy divergence.
    Heartbeat,
    /// Display the local audit chain length and verify its integrity.
    AuditChain,
}

// ─── Wire protocol ─────────────────────────────────────────────────────────

/// Top-level request sent over the transport channel.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", content = "payload")]
enum FederationRequest {
    Status,
    Peers,
    Join(HelloMessage),
    Heartbeat(HeartbeatMessage),
    AuditChain,
}

/// Top-level response received from the remote endpoint.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", content = "data")]
enum FederationResponse {
    Ok(serde_json::Value),
    Error { message: String },
}

// ─── Command handlers ───────────────────────────────────────────────────────

async fn cmd_status(endpoint: &str) -> Result<()> {
    let resp: FederationResponse =
        ikrl_transport::rpc(endpoint, &FederationRequest::Status).await?;
    match resp {
        FederationResponse::Ok(data) => {
            let status: FederationStatus = serde_json::from_value(data)?;
            println!("kernel_id  : {}", status.kernel_id);
            println!(
                "cluster_id : {}",
                status
                    .cluster_id
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "<not joined>".into())
            );
            println!("role       : {}", status.role);
            println!("peers      : {}", status.peer_count);
            println!("policy     : {}", if status.policy_hash.is_empty() { "<none>" } else { &status.policy_hash });
            println!("audit_len  : {}", status.audit_chain_len);
            println!("pending_tasks: {}", status.pending_tasks);
        }
        FederationResponse::Error { message } => {
            eprintln!("error: {}", message);
            std::process::exit(1);
        }
    }
    Ok(())
}

async fn cmd_peers(endpoint: &str) -> Result<()> {
    let resp: FederationResponse =
        ikrl_transport::rpc(endpoint, &FederationRequest::Peers).await?;
    match resp {
        FederationResponse::Ok(data) => {
            let peers: Vec<serde_json::Value> = serde_json::from_value(data)?;
            if peers.is_empty() {
                println!("(no peers discovered yet)");
            } else {
                println!("{:<36}  {:<20}  {:<8}  {}", "KERNEL_ID", "ADDR", "ROLE", "VERSION");
                for p in peers {
                    println!(
                        "{:<36}  {:<20}  {:<8}  {}",
                        p["kernel_id"].as_str().unwrap_or("-"),
                        p["addr"].as_str().unwrap_or("-"),
                        p["role"].as_str().unwrap_or("-"),
                        p["version"].as_str().unwrap_or("-"),
                    );
                }
            }
        }
        FederationResponse::Error { message } => {
            eprintln!("error: {}", message);
            std::process::exit(1);
        }
    }
    Ok(())
}

async fn cmd_join(_endpoint: &str, target_addr: &str) -> Result<()> {
    // Build a local cluster node just to obtain a HelloMessage.
    let local = FederationCluster::new(
        FederationRole::Peer,
        vec!["file:read".into(), "ai:infer".into()],
    );
    let hello = local.build_hello();
    info!(
        "joining {} as kernel_id={}",
        target_addr,
        hello.kernel_id
    );

    // Send the Hello directly to the target address (not through our local endpoint).
    let target_ep = if target_addr.contains("://") {
        target_addr.to_string()
    } else {
        format!("tcp://{}", target_addr)
    };

    let resp: FederationResponse =
        ikrl_transport::rpc(&target_ep, &FederationRequest::Join(hello)).await?;
    match resp {
        FederationResponse::Ok(data) => {
            let welcome: WelcomeMessage = serde_json::from_value(data)?;
            println!("joined cluster {}", welcome.cluster_id);
            println!("our role      : {}", welcome.role);
            println!(
                "known peers   : {}",
                welcome
                    .peers
                    .iter()
                    .map(|p| p.addr.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        FederationResponse::Error { message } => {
            eprintln!("join rejected: {}", message);
            std::process::exit(1);
        }
    }
    Ok(())
}

async fn cmd_heartbeat(endpoint: &str) -> Result<()> {
    // We broadcast a synthetic heartbeat with an empty policy hash so the
    // remote can compare and signal divergence.
    let hb = HeartbeatMessage {
        kernel_id: Uuid::new_v4(),
        timestamp_ms: chrono_ms(),
        policy_hash: String::new(),
    };
    let resp: FederationResponse =
        ikrl_transport::rpc(endpoint, &FederationRequest::Heartbeat(hb)).await?;
    match resp {
        FederationResponse::Ok(data) => println!("{}", serde_json::to_string_pretty(&data)?),
        FederationResponse::Error { message } => {
            eprintln!("error: {}", message);
            std::process::exit(1);
        }
    }
    Ok(())
}

async fn cmd_audit_chain(endpoint: &str) -> Result<()> {
    let resp: FederationResponse =
        ikrl_transport::rpc(endpoint, &FederationRequest::AuditChain).await?;
    match resp {
        FederationResponse::Ok(data) => {
            let entries: Vec<serde_json::Value> = serde_json::from_value(data)?;
            println!("audit chain length: {}", entries.len());
            for e in &entries {
                println!(
                    "  seq={} ts={} syscall={} result={}",
                    e["seq"].as_u64().unwrap_or(0),
                    e["timestamp_ms"].as_u64().unwrap_or(0),
                    e["syscall"].as_str().unwrap_or("-"),
                    e["result"].as_str().unwrap_or("-"),
                );
            }
        }
        FederationResponse::Error { message } => {
            eprintln!("error: {}", message);
            std::process::exit(1);
        }
    }
    Ok(())
}

// ─── Entry point ────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match &cli.command {
        Command::Status => cmd_status(&cli.endpoint).await?,
        Command::Peers => cmd_peers(&cli.endpoint).await?,
        Command::Join { addr } => cmd_join(&cli.endpoint, addr).await?,
        Command::Heartbeat => cmd_heartbeat(&cli.endpoint).await?,
        Command::AuditChain => cmd_audit_chain(&cli.endpoint).await?,
    }
    Ok(())
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn chrono_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use intentos_kernel::{FederationCluster, FederationRole};

    #[test]
    fn build_hello_roundtrip() {
        let node = FederationCluster::new(
            FederationRole::Peer,
            vec!["file:read".into()],
        );
        let hello = node.build_hello();
        let json = serde_json::to_string(&hello).unwrap();
        let decoded: HelloMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.kernel_id, hello.kernel_id);
        assert_eq!(decoded.version, hello.version);
    }

    #[test]
    fn federation_request_serialises() {
        let req = FederationRequest::Status;
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains("Status"));
    }

    #[test]
    fn join_request_carries_hello() {
        let node = FederationCluster::new(FederationRole::Worker, vec![]);
        let hello = node.build_hello();
        let req = FederationRequest::Join(hello.clone());
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains(&hello.kernel_id.to_string()));
    }
}
