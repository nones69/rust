//! ikrl-bench — Benchmark harness for the IntentKernel daemon stack.
//!
//! Measures token issuance, verification, registration, and capability-table
//! throughput. Designed for the empirical validation framework described in
//! `docs/thesis_proposal.md`.

use anyhow::{Context, Result};
use clap::Parser;
use ikrl_transport::rpc;
use intentkernel_core::{CapabilityTable, CapabilityToken, TrustAnchor};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "ikrl-bench")]
#[command(about = "IntentKernel benchmark harness")]
struct Args {
    /// Capability engine address.
    #[arg(long, default_value = "tcp://127.0.0.1:9101")]
    capd_addr: String,

    /// Intent broker address.
    #[arg(long, default_value = "tcp://127.0.0.1:9100")]
    intentd_addr: String,

    /// Spawn the daemons internally.
    #[arg(long)]
    spawn_daemons: bool,

    /// Number of iterations per benchmark.
    #[arg(long, default_value = "1000")]
    iterations: usize,

    /// Concurrency for batch benchmarks.
    #[arg(long, default_value = "50")]
    concurrency: usize,
}

struct DaemonGuard {
    #[allow(dead_code)]
    name: &'static str,
    child: Child,
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let _guards = if args.spawn_daemons {
        Some(spawn_daemons(&args.capd_addr, &args.intentd_addr).await?)
    } else {
        None
    };

    wait_for_daemons(&args.capd_addr, &args.intentd_addr).await?;

    info!("starting benchmarks (iterations={})", args.iterations);

    let capd_latencies = bench_capd_issue(&args.capd_addr, args.iterations).await?;
    report("capd IssueToken", &capd_latencies.latencies);

    let intent_latencies = bench_intent_issue(&args.intentd_addr, args.iterations).await?;
    report("intentd SubmitIntent", &intent_latencies.latencies);

    let verify_latencies = bench_verify(&args.capd_addr, &capd_latencies.tokens).await?;
    report("capd VerifyToken", &verify_latencies);

    let core_latencies = bench_core_table(args.iterations);
    report("core capability table", &core_latencies);

    Ok(())
}

async fn spawn_daemons(capd_addr: &str, intentd_addr: &str) -> Result<Vec<DaemonGuard>> {
    let capd_port = addr_port(capd_addr)?;
    let intentd_port = addr_port(intentd_addr)?;
    let mut guards = Vec::new();

    let mut capd_cmd = Command::new("capd");
    capd_cmd.arg(format!("--listen=127.0.0.1:{}", capd_port));
    capd_cmd.stdout(Stdio::null()).stderr(Stdio::inherit());
    guards.push(DaemonGuard {
        name: "capd",
        child: capd_cmd.spawn().context("failed to spawn capd")?,
    });

    let mut intentd_cmd = Command::new("intentd");
    intentd_cmd
        .arg(format!("--listen=127.0.0.1:{}", intentd_port))
        .arg(format!("--capd-addr=127.0.0.1:{}", capd_port));
    intentd_cmd.stdout(Stdio::null()).stderr(Stdio::inherit());
    guards.push(DaemonGuard {
        name: "intentd",
        child: intentd_cmd.spawn().context("failed to spawn intentd")?,
    });

    tokio::time::sleep(Duration::from_millis(500)).await;
    Ok(guards)
}

async fn wait_for_daemons(capd_addr: &str, intentd_addr: &str) -> Result<()> {
    for _ in 0..50 {
        let mut ok = true;
        if rpc::<serde_json::Value, serde_json::Value>(
            capd_addr,
            &serde_json::json!({"method": "GetPublicKey"}),
        )
        .await
        .is_err()
        {
            ok = false;
        }
        if rpc::<serde_json::Value, serde_json::Value>(
            intentd_addr,
            &serde_json::json!({
                "method": "GetPolicy",
                "params": {
                    "actor_id": "bench",
                    "action": "read",
                    "resource": "file",
                    "anchor": "UiEvent",
                    "timestamp_ms": 0
                }
            }),
        )
        .await
        .is_err()
        {
            ok = false;
        }
        if ok {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    anyhow::bail!("daemons did not become ready in time")
}

fn addr_port(addr: &str) -> Result<u16> {
    let stripped = addr.strip_prefix("tcp://").unwrap_or(addr);
    stripped
        .split(':')
        .last()
        .and_then(|s| s.parse().ok())
        .context("invalid address")
}

struct IssueResult {
    latencies: Vec<Duration>,
    tokens: Vec<Vec<u8>>,
}

async fn bench_capd_issue(capd_addr: &str, iterations: usize) -> Result<IssueResult> {
    let mut latencies = Vec::with_capacity(iterations);
    let mut tokens = Vec::with_capacity(iterations);

    for i in 0..iterations {
        let start = Instant::now();
        let req = serde_json::json!({
            "method": "IssueToken",
            "params": {
                "iss": "broker-bench",
                "sub": "bench",
                "ctx": vec![0u8; 48],
                "resource": "file",
                "action": "read",
                "constraints": {},
                "exp": u64::MAX,
                "nbf": 0u64,
                "uses": 1,
                "anchor": "UiEvent",
                "typ": "Capability"
            }
        });
        let resp: serde_json::Value = rpc(capd_addr, &req).await?;
        let cbor: Vec<u8> = resp["data"]["token_cbor"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap_or(0) as u8)
            .collect();
        latencies.push(start.elapsed());
        tokens.push(cbor);
        if i % 100 == 0 {
            info!("capd issue iteration {}", i);
        }
    }
    Ok(IssueResult { latencies, tokens })
}

async fn bench_intent_issue(intentd_addr: &str, iterations: usize) -> Result<IssueResult> {
    let mut latencies = Vec::with_capacity(iterations);
    let mut tokens = Vec::with_capacity(iterations);

    for i in 0..iterations {
        let start = Instant::now();
        let req = serde_json::json!({
            "method": "SubmitIntent",
            "params": {
                "actor_id": "bench",
                "action": "read",
                "resource": "file",
                "anchor": "UiEvent",
                "timestamp_ms": intentkernel_core::wall_epoch_ms()
            }
        });
        let resp: serde_json::Value = rpc(intentd_addr, &req).await?;
        let cbor: Vec<u8> = resp["data"]["token_cbor"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap_or(0) as u8)
            .collect();
        latencies.push(start.elapsed());
        tokens.push(cbor);
        if i % 100 == 0 {
            info!("intent issue iteration {}", i);
        }
    }
    Ok(IssueResult { latencies, tokens })
}

async fn bench_verify(capd_addr: &str, tokens: &[Vec<u8>]) -> Result<Vec<Duration>> {
    let mut latencies = Vec::with_capacity(tokens.len());
    for (i, cbor) in tokens.iter().enumerate() {
        let start = Instant::now();
        let req = serde_json::json!({
            "method": "VerifyToken",
            "params": {"token_cbor": cbor}
        });
        rpc::<serde_json::Value, serde_json::Value>(capd_addr, &req).await?;
        latencies.push(start.elapsed());
        if i % 100 == 0 {
            info!("verify iteration {}", i);
        }
    }
    Ok(latencies)
}

fn bench_core_table(iterations: usize) -> Vec<Duration> {
    use intentkernel_crypto as crypto;

    let table = CapabilityTable::new();
    let kp = crypto::ml_dsa87_keygen().expect("keygen");
    table.set_broker_key(kp.public_key);

    let mut token_template = CapabilityToken {
        ver: 1,
        typ: intentkernel_core::TokenType::Capability,
        alg: 1,
        anchor: TrustAnchor::UiEvent,
        iss: "bench".into(),
        sub: "bench".into(),
        ctx: vec![0u8; 48],
        scope: intentkernel_core::CapabilityScope::new("file", "read"),
        exp: u64::MAX,
        nbf: 0,
        uses: 1,
        state: intentkernel_core::LeaseState::Granted,
        jti: "bench-jti".into(),
        signature: Vec::new(),
    };
    let mut sign = token_template.clone();
    sign.signature.clear();
    let cbor = intentkernel_core::token_to_cbor(&sign).unwrap();
    let sig = crypto::ml_dsa87_sign(&kp.secret_key, &cbor).unwrap();
    token_template.signature = sig.to_vec();

    let mut latencies = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        let _ = table.register_full_token(&token_template);
        latencies.push(start.elapsed());
    }
    latencies
}

fn report(name: &str, latencies: &[Duration]) {
    if latencies.is_empty() {
        return;
    }
    let ns: Vec<u128> = latencies.iter().map(|d| d.as_nanos()).collect();
    let sum: u128 = ns.iter().sum();
    let mean = sum / ns.len() as u128;
    let mut sorted = ns.clone();
    sorted.sort_unstable();
    let p50 = sorted[sorted.len() / 2];
    let p95 = sorted[((sorted.len() as f64 * 0.95) as usize).min(sorted.len() - 1)];
    let p99 = sorted[((sorted.len() as f64 * 0.99) as usize).min(sorted.len() - 1)];
    let min = sorted[0];
    let max = sorted[sorted.len() - 1];

    info!(
        "{}: mean={}ns p50={}ns p95={}ns p99={}ns min={}ns max={}ns samples={}",
        name,
        mean,
        p50,
        p95,
        p99,
        min,
        max,
        sorted.len()
    );
}
