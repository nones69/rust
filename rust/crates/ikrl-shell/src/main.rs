//! ikrl-shell — IntentOS interactive shell (tier 2).
//!
//! The shell is the primary user session. It translates typed commands into
//! capability-gated kernel RPCs and utility calls.
//!
//! ```text
//! intentos> status
//! intentos> intent file read --actor myapp
//! intentos> ai infer "summarize logs" --model llama3
//! intentos> fs list .
//! ```

use anyhow::{Context, Result};
use clap::Parser;
use ikrl_transport::rpc;
use intentkernel_core::{wall_epoch_ms, CapabilityToken, IntentEvent, TrustAnchor};
use intentkernel_os::{boot_banner, OsEndpoints, KERNEL, SHELL, UTILITIES};
use serde_json::json;
use std::io::{self, Write};

#[derive(Parser, Debug)]
#[command(name = "ikrl-shell")]
#[command(about = "IntentOS interactive shell")]
struct Args {
    #[command(flatten)]
    endpoints: EndpointArgs,
}

#[derive(Parser, Debug)]
struct EndpointArgs {
    #[arg(long, default_value = "tcp://127.0.0.1:9100")]
    intentd: String,
    #[arg(long, default_value = "tcp://127.0.0.1:9101")]
    capd: String,
    #[arg(long, default_value = "tcp://127.0.0.1:9102")]
    leasebroker: String,
    #[arg(long, default_value = "tcp://127.0.0.1:9103")]
    eventscope: String,
    #[arg(long, default_value = "tcp://127.0.0.1:9200")]
    ikrl_ai: String,
    #[arg(long, default_value = "tcp://127.0.0.1:9400")]
    ikrl_fs: String,
}

struct ShellState {
    endpoints: OsEndpoints,
    actor: String,
    last_token_hex: Option<String>,
    last_handle: Option<u64>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    println!("{}", boot_banner());
    println!("  Shell tier: {} — type `help` for commands\n", SHELL.binary);

    let mut state = ShellState {
        endpoints: OsEndpoints {
            intentd: args.endpoints.intentd,
            capd: args.endpoints.capd,
            leasebroker: args.endpoints.leasebroker,
            eventscope: args.endpoints.eventscope,
            ikrl_ai: args.endpoints.ikrl_ai,
            ikrl_fs: args.endpoints.ikrl_fs,
            ..OsEndpoints::default()
        },
        actor: "intentos-user".into(),
        last_token_hex: None,
        last_handle: None,
    };

    let stdin = io::stdin();
    loop {
        print!("intentos> ");
        io::stdout().flush()?;

        let mut line = String::new();
        if stdin.read_line(&mut line)? == 0 {
            break;
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        match run_command(line, &mut state).await {
            Ok(continue_loop) => {
                if !continue_loop {
                    println!("logout");
                    break;
                }
            }
            Err(e) => eprintln!("error: {:#}", e),
        }
    }

    Ok(())
}

async fn run_command(line: &str, state: &mut ShellState) -> Result<bool> {
    let mut parts = line.split_whitespace().collect::<Vec<_>>();
    let cmd = parts.remove(0);

    match cmd {
        "help" | "?" => {
            print_help();
            Ok(true)
        }
        "exit" | "quit" | "logout" => Ok(false),
        "status" => {
            status(state).await?;
            Ok(true)
        }
        "layers" => {
            print_layers();
            Ok(true)
        }
        "intent" => {
            intent_cmd(&parts, state).await?;
            Ok(true)
        }
        "register" => {
            register_cmd(state).await?;
            Ok(true)
        }
        "syscall" => {
            syscall_cmd(&parts, state).await?;
            Ok(true)
        }
        "flow" => {
            flow_cmd(&parts, state).await?;
            Ok(true)
        }
        "ai" => {
            ai_cmd(&parts, state).await?;
            Ok(true)
        }
        "fs" => {
            fs_cmd(&parts, state).await?;
            Ok(true)
        }
        "lease" => {
            lease_cmd(&parts, state).await?;
            Ok(true)
        }
        "actor" => {
            if parts.is_empty() {
                println!("current actor: {}", state.actor);
            } else {
                state.actor = parts.join(" ");
                println!("actor set to {}", state.actor);
            }
            Ok(true)
        }
        _ => {
            eprintln!("unknown command: {cmd}. Type `help`.");
            Ok(true)
        }
    }
}

fn print_help() {
    println!(
        r#"
IntentOS shell commands:

  status              Ping kernel + utility daemons
  layers              Show the 3 OS tiers (kernel / shell / utilities)
  intent <res> <act>  Submit intent → receive capability token
  register            Register last token at eventscope → kernel handle
  syscall <name>      Invoke syscall with last handle
  flow <res> <act>    Full path: intent → verify → register
  ai infer <prompt>   Capability-gated AI inference (needs token)
  fs list <path>      List directory via ikrl-fs (needs token)
  lease list          List active leases
  actor [name]        Show or set actor id
  exit                End session
"#
    );
}

fn print_layers() {
    println!("\n=== 1. KERNEL ===");
    for c in KERNEL {
        println!("  {:<14} {}  {}", c.binary, c.default_listen, c.description);
    }
    println!("\n=== 2. SHELL ===");
    println!(
        "  {:<14} (this session)  {}",
        SHELL.binary, SHELL.description
    );
    println!("\n=== 3. UTILITIES ===");
    for c in UTILITIES {
        println!("  {:<14} {}  {}", c.binary, c.default_listen, c.description);
    }
    println!();
}

async fn status(state: &ShellState) -> Result<()> {
    println!("\n--- Kernel tier ---");
    ping("intentd", &state.endpoints.intentd).await;
    ping("capd", &state.endpoints.capd).await;
    ping("leasebroker", &state.endpoints.leasebroker).await;
    ping("eventscope", &state.endpoints.eventscope).await;

    println!("\n--- Utilities tier ---");
    ping("ikrl-ai", &state.endpoints.ikrl_ai).await;
    ping("ikrl-fs", &state.endpoints.ikrl_fs).await;

    println!("\n--- Shell tier ---");
    println!("  ikrl-shell     active  (pid {})", std::process::id());
    println!();
    Ok(())
}

async fn ping(name: &str, addr: &str) {
    let host = addr
        .strip_prefix("tcp://")
        .or_else(|| addr.strip_prefix("unix://"))
        .unwrap_or(addr);
    match tokio::net::TcpStream::connect(host).await {
        Ok(_) => println!("  {name:<14} up      {addr}"),
        Err(e) => println!("  {name:<14} down    {addr} ({e})"),
    }
}

async fn intent_cmd(parts: &[&str], state: &mut ShellState) -> Result<()> {
    let (resource, action) = parse_resource_action(parts)?;
    let event = IntentEvent {
        actor_id: state.actor.clone(),
        action: action.to_string(),
        resource: resource.to_string(),
        anchor: TrustAnchor::UiEvent,
        timestamp_ms: wall_epoch_ms(),
        metadata: Default::default(),
    };
    let req = json!({"method": "SubmitIntent", "params": event});
    let resp: serde_json::Value = rpc(&state.endpoints.intentd, &req).await?;
    if resp.get("status").and_then(|s| s.as_str()) == Some("Denied") {
        println!("denied: {}", resp["reason"].as_str().unwrap_or("policy"));
        return Ok(());
    }
    let token: CapabilityToken = serde_json::from_value(resp["data"].clone())
        .context("intentd did not return a token")?;
    let cbor = token.to_cbor()?;
    let hex_token = hex::encode(&cbor);
    state.last_token_hex = Some(hex_token.clone());
    println!("token issued  jti={} exp={}", token.jti, token.exp);
    println!("TOKEN_CBOR_HEX={hex_token}");
    Ok(())
}

async fn register_cmd(state: &mut ShellState) -> Result<()> {
    let hex_token = state
        .last_token_hex
        .as_ref()
        .context("no token — run `intent` first")?;
    let cbor = hex::decode(hex_token)?;
    let req = json!({"method": "RegisterToken", "params": {"token_cbor": cbor}});
    let resp: serde_json::Value = rpc(&state.endpoints.eventscope, &req).await?;
    if let Some(handle) = resp["data"]["handle"].as_u64() {
        state.last_handle = Some(handle);
        println!("registered  handle=0x{handle:X}");
    } else {
        println!("{}", serde_json::to_string_pretty(&resp)?);
    }
    Ok(())
}

async fn syscall_cmd(parts: &[&str], state: &mut ShellState) -> Result<()> {
    let syscall = parts.first().context("usage: syscall <name> [args...]")?;
    let handle = state
        .last_handle
        .context("no handle — run `flow` or `register` first")?;
    let args: Vec<&str> = parts.get(1..).unwrap_or(&[]).to_vec();
    let req = json!({
        "method": "Syscall",
        "params": {"handle": handle, "syscall": syscall, "args": args}
    });
    let resp: serde_json::Value = rpc(&state.endpoints.eventscope, &req).await?;
    println!("{}", serde_json::to_string_pretty(&resp)?);
    Ok(())
}

async fn flow_cmd(parts: &[&str], state: &mut ShellState) -> Result<()> {
    intent_cmd(parts, state).await?;
    let hex_token = state.last_token_hex.clone().unwrap();
    let cbor = hex::decode(&hex_token)?;

    let verify_req = json!({"method": "VerifyToken", "params": {"token_cbor": cbor.clone()}});
    let verify: serde_json::Value = rpc(&state.endpoints.capd, &verify_req).await?;
    println!("capd verify: {}", verify["status"].as_str().unwrap_or("?"));

    let register_req = json!({"method": "RegisterToken", "params": {"token_cbor": cbor}});
    let register: serde_json::Value = rpc(&state.endpoints.eventscope, &register_req).await?;
    if let Some(handle) = register["data"]["handle"].as_u64() {
        state.last_handle = Some(handle);
        println!("flow complete  handle=0x{handle:X}");
    } else {
        println!("{}", serde_json::to_string_pretty(&register)?);
    }
    Ok(())
}

async fn ai_cmd(parts: &[&str], state: &mut ShellState) -> Result<()> {
    if parts.first() != Some(&"infer") {
        anyhow::bail!("usage: ai infer <prompt> [--model NAME]");
    }
    let hex_token = state
        .last_token_hex
        .as_ref()
        .context("no token — run `intent ai infer ...` or `intent` first")?;
    let cbor = hex::decode(hex_token)?;

    let mut model = "llama3".to_string();
    let mut prompt_parts = Vec::new();
    let mut i = 1;
    while i < parts.len() {
        if parts[i] == "--model" {
            i += 1;
            model = parts.get(i).context("--model requires a value")?.to_string();
        } else {
            prompt_parts.push(parts[i]);
        }
        i += 1;
    }
    let prompt = prompt_parts.join(" ");
    if prompt.is_empty() {
        anyhow::bail!("usage: ai infer <prompt> [--model NAME]");
    }

    let req = json!({
        "method": "Infer",
        "params": {"model": model, "prompt": prompt, "token_cbor": cbor}
    });
    let resp: serde_json::Value = rpc(&state.endpoints.ikrl_ai, &req).await?;
    println!("{}", serde_json::to_string_pretty(&resp)?);
    Ok(())
}

async fn fs_cmd(parts: &[&str], state: &mut ShellState) -> Result<()> {
    let sub = parts.first().context("usage: fs list <path>")?;
    let hex_token = state
        .last_token_hex
        .as_ref()
        .context("no token — run `intent file read` first")?;
    let cbor = hex::decode(hex_token)?;

    let resp: serde_json::Value = match *sub {
        "list" => {
            let path = parts.get(1).copied().unwrap_or(".");
            let req = json!({
                "method": "List",
                "params": {"path": path, "token_cbor": cbor}
            });
            rpc(&state.endpoints.ikrl_fs, &req).await?
        }
        _ => anyhow::bail!("usage: fs list <path>"),
    };
    println!("{}", serde_json::to_string_pretty(&resp)?);
    Ok(())
}

async fn lease_cmd(parts: &[&str], state: &ShellState) -> Result<()> {
    match parts.first().copied().unwrap_or("list") {
        "list" => {
            let req = json!({"method": "ListLeases", "params": {}});
            let resp: serde_json::Value = rpc(&state.endpoints.leasebroker, &req).await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        other => anyhow::bail!("unknown lease subcommand: {other}"),
    }
    Ok(())
}

fn parse_resource_action<'a>(parts: &'a [&'a str]) -> Result<(&'a str, &'a str)> {
    if parts.len() < 2 {
        anyhow::bail!("usage: intent <resource> <action>");
    }
    Ok((parts[0], parts[1]))
}