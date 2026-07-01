//! IntentOS — single-binary ground-up AI capability OS.
//!
//! Component order:
//!   1. Utilities — vfs, ai, tools
//!   2. Shell     — interactive user session (tier 2)
//!   3. Kernel    — policy, tokens, enforcement

use anyhow::Result;
use clap::Parser;
use intentos_shell::{banner, Shell, TIER_KERNEL, TIER_SHELL, TIER_UTILITIES};
use intentos_utilities::OsRuntime;
use std::io::Read;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(name = "intentos")]
#[command(about = "IntentOS — utilities (1) + shell (2) + kernel (3)")]
struct Args {
    /// Run one command and exit (non-interactive).
    #[arg(short = 'c', long)]
    command: Option<String>,

    /// Run commands from a script file. Use `-` to read from stdin.
    #[arg(long)]
    script: Option<String>,
}

fn main() -> Result<()> {
    println!("{}", banner());

    let args = Args::parse();
    let runtime = Arc::new(OsRuntime::boot()?);

    println!(
        "  [{TIER_KERNEL}] kernel   online  recognizer={}",
        runtime.kernel().recognizer_name()
    );
    println!(
        "  [{TIER_UTILITIES}] utilities online  hal={} vfs=mounted audit=chain",
        runtime.platform.backend
    );
    println!(
        "  identity actor={} domain={} backend={:?}",
        runtime.boot_actor(),
        runtime.identity.domain(),
        runtime.identity.backend()
    );
    match &runtime.ip_discrambler {
        Some(bridge) => println!(
            "  ip-discrambler online  root={}",
            bridge.root().display()
        ),
        None => println!("  ip-discrambler offline (optional Python bridge)"),
    }
    println!("  [{TIER_SHELL}] shell    starting session — type `help`\n");

    let mut shell = Shell::open(Arc::clone(&runtime));

    if let Some(cmd) = args.command {
        shell.eval(&cmd)?;
    } else if let Some(path) = args.script {
        let script = if path == "-" {
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            buf
        } else {
            std::fs::read_to_string(path)?
        };
        shell.run_script(&script)?;
    } else {
        shell.run()?;
    }

    Ok(())
}