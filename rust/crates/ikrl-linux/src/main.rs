//! ikrl-linux — Linux ptrace/syscall supervisor binary.

use clap::Parser;
#[cfg(target_os = "linux")]
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "ikrl-linux")]
#[command(about = "IntentKernel Linux syscall supervisor")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:9103")]
    eventscope_addr: String,

    #[arg(required = true)]
    program: Vec<String>,
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    if args.program.is_empty() {
        anyhow::bail!("program to supervise is required");
    }
    let program = args.program[0].clone();
    let prog_args: Vec<&str> = args.program[1..].iter().map(|s| s.as_str()).collect();
    info!("starting Linux supervisor for {}", program);
    ikrl_linux::supervise(&program, &prog_args, &args.eventscope_addr).await
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("ikrl-linux is only supported on Linux");
    std::process::exit(1);
}
