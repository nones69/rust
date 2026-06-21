//! ikrl-init — IntentOS boot orchestrator.
//!
//! Boots the three-tier AI OS:
//!   1. **Kernel** (always) — capd, intentd, leasebroker, eventscope
//!   2. **Shell** (user-launched) — run `ikrl-shell` after boot
//!   3. **Utilities** (optional) — ikrl-ai, ikrl-fs, ikrl-federation, ikrl-bridge

use anyhow::{Context, Result};
use clap::Parser;
use intentkernel_os::{boot_banner, OsLayer, KERNEL, SHELL};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
#[command(name = "ikrl-init")]
#[command(about = "IntentOS boot — kernel + utilities")]
struct Args {
    #[arg(long, default_value = "tcp://127.0.0.1:9101")]
    capd_addr: String,

    #[arg(long, default_value = "tcp://127.0.0.1:9100")]
    intentd_addr: String,

    #[arg(long, default_value = "tcp://127.0.0.1:9102")]
    leasebroker_addr: String,

    #[arg(long, default_value = "tcp://127.0.0.1:9103")]
    eventscope_addr: String,

    #[arg(long)]
    /// Path to the IntentKernel binary directory (defaults to same dir as ikrl-init)
    bin_dir: Option<PathBuf>,

    #[arg(long, default_value = "tcp://127.0.0.1:9200")]
    ikrl_ai_addr: String,

    #[arg(long, default_value = "tcp://127.0.0.1:9400")]
    ikrl_fs_addr: String,

    #[arg(long, default_value = "tcp://127.0.0.1:9310")]
    federation_addr: String,

    #[arg(long, default_value = "tcp://127.0.0.1:9300")]
    bridge_addr: String,

    /// Boot utility tier: ikrl-ai, ikrl-fs, ikrl-federation, ikrl-bridge.
    #[arg(long, help = "Start all utility daemons (AI, FS, federation, bridge)")]
    with_utilities: bool,

    #[arg(long, help = "Start ikrl-ai only (alias for partial utilities)")]
    with_ai: bool,

    #[arg(long, help = "Start ikrl-bridge only (alias for partial utilities)")]
    with_bridge: bool,
}

struct Daemon {
    name: String,
    layer: OsLayer,
    child: Child,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let bin_dir = args
        .bin_dir
        .clone()
        .or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(PathBuf::from))
        })
        .context("could not determine binary directory")?;

    println!("{}", boot_banner());
    info!("binary directory: {}", bin_dir.display());

    #[cfg(windows)]
    let _job = match job_object::create_kill_on_close_job() {
        Ok(job) => {
            info!("Windows job object created with KILL_ON_JOB_CLOSE");
            Some(job)
        }
        Err(e) => {
            warn!(
                "could not create kill-on-close job object ({}); child cleanup may require manual taskkill",
                e
            );
            None
        }
    };

    let daemons = Arc::new(Mutex::new(Vec::<Daemon>::new()));

    // --- Tier 1: Kernel (always) ---
    info!("booting kernel tier");
    spawn_daemon(
        &daemons,
        &bin_dir,
        OsLayer::Kernel,
        "capd",
        &[format!("--listen={}", strip_prefix(&args.capd_addr))],
    )?;
    spawn_daemon(
        &daemons,
        &bin_dir,
        OsLayer::Kernel,
        "intentd",
        &[
            format!("--listen={}", strip_prefix(&args.intentd_addr)),
            format!("--capd-addr={}", strip_prefix(&args.capd_addr)),
        ],
    )?;
    spawn_daemon(
        &daemons,
        &bin_dir,
        OsLayer::Kernel,
        "leasebroker",
        &[format!("--listen={}", strip_prefix(&args.leasebroker_addr))],
    )?;
    spawn_daemon(
        &daemons,
        &bin_dir,
        OsLayer::Kernel,
        "eventscope",
        &[
            format!("--listen={}", strip_prefix(&args.eventscope_addr)),
            format!("--capd-addr={}", strip_prefix(&args.capd_addr)),
        ],
    )?;

    let start_ai = args.with_utilities || args.with_ai;
    let start_bridge = args.with_utilities || args.with_bridge;
    let start_fs = args.with_utilities;
    let start_federation = args.with_utilities;

    if start_ai || start_fs || start_bridge || start_federation {
        info!("booting utilities tier");
    }

    if start_ai {
        spawn_daemon(
            &daemons,
            &bin_dir,
            OsLayer::Utilities,
            "ikrl-ai",
            &[
                format!("--listen={}", strip_prefix(&args.ikrl_ai_addr)),
                format!(
                    "--eventscope-addr={}",
                    strip_prefix(&args.eventscope_addr)
                ),
            ],
        )?;
    }

    if start_fs {
        spawn_daemon(
            &daemons,
            &bin_dir,
            OsLayer::Utilities,
            "ikrl-fs",
            &[
                format!("--listen={}", strip_prefix(&args.ikrl_fs_addr)),
                format!(
                    "--eventscope-addr={}",
                    strip_prefix(&args.eventscope_addr)
                ),
            ],
        )?;
    }

    if start_federation {
        let listen = strip_prefix(&args.federation_addr);
        spawn_daemon(
            &daemons,
            &bin_dir,
            OsLayer::Utilities,
            "ikrl-federation",
            &[
                format!("--listen={listen}"),
                format!("--device-id=intentos-1"),
            ],
        )?;
    }

    if start_bridge {
        spawn_daemon(
            &daemons,
            &bin_dir,
            OsLayer::Utilities,
            "ikrl-bridge",
            &[format!("--listen={}", strip_prefix(&args.bridge_addr))],
        )?;
    }

    let shell_exe = bin_dir.join(exe_name(SHELL.binary));
    println!("\n  Kernel:     {} daemons running", KERNEL.len());
    println!(
        "  Utilities:  {} running",
        daemons.lock().unwrap().iter().filter(|d| d.layer == OsLayer::Utilities).count()
    );
    println!("  Shell:      launch interactive session:");
    println!("              {}\n", shell_exe.display());
    info!("IntentOS boot complete — press Ctrl-C to shut down");

    let monitor = Arc::clone(&daemons);
    let monitor_handle = tokio::task::spawn_blocking(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(5));
            let mut dead = Vec::new();
            {
                let mut d = monitor.lock().unwrap();
                for (i, daemon) in d.iter_mut().enumerate() {
                    match daemon.child.try_wait() {
                        Ok(Some(status)) => {
                            warn!("{} exited with {:?}", daemon.name, status);
                            dead.push(i);
                        }
                        Ok(None) => {}
                        Err(e) => {
                            error!("failed to poll {}: {}", daemon.name, e);
                            dead.push(i);
                        }
                    }
                }
                for &i in dead.iter().rev() {
                    d.remove(i);
                }
            }
            if !dead.is_empty() {
                error!("one or more daemons died; shutting down");
                break;
            }
        }
    });

    tokio::signal::ctrl_c().await?;
    info!("shutdown signal received");

    let mut d = daemons.lock().unwrap();
    for daemon in d.iter_mut() {
        info!("stopping {}", daemon.name);
        let _ = daemon.child.kill();
    }

    monitor_handle.abort();
    Ok(())
}

fn spawn_daemon(
    daemons: &Arc<Mutex<Vec<Daemon>>>,
    bin_dir: &PathBuf,
    layer: OsLayer,
    name: &str,
    args: &[String],
) -> Result<()> {
    let exe = bin_dir.join(exe_name(name));
    let mut cmd = Command::new(&exe);
    cmd.args(args)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    info!("[{}] spawning {}: {:?} {:?}", layer.label(), name, exe, args);
    let child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn {} from {}", name, exe.display()))?;

    daemons.lock().unwrap().push(Daemon {
        name: name.to_string(),
        layer,
        child,
    });
    Ok(())
}

fn exe_name(name: &str) -> String {
    if cfg!(windows) {
        format!("{}.exe", name)
    } else {
        name.to_string()
    }
}

fn strip_prefix(addr: &str) -> String {
    addr.strip_prefix("tcp://")
        .or_else(|| addr.strip_prefix("unix://"))
        .or_else(|| addr.strip_prefix("pipe://"))
        .unwrap_or(addr)
        .to_string()
}

#[cfg(windows)]
mod job_object {
    use anyhow::{Context, Result};
    use std::os::windows::io::AsRawHandle;
    use std::process::Child;
    use tracing::info;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::SECURITY_ATTRIBUTES;
    use windows::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
    };
    use windows::Win32::System::Threading::GetCurrentProcess;

    pub struct JobObject(HANDLE);

    impl Drop for JobObject {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    pub fn create_kill_on_close_job() -> Result<JobObject> {
        unsafe {
            let handle = CreateJobObjectW(Some(&SECURITY_ATTRIBUTES::default()), None)
                .context("CreateJobObjectW failed")?;

            let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            info.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;

            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
            .context("SetInformationJobObject failed")?;

            let current = GetCurrentProcess();
            AssignProcessToJobObject(handle, current)
                .context("AssignProcessToJobObject failed for current process")?;

            info!("Windows job object created with KILL_ON_JOB_CLOSE");
            Ok(JobObject(handle))
        }
    }

    #[allow(dead_code)]
    pub fn assign_child(job: &JobObject, child: &Child) {
        unsafe {
            let raw = HANDLE(child.as_raw_handle() as *mut _);
            if let Err(e) = AssignProcessToJobObject(job.0, raw) {
                tracing::warn!("failed to assign child process to job object: {}", e);
            }
        }
    }
}

#[cfg(not(windows))]
mod job_object {
    use anyhow::Result;

    pub struct JobObject;

    pub fn create_kill_on_close_job() -> Result<JobObject> {
        Ok(JobObject)
    }

    #[allow(dead_code)]
    pub fn assign_child(_job: &JobObject, _child: &std::process::Child) {}
}