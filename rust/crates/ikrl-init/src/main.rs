//! ikrl-init — IntentKernel init / orchestrator.
//!
//! Starts the four core daemons and any platform-specific enforcers, then
//! monitors their health. This is the single command a user runs to boot the
//! IntentKernel user-space OS on any host.

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
#[command(name = "ikrl-init")]
#[command(about = "IntentKernel user-space init / orchestrator")]
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

    #[arg(long, default_value = "tcp://127.0.0.1:9300")]
    bridge_addr: String,

    #[arg(long, help = "Also start ikrl-ai gateway")]
    with_ai: bool,

    #[arg(long, help = "Also start ikrl-bridge for CRASS OS")]
    with_bridge: bool,
}

struct Daemon {
    name: String,
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

    info!("starting IntentKernel user-space OS");
    info!("binary directory: {}", bin_dir.display());

    #[cfg(windows)]
    let _job = match job_object::create_kill_on_close_job() {
        Ok(job) => {
            info!("Windows job object created with KILL_ON_JOB_CLOSE");
            Some(job)
        }
        Err(e) => {
            warn!("could not create kill-on-close job object ({}); child cleanup may require manual taskkill", e);
            None
        }
    };

    let daemons = Arc::new(Mutex::new(Vec::<Daemon>::new()));

    // Start core daemons in dependency order.
    spawn_daemon(
        &daemons,
        &bin_dir,
        "capd",
        &[format!("--listen={}", strip_prefix(&args.capd_addr))],
    )?;
    spawn_daemon(
        &daemons,
        &bin_dir,
        "intentd",
        &[
            format!("--listen={}", strip_prefix(&args.intentd_addr)),
            format!("--capd-addr={}", strip_prefix(&args.capd_addr)),
        ],
    )?;
    spawn_daemon(
        &daemons,
        &bin_dir,
        "leasebroker",
        &[format!("--listen={}", strip_prefix(&args.leasebroker_addr))],
    )?;
    spawn_daemon(
        &daemons,
        &bin_dir,
        "eventscope",
        &[
            format!("--listen={}", strip_prefix(&args.eventscope_addr)),
            format!("--capd-addr={}", strip_prefix(&args.capd_addr)),
        ],
    )?;

    if args.with_ai {
        spawn_daemon(
            &daemons,
            &bin_dir,
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

    if args.with_bridge {
        spawn_daemon(
            &daemons,
            &bin_dir,
            "ikrl-bridge",
            &[format!("--listen={}", strip_prefix(&args.bridge_addr))],
        )?;
    }

    info!("all daemons started");

    // Health monitor loop.
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
                // Remove dead daemons (reverse order to keep indices valid).
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

    // Wait for Ctrl-C.
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
    name: &str,
    args: &[String],
) -> Result<()> {
    let exe = bin_dir.join(exe_name(name));
    let mut cmd = Command::new(&exe);
    cmd.args(args)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    info!("spawning {}: {:?} {:?}", name, exe, args);
    let child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn {} from {}", name, exe.display()))?;

    daemons.lock().unwrap().push(Daemon {
        name: name.to_string(),
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
    use tracing::{info, warn};
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

    /// Create a Windows Job Object that kills all child processes when the
    /// job handle is closed (i.e., when ikrl-init exits).
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

    /// Assign a spawned child process to the job object.
    #[allow(dead_code)]
    pub fn assign_child(job: &JobObject, child: &Child) {
        unsafe {
            let raw = HANDLE(child.as_raw_handle() as *mut _);
            if let Err(e) = AssignProcessToJobObject(job.0, raw) {
                warn!("failed to assign child process to job object: {}", e);
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

    pub fn assign_child(_job: &JobObject, _child: &std::process::Child) {}
}
