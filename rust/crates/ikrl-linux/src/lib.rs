//! # ikrl-linux
//!
//! Linux-specific IntentKernel enforcement layer.
//!
//! This crate provides two supervision mechanisms:
//!
//! 1. **`ptrace` supervisor** — attaches to a child process and intercepts
//!    syscalls before the kernel executes them, validating capability tokens
//!    via the eventscope daemon.
//! 2. **`seccomp-notify` supervisor** (scaffold) — a placeholder module in
//!    `seccomp_notify.rs` for the kernel's seccomp user-notification facility
//!    (Linux 5.0+) intended for lower-overhead mediation in production.
//!
//! Only builds on Linux; other platforms see a no-op stub.

#[cfg(target_os = "linux")]
mod seccomp_notify;

#[cfg(target_os = "linux")]
use anyhow::{Context, Result};
#[cfg(target_os = "linux")]
use nix::sys::ptrace;
#[cfg(target_os = "linux")]
use nix::sys::signal::Signal;
#[cfg(target_os = "linux")]
use nix::sys::wait::{waitpid, WaitStatus};
#[cfg(target_os = "linux")]
use nix::unistd::{fork, ForkResult, Pid};
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
#[cfg(target_os = "linux")]
use std::process::Command;
#[cfg(target_os = "linux")]
use tracing::{info, warn};

#[cfg(target_os = "linux")]
use ikrl_transport::Channel;

/// Syscall numbers for x86_64 Linux.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod syscalls {
    pub const SYS_OPEN: i64 = 2;
    pub const SYS_OPENAT: i64 = 257;
    pub const SYS_WRITE: i64 = 1;
    pub const SYS_CONNECT: i64 = 42;
    pub const SYS_SOCKET: i64 = 41;
    pub const SYS_EXECVE: i64 = 59;
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod syscalls {
    pub const SYS_OPENAT: i64 = 56;
    pub const SYS_WRITE: i64 = 64;
    pub const SYS_CONNECT: i64 = 203;
    pub const SYS_SOCKET: i64 = 198;
    pub const SYS_EXECVE: i64 = 221;
}

/// Spawn `program` under ptrace supervision and enforce capability tokens.
#[cfg(target_os = "linux")]
pub async fn supervise(program: &str, args: &[&str], eventscope_addr: &str) -> Result<()> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<SupervisorEvent>();

    let child_pid = unsafe {
        match fork().context("fork failed")? {
            ForkResult::Child => {
                // Trace me before exec.
                ptrace::traceme().expect("ptrace_traceme failed");
                let mut cmd = Command::new(program);
                cmd.args(args);
                let err = cmd.exec();
                eprintln!("exec failed: {}", err);
                std::process::exit(1);
            }
            ForkResult::Parent { child } => child,
        }
    };

    let pid = Pid::from_raw(child_pid.as_raw());
    info!("supervising pid {} ({} {:?})", child_pid, program, args);

    // Spawn a blocking thread for the ptrace loop.
    std::thread::spawn(move || {
        let _ = ptrace_loop(pid, tx);
    });

    while let Some(event) = rx.recv().await {
        match event {
            SupervisorEvent::SyscallEnter { nr, pid } => {
                let denied = should_deny(nr, pid, eventscope_addr).await;
                if denied {
                    warn!("denying syscall {} for pid {}", nr, pid);
                    inject_error(Pid::from_raw(pid)).ok();
                }
            }
            SupervisorEvent::Exited { pid, status } => {
                info!("pid {} exited with status {}", pid, status);
                break;
            }
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
enum SupervisorEvent {
    SyscallEnter { nr: i64, pid: i32 },
    Exited { pid: i32, status: i32 },
}

#[cfg(target_os = "linux")]
fn ptrace_loop(pid: Pid, tx: tokio::sync::mpsc::UnboundedSender<SupervisorEvent>) -> Result<()> {
    let mut status = waitpid(pid, None).context("first waitpid failed")?;
    ptrace::setoptions(pid, ptrace::Options::PTRACE_O_TRACESYSGOOD).context("setoptions failed")?;

    loop {
        match status {
            WaitStatus::Stopped(child, Signal::SIGTRAP) => {
                // Read registers to identify syscall.
                let regs = read_registers(child)?;
                let nr = regs.orig_rax as i64;
                let _ = tx.send(SupervisorEvent::SyscallEnter {
                    nr,
                    pid: child.as_raw(),
                });

                ptrace::syscall(child, None)?;
            }
            WaitStatus::PtraceSyscall(child) => {
                // Syscall exit; continue.
                ptrace::syscall(child, None)?;
            }
            WaitStatus::Exited(child, code) => {
                let _ = tx.send(SupervisorEvent::Exited {
                    pid: child.as_raw(),
                    status: code,
                });
                break;
            }
            WaitStatus::Signaled(child, sig, _) => {
                warn!("pid {} signaled {:?}", child, sig);
                break;
            }
            _ => {
                ptrace::syscall(pid, None)?;
            }
        }
        status = waitpid(pid, None).context("waitpid failed")?;
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn read_registers(pid: Pid) -> Result<libc::user_regs_struct> {
    let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::ptrace(libc::PTRACE_GETREGS, pid.as_raw(), 0, &mut regs as *mut _) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(regs)
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn read_registers(_pid: Pid) -> Result<libc::user_regs_struct> {
    anyhow::bail!("aarch64 register reading not yet implemented")
}

#[cfg(target_os = "linux")]
async fn should_deny(nr: i64, pid: i32, eventscope_addr: &str) -> bool {
    use syscalls::*;
    let sensitive = matches!(
        nr,
        SYS_OPEN | SYS_OPENAT | SYS_WRITE | SYS_CONNECT | SYS_SOCKET | SYS_EXECVE
    );
    if !sensitive {
        return false;
    }

    // Ask eventscope whether this pid has any capability.
    let req = serde_json::json!({
        "method": "SimulateIntercept",
        "params": { "pid": pid, "syscall": nr }
    });
    match Channel::connect(eventscope_addr).await {
        Ok(mut ch) => {
            if ch.send_json(&req).await.is_err() {
                return true; // fail closed
            }
            // If the response is Denied, block the syscall.
            match ch.recv_json::<serde_json::Value>().await {
                Ok(resp) => {
                    if resp.get("status").and_then(|s| s.as_str()) == Some("Denied") {
                        return true;
                    }
                    false
                }
                Err(_) => true, // fail closed
            }
        }
        Err(_) => true, // fail closed
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn inject_error(pid: Pid) -> Result<()> {
    let mut regs = read_registers(pid)?;
    regs.rax = -libc::EPERM as i64 as u64; // -1 in signed interpretation
    let ret = unsafe { libc::ptrace(libc::PTRACE_SETREGS, pid.as_raw(), 0, &regs as *const _) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn inject_error(_pid: Pid) -> Result<()> {
    anyhow::bail!("aarch64 error injection not yet implemented")
}

/// No-op stub on non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub async fn supervise(
    _program: &str,
    _args: &[&str],
    _eventscope_addr: &str,
) -> anyhow::Result<()> {
    anyhow::bail!("ikrl-linux supervisor requires Linux")
}
