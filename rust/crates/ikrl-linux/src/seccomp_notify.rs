//! Seccomp user-notification supervisor scaffold.
//!
//! This module is a **design placeholder** for the production Linux
//! enforcement path described in the thesis proposal. It will eventually
//! replace the higher-overhead `ptrace` loop with a `seccomp` filter that
//! forwards sensitive syscalls to a user-space supervisor over a file
//! descriptor (`SECCOMP_IOCTL_NOTIF_RECV`).
//!
//! Benefits:
//! - Lower latency: no per-syscall stop/resume via ptrace.
//! - Simpler threading: a single async task can handle notifications.
//! - Easier to audit: the filter is declarative, the policy is in Rust.
//!
//! What is needed to complete this module:
//! 1. Link or vendor `libseccomp` to install the filter.
//! 2. Implement `seccomp_notify_addfd` and response messages.
//! 3. Map file-descriptor arguments to capability token handles.

#[cfg(target_os = "linux")]
use anyhow::Result;

/// Install a seccomp filter that traps file and network syscalls.
#[cfg(target_os = "linux")]
pub fn install_filter() -> Result<()> {
    // Placeholder: real implementation requires libseccomp.
    tracing::info!("seccomp-notify filter installation is not yet implemented");
    Ok(())
}

/// Run the notification loop for a seccomp supervisor.
#[cfg(target_os = "linux")]
pub async fn run_supervisor(_notify_fd: std::os::fd::RawFd) -> Result<()> {
    // Placeholder: real implementation uses SECCOMP_IOCTL_NOTIF_RECV.
    tracing::info!("seccomp-notify supervisor loop is not yet implemented");
    Ok(())
}
