//! # intentos-hal — Hardware Abstraction Layer
//!
//! Trait-based HAL for cross-platform IntentOS deployment. Detects host CPU
//! architecture and OS, then exposes a uniform platform descriptor for the
//! kernel boot path and enterprise sector plugins.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// CPU architecture detected at boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CpuArch {
    X86_64,
    Aarch64,
    Unknown,
}

/// Host operating system family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostOs {
    Linux,
    Windows,
    Unknown,
}

/// Platform snapshot returned by [`HardwareAbstraction::probe`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformInfo {
    pub arch: CpuArch,
    pub os: HostOs,
    pub hostname: String,
    pub logical_cpus: u32,
    pub backend: &'static str,
}

/// Hardware abstraction — probe host and report platform capabilities.
pub trait HardwareAbstraction: Send + Sync {
    fn probe(&self) -> PlatformInfo;
    fn backend_name(&self) -> &'static str;
}

/// Linux host backend.
pub struct LinuxHal;

impl HardwareAbstraction for LinuxHal {
    fn probe(&self) -> PlatformInfo {
        PlatformInfo {
            arch: detect_arch(),
            os: HostOs::Linux,
            hostname: read_hostname(),
            logical_cpus: detect_cpus(),
            backend: self.backend_name(),
        }
    }

    fn backend_name(&self) -> &'static str {
        "linux-native"
    }
}

/// Windows host backend.
pub struct WindowsHal;

impl HardwareAbstraction for WindowsHal {
    fn probe(&self) -> PlatformInfo {
        PlatformInfo {
            arch: detect_arch(),
            os: HostOs::Windows,
            hostname: read_hostname(),
            logical_cpus: detect_cpus(),
            backend: self.backend_name(),
        }
    }

    fn backend_name(&self) -> &'static str {
        "win32-native"
    }
}

/// Select the native HAL for the compile target.
pub fn native_hal() -> Box<dyn HardwareAbstraction> {
    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxHal)
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(WindowsHal)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Box::new(GenericHal)
    }
}

/// Fallback HAL for unsupported host OS families.
pub struct GenericHal;

impl HardwareAbstraction for GenericHal {
    fn probe(&self) -> PlatformInfo {
        PlatformInfo {
            arch: detect_arch(),
            os: HostOs::Unknown,
            hostname: read_hostname(),
            logical_cpus: detect_cpus(),
            backend: self.backend_name(),
        }
    }

    fn backend_name(&self) -> &'static str {
        "generic"
    }
}

#[derive(Debug, Error)]
pub enum HalError {
    #[error("platform probe failed: {0}")]
    ProbeFailed(String),
}

fn detect_arch() -> CpuArch {
    #[cfg(target_arch = "x86_64")]
    {
        CpuArch::X86_64
    }
    #[cfg(target_arch = "aarch64")]
    {
        CpuArch::Aarch64
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        CpuArch::Unknown
    }
}

fn detect_cpus() -> u32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1)
}

fn read_hostname() -> String {
    #[cfg(target_os = "windows")]
    {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "intentos-host".into())
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("HOSTNAME")
            .or_else(|_| std::fs::read_to_string("/etc/hostname"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "intentos-host".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_hal_probes() {
        let hal = native_hal();
        let info = hal.probe();
        assert!(info.logical_cpus >= 1);
        assert!(!info.hostname.is_empty());
    }
}