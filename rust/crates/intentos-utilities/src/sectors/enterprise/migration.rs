//! Enterprise migration assessment — Phase 2 pilot tooling.
//!
//! Scores host readiness for Intent Kernel deployment using HAL probe data
//! and implemented compatibility modules (no live Win32/AD inventory yet).

use intentos_hal::{CpuArch, HostOs, PlatformInfo};
use serde::{Deserialize, Serialize};

/// Result of a pre-migration host assessment (assess stage of modernization).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationReport {
    pub sector: String,
    pub hostname: String,
    pub host_os: String,
    pub arch: String,
    pub logical_cpus: u32,
    pub readiness_score: u8,
    pub pilot_ready: bool,
    pub capabilities_ready: Vec<String>,
    pub blockers: Vec<String>,
    pub recommended_approach: String,
    pub estimated_weeks: u8,
}

/// Assess enterprise migration readiness from platform probe + code maturity.
pub struct MigrationAssessor;

impl MigrationAssessor {
    pub fn assess(platform: &PlatformInfo) -> MigrationReport {
        let mut capabilities = vec![
            "intentos-hal host probe".into(),
            "PowerShell/Bash/CMD command mapper".into(),
            "hash-chained audit log".into(),
            "capability-gated kernel flow".into(),
            "AD/LDAP identity stub (INTENTOS_IDENTITY_*)".into(),
            "live LDAP via ldap3 when INTENTOS_LDAP_URL set".into(),
            "application compatibility matrix (enterprise compat)".into(),
            "optional Ollama recognizer (INTENTOS_OLLAMA_*)".into(),
        ];

        let mut blockers = Vec::new();
        let mut score: u16 = 40;

        match platform.os {
            HostOs::Windows => {
                score += 25;
                capabilities.push("win32-native HAL backend".into());
            }
            HostOs::Linux => {
                score += 25;
                capabilities.push("linux-native HAL backend".into());
            }
            HostOs::Unknown => {
                blockers.push("unsupported host OS family for enterprise pilot".into());
            }
        }

        match platform.arch {
            CpuArch::X86_64 | CpuArch::Aarch64 => score += 15,
            CpuArch::Unknown => blockers.push("unknown CPU architecture".into()),
        }

        if platform.logical_cpus >= 4 {
            score += 5;
        }

        // Not yet implemented — honest blockers for production migration.
        blockers.extend(
            [
                "Win32/Win64 API compatibility layer not shipped",
                "production AD GPO / Kerberos SSO not shipped (LDAP lookup only)",
                "in-place OS upgrade orchestrator not shipped",
                "application compatibility automation not shipped",
            ]
            .into_iter()
            .map(String::from),
        );

        let (approach, weeks) = match platform.os {
            HostOs::Windows => (
                "Phase 2 pilot: intentos sidecar + EnterpriseMapper on Win10/11/SERVER; \
                 legacy XP/7 via virtualization wrapper",
                4_u8,
            ),
            HostOs::Linux => (
                "Phase 2 pilot: package-bridge path on Ubuntu/Debian; RHEL via translator + clean install",
                5_u8,
            ),
            HostOs::Unknown => ("halt: resolve host OS before migration scoping", 0_u8),
        };

        let readiness_score = score.min(100) as u8;
        let pilot_ready = readiness_score >= 55 && platform.os != HostOs::Unknown;

        MigrationReport {
            sector: "enterprise".into(),
            hostname: platform.hostname.clone(),
            host_os: format!("{:?}", platform.os),
            arch: format!("{:?}", platform.arch),
            logical_cpus: platform.logical_cpus,
            readiness_score,
            pilot_ready,
            capabilities_ready: capabilities,
            blockers,
            recommended_approach: approach.into(),
            estimated_weeks: weeks,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use intentos_hal::native_hal;

    #[test]
    fn assess_returns_report_for_native_host() {
        let platform = native_hal().probe();
        let report = MigrationAssessor::assess(&platform);
        assert!(report.readiness_score > 0);
        assert!(!report.capabilities_ready.is_empty());
        assert!(!report.blockers.is_empty());
    }
}