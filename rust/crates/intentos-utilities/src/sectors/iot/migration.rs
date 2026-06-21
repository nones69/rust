//! IoT/embedded pilot readiness assessment (IEC 62443-oriented blockers).

use intentos_hal::{CpuArch, PlatformInfo};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IotPilotReport {
    pub sector: String,
    pub pilot_ready: bool,
    pub readiness_score: u8,
    pub capabilities_ready: Vec<String>,
    pub blockers: Vec<String>,
    pub compliance_targets: Vec<String>,
    pub hal_arch: String,
}

pub struct IotAssessor;

impl IotAssessor {
    pub fn assess(platform: &PlatformInfo) -> IotPilotReport {
        let arch_note = match platform.arch {
            CpuArch::Aarch64 => "ARM64 target detected — embedded path viable",
            CpuArch::X86_64 => "x86_64 host — use cross-compile for Cortex-M fleet",
            CpuArch::Unknown => "unknown arch — HAL probe incomplete",
        };

        IotPilotReport {
            sector: "iot".into(),
            pilot_ready: false,
            readiness_score: 22,
            capabilities_ready: vec![
                "OTA/secure-boot-shaped intent mapper (stub)".into(),
                format!("HAL probe: {arch_note}"),
                "kernel audit chain (prototype)".into(),
            ],
            blockers: vec![
                "Secure boot chain verification not shipped".into(),
                "Signed OTA delta/rollback pipeline not shipped".into(),
                "FreeRTOS/Zephyr RTOS bridge not shipped".into(),
                "Device X.509 identity provisioning not shipped".into(),
                "IEC 62443 compliance test harness not shipped".into(),
                "SBOM / firmware attestation workflow not shipped".into(),
            ],
            compliance_targets: vec![
                "IEC 62443".into(),
                "ISO 27001".into(),
                "EU Cyber Resilience Act".into(),
            ],
            hal_arch: format!("{:?}", platform.arch),
        }
    }
}