//! Banking/ATM pilot readiness assessment (PCI-DSS-oriented blockers).

use intentos_hal::PlatformInfo;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BankingPilotReport {
    pub sector: String,
    pub pilot_ready: bool,
    pub readiness_score: u8,
    pub capabilities_ready: Vec<String>,
    pub blockers: Vec<String>,
    pub compliance_targets: Vec<String>,
}

pub struct BankingAssessor;

impl BankingAssessor {
    pub fn assess(_platform: &PlatformInfo) -> BankingPilotReport {
        BankingPilotReport {
            sector: "banking".into(),
            pilot_ready: false,
            readiness_score: 15,
            capabilities_ready: vec![
                "PCI/EMV-shaped intent mapper (stub)".into(),
                "kernel audit chain (prototype)".into(),
            ],
            blockers: vec![
                "HSM / TPM key ceremony module not shipped".into(),
                "EMV/PCI live transaction processing not shipped".into(),
                "ATM vendor SDK bridge (Diebold/NCR) not shipped".into(),
                "Fraud detection ML engine not shipped".into(),
                "PCI-DSS v4.0 compliance test harness not shipped".into(),
                "Legacy OS/2 ATM virtualization wrapper not shipped".into(),
            ],
            compliance_targets: vec![
                "PCI-DSS".into(),
                "FIPS 140-2/3".into(),
                "SOC 2 Type II".into(),
            ],
        }
    }
}