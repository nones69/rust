//! Healthcare pilot readiness assessment (HIPAA-oriented blockers).

use intentos_audit::AuditLog;
use intentos_hal::PlatformInfo;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthcarePilotReport {
    pub sector: String,
    pub pilot_ready: bool,
    pub readiness_score: u8,
    pub capabilities_ready: Vec<String>,
    pub blockers: Vec<String>,
    pub compliance_targets: Vec<String>,
    pub audit_chain_ok: Option<bool>,
}

pub struct HealthcareAssessor;

impl HealthcareAssessor {
    pub fn assess(platform: &PlatformInfo) -> HealthcarePilotReport {
        Self::assess_with_audit(platform, None)
    }

    pub fn assess_with_audit(
        platform: &PlatformInfo,
        audit: Option<&AuditLog>,
    ) -> HealthcarePilotReport {
        let mut score: u16 = 30;
        let mut capabilities = vec![
            "FHIR-shaped intent mapper (Patient/Observation/Imaging)".into(),
            "shell healthcare list | assess | <op>".into(),
            "kernel audit chain (prototype)".into(),
        ];

        let blockers = vec![
            "HSM / patient data encryption module not shipped".into(),
            "DICOM/PACS integration not shipped".into(),
            "federated learning node not shipped".into(),
            "HIPAA compliance test harness not shipped".into(),
            "FDA 510(k) pathway not started".into(),
        ];

        if platform.logical_cpus >= 2 {
            score += 5;
        }

        let audit_chain_ok = audit.map(|log| log.verify_chain().unwrap_or(false));
        if audit_chain_ok == Some(true) {
            score += 15;
            capabilities.push("verified audit hash chain".into());
        }

        HealthcarePilotReport {
            sector: "healthcare".into(),
            pilot_ready: false,
            readiness_score: score.min(100) as u8,
            capabilities_ready: capabilities,
            blockers,
            compliance_targets: vec![
                "HIPAA".into(),
                "GDPR".into(),
                "EU AI Act (high-risk clinical)".into(),
            ],
            audit_chain_ok,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use intentos_audit::AuditEventKind;
    use intentos_hal::native_hal;

    #[test]
    fn assess_with_verified_audit_boosts_score() {
        let audit = AuditLog::new();
        let _ = audit.record(AuditEventKind::Boot, "hc", "test");
        let platform = native_hal().probe();
        let report = HealthcareAssessor::assess_with_audit(&platform, Some(&audit));
        assert_eq!(report.audit_chain_ok, Some(true));
        assert!(report.readiness_score >= 45);
    }
}