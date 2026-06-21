//! Healthcare sector plugin scaffold — FHIR-shaped intent mapping (Phase 2).

use intentos_audit::{AuditEventKind, AuditLog};
use intentos_kernel::{Intent, TrustAnchor, wall_ms};
use std::collections::BTreeMap;

/// FHIR-oriented command → capability intent mapper (rule-based pilot).
pub struct HealthcareMapper;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClinicalMapping {
    pub fhir_resource: String,
    pub action: String,
    pub original: String,
}

impl HealthcareMapper {
    pub const SUPPORTED: &'static [&'static str] = &[
        "Patient.read",
        "Patient.list",
        "Observation.read",
        "Observation.list",
        "ImagingStudy.read",
        "DiagnosticReport.read",
        "MedicationRequest.list",
        "GET /Patient",
        "GET /Observation",
    ];

    pub fn map(cmd: &str) -> Option<ClinicalMapping> {
        let trimmed = cmd.trim();
        let lower = trimmed.to_lowercase();

        let (resource, action) = match lower.as_str() {
            "patient.read" | "get /patient" => ("patient", "read"),
            "patient.list" => ("patient", "list"),
            "observation.read" | "get /observation" => ("observation", "read"),
            "observation.list" => ("observation", "list"),
            "imagingstudy.read" => ("imaging", "read"),
            "diagnosticreport.read" => ("diagnostic", "read"),
            "medicationrequest.list" => ("medication", "list"),
            s if s.starts_with("get /patient/") => ("patient", "read"),
            s if s.starts_with("get /observation/") => ("observation", "read"),
            _ => return None,
        };

        Some(ClinicalMapping {
            fhir_resource: resource.into(),
            action: action.into(),
            original: trimmed.into(),
        })
    }

    pub fn to_intent(mapped: &ClinicalMapping, actor: &str) -> Intent {
        Intent {
            actor: actor.into(),
            resource: mapped.fhir_resource.clone(),
            action: mapped.action.clone(),
            anchor: TrustAnchor::UiEvent,
            timestamp_ms: wall_ms(),
            metadata: BTreeMap::from([
                ("sector".into(), "healthcare".into()),
                ("fhir".into(), mapped.original.clone()),
                ("hipaa_mode".into(), "stub".into()),
            ]),
        }
    }

    pub fn map_and_audit(cmd: &str, actor: &str, audit: &AuditLog) -> Option<Intent> {
        let mapped = Self::map(cmd)?;
        let _ = audit.record(
            AuditEventKind::SectorMap,
            actor,
            format!(
                "healthcare `{}` -> {}/{}",
                mapped.original, mapped.fhir_resource, mapped.action
            ),
        );
        Some(Self::to_intent(&mapped, actor))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_patient_read() {
        let m = HealthcareMapper::map("Patient.read").unwrap();
        assert_eq!(m.fhir_resource, "patient");
        assert_eq!(m.action, "read");
    }
}