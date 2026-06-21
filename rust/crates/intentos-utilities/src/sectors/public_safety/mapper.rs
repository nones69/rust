//! Public safety sector plugin scaffold — CAD/CJIS-shaped intent mapping (Phase 2).

use intentos_audit::{AuditEventKind, AuditLog};
use intentos_kernel::{Intent, TrustAnchor, wall_ms};
use std::collections::BTreeMap;

/// CAD / CJIS-oriented command → capability intent mapper (rule-based pilot).
pub struct PublicSafetyMapper;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissionMapping {
    pub domain: String,
    pub action: String,
    pub original: String,
}

impl PublicSafetyMapper {
    pub const SUPPORTED: &'static [&'static str] = &[
        "CAD.dispatch.create",
        "CAD.incident.read",
        "CAD.unit.assign",
        "NCIC.lookup",
        "NLETS.query",
        "Evidence.upload",
        "Evidence.chain.read",
        "GIS.map.center",
        "Radio.ptt.status",
        "POST /dispatch",
        "GET /incident",
    ];

    pub fn map(cmd: &str) -> Option<MissionMapping> {
        let trimmed = cmd.trim();
        let lower = trimmed.to_lowercase();

        let (domain, action) = match lower.as_str() {
            "cad.dispatch.create" | "post /dispatch" => ("dispatch", "create"),
            "cad.incident.read" | "get /incident" => ("incident", "read"),
            "cad.unit.assign" => ("unit", "assign"),
            "ncic.lookup" => ("ncic", "lookup"),
            "nlets.query" => ("nlets", "query"),
            "evidence.upload" => ("evidence", "upload"),
            "evidence.chain.read" => ("evidence", "audit"),
            "gis.map.center" => ("gis", "center"),
            "radio.ptt.status" => ("radio", "status"),
            s if s.starts_with("get /incident/") => ("incident", "read"),
            _ => return None,
        };

        Some(MissionMapping {
            domain: domain.into(),
            action: action.into(),
            original: trimmed.into(),
        })
    }

    pub fn to_intent(mapped: &MissionMapping, actor: &str) -> Intent {
        Intent {
            actor: actor.into(),
            resource: mapped.domain.clone(),
            action: mapped.action.clone(),
            anchor: TrustAnchor::UiEvent,
            timestamp_ms: wall_ms(),
            metadata: BTreeMap::from([
                ("sector".into(), "public_safety".into()),
                ("mission".into(), mapped.original.clone()),
                ("cjis_mode".into(), "stub".into()),
            ]),
        }
    }

    pub fn map_and_audit(cmd: &str, actor: &str, audit: &AuditLog) -> Option<Intent> {
        let mapped = Self::map(cmd)?;
        let _ = audit.record(
            AuditEventKind::SectorMap,
            actor,
            format!(
                "public_safety `{}` -> {}/{}",
                mapped.original, mapped.domain, mapped.action
            ),
        );
        Some(Self::to_intent(&mapped, actor))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_ncic_lookup() {
        let mapped = PublicSafetyMapper::map("NCIC.lookup").expect("map");
        assert_eq!(mapped.domain, "ncic");
        assert_eq!(mapped.action, "lookup");
    }
}