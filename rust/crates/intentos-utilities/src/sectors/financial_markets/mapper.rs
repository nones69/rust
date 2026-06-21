//! Financial markets sector plugin — FIX/ITCH/OMS-shaped intent mapping (Phase 2).

use intentos_audit::{AuditEventKind, AuditLog};
use intentos_kernel::{Intent, TrustAnchor, wall_ms};
use std::collections::BTreeMap;

/// Trading / exchange command → capability intent mapper (rule-based pilot).
pub struct MarketsMapper;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TradingMapping {
    pub domain: String,
    pub action: String,
    pub original: String,
}

impl MarketsMapper {
    pub const SUPPORTED: &'static [&'static str] = &[
        "FIX.subscribe",
        "FIX.order",
        "FIX.cancel",
        "ITCH.snapshot",
        "OMS.route",
        "Risk.precheck",
        "Risk.killswitch",
        "SOR.route",
        "Surveillance.alert",
        "MiFID.report",
        "CAT.submit",
        "Latency.measure",
        "POST /order",
        "GET /marketdata",
    ];

    pub fn map(cmd: &str) -> Option<TradingMapping> {
        let trimmed = cmd.trim();
        let lower = trimmed.to_lowercase();

        let (domain, action) = match lower.as_str() {
            "fix.subscribe" | "get /marketdata" => ("fix", "subscribe"),
            "fix.order" | "post /order" => ("fix", "order"),
            "fix.cancel" => ("fix", "cancel"),
            "itch.snapshot" => ("itch", "snapshot"),
            "oms.route" => ("oms", "route"),
            "risk.precheck" => ("risk", "precheck"),
            "risk.killswitch" => ("risk", "killswitch"),
            "sor.route" => ("sor", "route"),
            "surveillance.alert" => ("surveillance", "alert"),
            "mifid.report" => ("mifid", "report"),
            "cat.submit" => ("cat", "submit"),
            "latency.measure" => ("latency", "measure"),
            _ => return None,
        };

        Some(TradingMapping {
            domain: domain.into(),
            action: action.into(),
            original: trimmed.into(),
        })
    }

    pub fn to_intent(mapped: &TradingMapping, actor: &str) -> Intent {
        Intent {
            actor: actor.into(),
            resource: mapped.domain.clone(),
            action: mapped.action.clone(),
            anchor: TrustAnchor::UiEvent,
            timestamp_ms: wall_ms(),
            metadata: BTreeMap::from([
                ("sector".into(), "financial_markets".into()),
                ("trading".into(), mapped.original.clone()),
                ("latency_mode".into(), "stub".into()),
            ]),
        }
    }

    pub fn map_and_audit(cmd: &str, actor: &str, audit: &AuditLog) -> Option<Intent> {
        let mapped = Self::map(cmd)?;
        let _ = audit.record(
            AuditEventKind::SectorMap,
            actor,
            format!(
                "financial_markets `{}` -> {}/{}",
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
    fn maps_fix_order() {
        let mapped = MarketsMapper::map("FIX.order").expect("map");
        assert_eq!(mapped.domain, "fix");
        assert_eq!(mapped.action, "order");
    }

    #[test]
    fn maps_risk_killswitch() {
        let mapped = MarketsMapper::map("Risk.killswitch").expect("map");
        assert_eq!(mapped.domain, "risk");
        assert_eq!(mapped.action, "killswitch");
    }
}