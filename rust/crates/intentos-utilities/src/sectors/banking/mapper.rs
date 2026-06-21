//! Banking/ATM sector plugin scaffold — PCI/EMV-shaped intent mapping (Phase 2).

use intentos_audit::{AuditEventKind, AuditLog};
use intentos_kernel::{Intent, TrustAnchor, wall_ms};
use std::collections::BTreeMap;

/// Payments / ATM-oriented command → capability intent mapper (rule-based pilot).
pub struct BankingMapper;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentMapping {
    pub domain: String,
    pub action: String,
    pub original: String,
}

impl BankingMapper {
    pub const SUPPORTED: &'static [&'static str] = &[
        "ATM.withdraw",
        "ATM.deposit",
        "ATM.balance",
        "EMV.authorize",
        "EMV.settle",
        "PCI.key.rotate",
        "Fraud.score",
        "AML.screen",
        "SWIFT.send",
        "ACH.credit",
        "POST /transaction",
        "GET /atm/status",
    ];

    pub fn map(cmd: &str) -> Option<PaymentMapping> {
        let trimmed = cmd.trim();
        let lower = trimmed.to_lowercase();

        let (domain, action) = match lower.as_str() {
            "atm.withdraw" => ("atm", "withdraw"),
            "atm.deposit" => ("atm", "deposit"),
            "atm.balance" | "get /atm/status" => ("atm", "status"),
            "emv.authorize" | "post /transaction" => ("emv", "authorize"),
            "emv.settle" => ("emv", "settle"),
            "pci.key.rotate" => ("pci", "rotate"),
            "fraud.score" => ("fraud", "score"),
            "aml.screen" => ("aml", "screen"),
            "swift.send" => ("swift", "send"),
            "ach.credit" => ("ach", "credit"),
            _ => return None,
        };

        Some(PaymentMapping {
            domain: domain.into(),
            action: action.into(),
            original: trimmed.into(),
        })
    }

    pub fn to_intent(mapped: &PaymentMapping, actor: &str) -> Intent {
        Intent {
            actor: actor.into(),
            resource: mapped.domain.clone(),
            action: mapped.action.clone(),
            anchor: TrustAnchor::UiEvent,
            timestamp_ms: wall_ms(),
            metadata: BTreeMap::from([
                ("sector".into(), "banking".into()),
                ("payment".into(), mapped.original.clone()),
                ("pci_mode".into(), "stub".into()),
            ]),
        }
    }

    pub fn map_and_audit(cmd: &str, actor: &str, audit: &AuditLog) -> Option<Intent> {
        let mapped = Self::map(cmd)?;
        let _ = audit.record(
            AuditEventKind::SectorMap,
            actor,
            format!(
                "banking `{}` -> {}/{}",
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
    fn maps_emv_authorize() {
        let mapped = BankingMapper::map("EMV.authorize").expect("map");
        assert_eq!(mapped.domain, "emv");
        assert_eq!(mapped.action, "authorize");
    }
}