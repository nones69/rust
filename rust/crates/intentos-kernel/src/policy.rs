use crate::ip_policy::apply_ip_policy;
use crate::types::{Intent, PolicyDecision, TrustAnchor};

/// Native IntentOS policy engine — no external daemon.
pub struct PolicyEngine;

impl PolicyEngine {
    pub fn evaluate(intent: &Intent) -> PolicyDecision {
        if (intent.anchor as u8) < TrustAnchor::UiEvent as u8 {
            return PolicyDecision {
                allowed: false,
                reason: "intent anchor below UiEvent threshold".into(),
                ttl_ms: 0,
                max_uses: 0,
            };
        }

        let (ttl_ms, max_uses) = match (intent.action.as_str(), intent.resource.as_str()) {
            ("read", "file") => (5_000, 1),
            ("write", "file") => (10_000, 1),
            ("list", "dir") | ("list", "file") => (5_000, 1),
            ("send", "network") => (30_000, 1),
            ("descramble", "network") => (15_000, 1),
            ("infer", "ai") => (60_000, 1),
            ("background", "lease") => (30_000, 1),
            _ => (5_000, 1),
        };

        apply_ip_policy(
            intent,
            PolicyDecision {
                allowed: true,
                reason: "intentos policy allow".into(),
                ttl_ms,
                max_uses,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::wall_ms;
    use std::collections::BTreeMap;

    #[test]
    fn blocks_bogon_ip() {
        let mut meta = BTreeMap::new();
        meta.insert("dest_ip".into(), "192.0.2.1".into());
        let intent = Intent {
            actor: "app".into(),
            resource: "network".into(),
            action: "send".into(),
            anchor: TrustAnchor::UiEvent,
            timestamp_ms: wall_ms(),
            metadata: meta,
        };
        assert!(!PolicyEngine::evaluate(&intent).allowed);
    }
}