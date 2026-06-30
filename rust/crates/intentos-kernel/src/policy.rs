use crate::ip_policy::apply_ip_policy;
use crate::threshold::{gate_outcome, risk_for, PolicyOutcome, ThresholdLevel};
use crate::types::{Intent, PolicyDecision, TrustAnchor};

/// Native IntentOS policy engine — no external daemon.
pub struct PolicyEngine;

impl PolicyEngine {
    pub fn evaluate(intent: &Intent) -> PolicyDecision {
        Self::evaluate_with_threshold(intent, ThresholdLevel::Medium)
    }

    pub fn evaluate_with_threshold(intent: &Intent, profile: ThresholdLevel) -> PolicyDecision {
        let cap_summary = format!("{}/{}", intent.resource, intent.action);

        if (intent.anchor as u8) < TrustAnchor::UiEvent as u8 {
            return PolicyDecision {
                outcome: PolicyOutcome::Deny,
                allowed: false,
                requires_confirmation: false,
                threshold_level: profile,
                reason: "intent anchor below UiEvent threshold".into(),
                reason_code: "anchor_low".into(),
                cap_summary,
                ttl_ms: 0,
                max_uses: 0,
            };
        }

        let risk = risk_for(&intent.resource, &intent.action);
        let outcome = gate_outcome(risk, profile);
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

        let (allowed, requires_confirmation, reason, reason_code) = match outcome {
            PolicyOutcome::Allow => (
                true,
                false,
                "intentos policy allow".into(),
                "allow".into(),
            ),
            PolicyOutcome::Confirm => (
                true,
                true,
                format!("threshold {risk:?} requires explicit confirmation"),
                "confirm_required".into(),
            ),
            PolicyOutcome::Deny => (
                false,
                false,
                "threshold policy deny".into(),
                "deny".into(),
            ),
        };

        apply_ip_policy(
            intent,
            PolicyDecision {
                outcome,
                allowed,
                requires_confirmation,
                threshold_level: risk,
                reason,
                reason_code,
                cap_summary,
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

    #[test]
    fn denies_anchor_below_threshold() {
        // TrustAnchor::None is below the UiEvent threshold => non-allowed
        // decision with zero ttl/uses, regardless of resource/action.
        let intent = Intent {
            actor: "app".into(),
            resource: "file".into(),
            action: "read".into(),
            anchor: TrustAnchor::None,
            timestamp_ms: wall_ms(),
            metadata: BTreeMap::new(),
        };
        let decision = PolicyEngine::evaluate(&intent);
        assert!(!decision.allowed);
        assert_eq!(decision.ttl_ms, 0);
        assert_eq!(decision.max_uses, 0);
    }

    #[test]
    fn high_threat_score_denies_otherwise_public_ip() {
        // Public IP (8.8.8.8) would normally pass, but a threat score >= 75
        // from IP-Discrambler must flip the decision to denied.
        let mut meta = BTreeMap::new();
        meta.insert("dest_ip".into(), "8.8.8.8".into());
        meta.insert("threat_score".into(), "90".into());
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

#[cfg(test)]
mod kernel_policy_tests {
    use crate::types::{Intent, TrustAnchor, wall_ms};
    use crate::{Kernel, KernelError};
    use std::collections::BTreeMap;

    #[test]
    fn mint_token_errors_when_policy_denies_low_trust() {
        // End-to-end: a policy-denied intent must fail at mint_token with
        // PolicyDenied — no token (and therefore no capability) is issued.
        let k = Kernel::boot().unwrap();
        let intent = Intent {
            actor: "app".into(),
            resource: "file".into(),
            action: "read".into(),
            anchor: TrustAnchor::None,
            timestamp_ms: wall_ms(),
            metadata: BTreeMap::new(),
        };
        let err = k.mint_token(intent).unwrap_err();
        assert!(matches!(err, KernelError::PolicyDenied(_)));
    }

    #[test]
    fn mint_token_errors_on_blocked_network_dest() {
        // A blocked (bogon) network destination yields a denied policy
        // decision, so mint_token must surface PolicyDenied.
        let k = Kernel::boot().unwrap();
        let mut meta = BTreeMap::new();
        meta.insert("dest_ip".into(), "192.0.2.10".into());
        let intent = Intent {
            actor: "app".into(),
            resource: "network".into(),
            action: "send".into(),
            anchor: TrustAnchor::UiEvent,
            timestamp_ms: wall_ms(),
            metadata: meta,
        };
        let err = k.mint_token(intent).unwrap_err();
        assert!(matches!(err, KernelError::PolicyDenied(_)));
    }
}