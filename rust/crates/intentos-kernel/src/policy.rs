use crate::ip_policy::apply_ip_policy;
use crate::signals::ThresholdSignals;
use crate::threshold::{gate_outcome, risk_for, PolicyOutcome, ThresholdLevel};
use crate::types::{Intent, PolicyDecision, TrustAnchor};

/// Native IntentOS policy engine — no external daemon.
pub struct PolicyEngine;

impl PolicyEngine {
    pub fn evaluate(intent: &Intent) -> PolicyDecision {
        Self::evaluate_with_threshold(intent, ThresholdLevel::Medium)
    }

    pub fn evaluate_with_threshold(intent: &Intent, profile: ThresholdLevel) -> PolicyDecision {
        Self::evaluate_with_signals(intent, profile, None)
    }

    pub fn evaluate_with_signals(
        intent: &Intent,
        profile: ThresholdLevel,
        signals: Option<&ThresholdSignals>,
    ) -> PolicyDecision {
        let cap_summary = format!("{}/{}", intent.resource, intent.action);

        if let Some(sig) = signals {
            let risk = risk_for(&intent.resource, &intent.action);
            if risk == ThresholdLevel::High
                && (intent.anchor as u8) < sig.min_anchor_for_high_risk() as u8
            {
                return PolicyDecision {
                    outcome: PolicyOutcome::Deny,
                    allowed: false,
                    requires_confirmation: false,
                    threshold_level: risk,
                    reason: format!(
                        "posture gate: high-risk intent needs anchor >= {:?} ({})",
                        sig.min_anchor_for_high_risk(),
                        sig.posture_summary
                    ),
                    reason_code: "posture_deny".into(),
                    cap_summary,
                    ttl_ms: 0,
                    max_uses: 0,
                };
            }
        }

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
        let known = matches!(
            (intent.action.as_str(), intent.resource.as_str()),
            ("read", "file")
                | ("write", "file")
                | ("list", "dir")
                | ("list", "file")
                | ("send", "network")
                | ("descramble", "network")
                | ("infer", "ai")
                | ("background", "lease")
        );
        if !known {
            return PolicyDecision {
                outcome: PolicyOutcome::Deny,
                allowed: false,
                requires_confirmation: false,
                threshold_level: profile,
                reason: format!(
                    "default-deny: unknown intent {}/{}",
                    intent.resource, intent.action
                ),
                reason_code: "unknown_intent".into(),
                cap_summary,
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
            _ => unreachable!("unknown intents denied above"),
        };

        // Empty actor / resource / action is never ambiently allowed.
        if intent.actor.trim().is_empty()
            || intent.resource.trim().is_empty()
            || intent.action.trim().is_empty()
        {
            return PolicyDecision {
                outcome: PolicyOutcome::Deny,
                allowed: false,
                requires_confirmation: false,
                threshold_level: profile,
                reason: "default-deny: malformed intent fields".into(),
                reason_code: "malformed_intent".into(),
                cap_summary,
                ttl_ms: 0,
                max_uses: 0,
            };
        }

        let (allowed, requires_confirmation, reason, reason_code) = match outcome {
            PolicyOutcome::Allow => (true, false, "intentos policy allow".into(), "allow".into()),
            PolicyOutcome::Confirm => (
                true,
                true,
                format!("threshold {risk:?} requires explicit confirmation"),
                "confirm_required".into(),
            ),
            PolicyOutcome::Deny => (false, false, "threshold policy deny".into(), "deny".into()),
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
    use super::PolicyEngine;
    use crate::types::{wall_ms, Intent, TrustAnchor};
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

    #[test]
    fn unknown_intent_is_default_denied() {
        let intent = Intent {
            actor: "user".into(),
            resource: "camera".into(),
            action: "stream".into(),
            anchor: TrustAnchor::UiEvent,
            timestamp_ms: wall_ms(),
            metadata: BTreeMap::new(),
        };
        let d = PolicyEngine::evaluate(&intent);
        assert!(!d.allowed);
        assert_eq!(d.reason_code, "unknown_intent");
    }

    #[test]
    fn empty_actor_is_default_denied() {
        let intent = Intent {
            actor: "  ".into(),
            resource: "file".into(),
            action: "read".into(),
            anchor: TrustAnchor::UiEvent,
            timestamp_ms: wall_ms(),
            metadata: BTreeMap::new(),
        };
        let d = PolicyEngine::evaluate(&intent);
        assert!(!d.allowed);
        assert_eq!(d.reason_code, "malformed_intent");
    }
}
