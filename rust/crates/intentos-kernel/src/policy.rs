use crate::ip_policy::apply_ip_policy;
use crate::signals::ThresholdSignals;
use crate::threshold::{gate_outcome, risk_for, PolicyOutcome, ThresholdLevel};
use crate::types::{Intent, PolicyDecision, TrustAnchor};

/// Native IntentOS policy engine — no external daemon.
pub struct PolicyEngine;

impl PolicyEngine {
    fn deny(
        profile: ThresholdLevel,
        cap_summary: String,
        reason: impl Into<String>,
        reason_code: &str,
    ) -> PolicyDecision {
        PolicyDecision {
            outcome: PolicyOutcome::Deny,
            allowed: false,
            requires_confirmation: false,
            threshold_level: profile,
            reason: reason.into(),
            reason_code: reason_code.into(),
            cap_summary,
            ttl_ms: 0,
            max_uses: 0,
        }
    }

    fn explicit_rule(resource: &str, action: &str) -> Option<(u64, u32)> {
        match (action, resource) {
            ("read", "file") => Some((5_000, 1)),
            ("write", "file") => Some((10_000, 1)),
            ("list", "dir") | ("list", "file") => Some((5_000, 1)),
            ("send", "network") => Some((30_000, 1)),
            ("descramble", "network") => Some((15_000, 1)),
            ("infer", "ai") => Some((60_000, 1)),
            ("background", "lease") => Some((30_000, 1)),
            _ => None,
        }
    }

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

        if !intent.is_well_formed() {
            return Self::deny(
                profile,
                cap_summary,
                "malformed intent: actor, resource, action, and timestamp are required",
                "malformed_intent",
            );
        }

        if let Some(sig) = signals {
            let risk = risk_for(&intent.resource, &intent.action);
            if risk == ThresholdLevel::High
                && (intent.anchor as u8) < sig.min_anchor_for_high_risk() as u8
            {
                let mut decision = Self::deny(risk, cap_summary, "", "posture_deny");
                decision.reason = format!(
                    "posture gate: high-risk intent needs anchor >= {:?} ({})",
                    sig.min_anchor_for_high_risk(),
                    sig.posture_summary
                );
                return decision;
            }
        }

        if (intent.anchor as u8) < TrustAnchor::UiEvent as u8 {
            return Self::deny(
                profile,
                cap_summary,
                "intent anchor below UiEvent threshold",
                "anchor_low",
            );
        }

        let requested_ttl_ms = match intent.requested_ttl_ms() {
            Ok(ttl) => ttl,
            Err(()) => {
                return Self::deny(
                    profile,
                    cap_summary,
                    "requested ttl must be a positive integer",
                    "ttl_invalid",
                );
            }
        };

        let Some((base_ttl_ms, max_uses)) =
            Self::explicit_rule(&intent.resource, &intent.action)
        else {
            return Self::deny(
                profile,
                cap_summary,
                "no explicit policy rule for requested resource/action",
                "unknown_scope",
            );
        };
        let ttl_ms = requested_ttl_ms.map(|ttl| ttl.min(base_ttl_ms)).unwrap_or(base_ttl_ms);
        if ttl_ms == 0 {
            return Self::deny(
                profile,
                cap_summary,
                "requested ttl must resolve to a positive value",
                "ttl_invalid",
            );
        }

        let risk = risk_for(&intent.resource, &intent.action);
        let outcome = gate_outcome(risk, profile);
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
    use crate::types::{wall_ms, META_REQUESTED_TTL_MS};
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

    #[test]
    fn test_deny_by_default_on_malformed_intent() {
        let intent = Intent {
            actor: "".into(),
            resource: "".into(),
            action: "read".into(),
            anchor: TrustAnchor::UiEvent,
            timestamp_ms: 0,
            metadata: BTreeMap::new(),
        };
        let decision = PolicyEngine::evaluate(&intent);
        assert!(!decision.allowed);
        assert_eq!(decision.reason_code, "malformed_intent");
    }

    #[test]
    fn test_deny_on_ttl_zero_or_negative() {
        for raw in ["0", "-1"] {
            let mut metadata = BTreeMap::new();
            metadata.insert(META_REQUESTED_TTL_MS.into(), raw.into());
            let intent = Intent {
                actor: "app".into(),
                resource: "file".into(),
                action: "read".into(),
                anchor: TrustAnchor::UiEvent,
                timestamp_ms: wall_ms(),
                metadata,
            };
            let decision = PolicyEngine::evaluate(&intent);
            assert!(!decision.allowed, "raw={raw}");
            assert_eq!(decision.reason_code, "ttl_invalid");
        }
    }

    #[test]
    fn test_deny_on_action_resource_mismatch() {
        let intent = Intent {
            actor: "app".into(),
            resource: "file".into(),
            action: "send".into(),
            anchor: TrustAnchor::UiEvent,
            timestamp_ms: wall_ms(),
            metadata: BTreeMap::new(),
        };
        let decision = PolicyEngine::evaluate(&intent);
        assert!(!decision.allowed);
        assert_eq!(decision.reason_code, "unknown_scope");
    }

    #[test]
    fn test_deny_on_unknown_action_type() {
        let intent = Intent {
            actor: "app".into(),
            resource: "file".into(),
            action: "chmod".into(),
            anchor: TrustAnchor::UiEvent,
            timestamp_ms: wall_ms(),
            metadata: BTreeMap::new(),
        };
        let decision = PolicyEngine::evaluate(&intent);
        assert!(!decision.allowed);
        assert_eq!(decision.reason_code, "unknown_scope");
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