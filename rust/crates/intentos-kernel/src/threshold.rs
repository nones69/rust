//! Threshold policy levels — risk gating for intent-scoped actions.

use serde::{Deserialize, Serialize};

/// User-configurable threshold profile level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ThresholdLevel {
    #[default]
    Low,
    Medium,
    High,
}

impl ThresholdLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "low" => Some(Self::Low),
            "medium" | "med" => Some(Self::Medium),
            "high" => Some(Self::High),
            _ => None,
        }
    }
}

/// Policy gate outcome before token mint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyOutcome {
    Allow,
    Confirm,
    Deny,
}

impl PolicyOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Confirm => "confirm",
            Self::Deny => "deny",
        }
    }
}

/// Map resource/action pairs to intrinsic risk level.
pub fn risk_for(resource: &str, action: &str) -> ThresholdLevel {
    match (resource, action) {
        ("file", "read") | ("dir", "list") | ("file", "list") => ThresholdLevel::Low,
        ("file", "write") | ("network", "descramble") => ThresholdLevel::Medium,
        ("network", "send") | ("ai", "infer") => ThresholdLevel::High,
        _ => ThresholdLevel::Medium,
    }
}

/// Combine intrinsic risk with profile threshold to produce a gate outcome.
pub fn gate_outcome(risk: ThresholdLevel, profile: ThresholdLevel) -> PolicyOutcome {
    use PolicyOutcome::*;
    use ThresholdLevel::*;
    match (risk, profile) {
        (Low, _) => Allow,
        (Medium, Low) => Confirm,
        (Medium, _) => Allow,
        (High, High) => Confirm,
        (High, _) => Confirm,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_risk_requires_confirm_at_high_profile() {
        let risk = risk_for("network", "send");
        assert_eq!(risk, ThresholdLevel::High);
        assert_eq!(
            gate_outcome(risk, ThresholdLevel::High),
            PolicyOutcome::Confirm
        );
    }

    #[test]
    fn low_risk_always_allows() {
        assert_eq!(
            gate_outcome(risk_for("file", "read"), ThresholdLevel::High),
            PolicyOutcome::Allow
        );
    }
}