//! Threshold signals — device posture inputs for policy gating (Phase 1 stub).

use crate::types::TrustAnchor;
use serde::{Deserialize, Serialize};

/// Host posture snapshot used to enrich trust evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdSignals {
    pub hardware_trust: bool,
    pub known_arch: bool,
    pub logical_cpus: u32,
    pub recommended_anchor: TrustAnchor,
    pub posture_summary: String,
}

impl ThresholdSignals {
    /// Derive signals from HAL platform probe (no external network calls).
    pub fn from_platform(arch: &str, os: &str, logical_cpus: u32, backend: &str) -> Self {
        let known_arch = arch == "X86_64" || arch == "Aarch64";
        let hardware_trust = known_arch && logical_cpus > 0 && backend.contains("native");
        let recommended_anchor = if hardware_trust {
            TrustAnchor::Hardware
        } else {
            TrustAnchor::UiEvent
        };
        let posture_summary = format!("arch={arch} os={os} cpus={logical_cpus} backend={backend}");
        Self {
            hardware_trust,
            known_arch,
            logical_cpus,
            recommended_anchor,
            posture_summary,
        }
    }

    /// Minimum anchor required for high-risk operations under enterprise posture.
    pub fn min_anchor_for_high_risk(&self) -> TrustAnchor {
        if self.hardware_trust {
            TrustAnchor::UiEvent
        } else {
            TrustAnchor::Biometric
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_host_gets_hardware_trust() {
        let s = ThresholdSignals::from_platform("X86_64", "Windows", 8, "win32-native");
        assert!(s.hardware_trust);
        assert_eq!(s.recommended_anchor, TrustAnchor::Hardware);
    }
}