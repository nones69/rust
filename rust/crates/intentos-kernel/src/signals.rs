//! Threshold signals — device posture inputs for policy gating.

use crate::types::TrustAnchor;
use serde::{Deserialize, Serialize};

/// Host posture snapshot used to enrich trust evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdSignals {
    pub hardware_trust: bool,
    pub known_arch: bool,
    pub logical_cpus: u32,
    pub trust_score: u8,
    pub developer_mode: bool,
    pub secure_boot_attested: bool,
    pub biometric_available: bool,
    pub recommended_anchor: TrustAnchor,
    pub posture_summary: String,
}

impl ThresholdSignals {
    /// Derive signals from HAL platform probe (no external network calls).
    pub fn from_platform(arch: &str, os: &str, logical_cpus: u32, backend: &str) -> Self {
        Self::from_platform_and_posture(arch, os, logical_cpus, backend, false, false, false, 50)
    }

    /// Full posture-aware signal derivation.
    pub fn from_platform_and_posture(
        arch: &str,
        os: &str,
        logical_cpus: u32,
        backend: &str,
        developer_mode: bool,
        secure_boot_attested: bool,
        biometric_available: bool,
        trust_score: u8,
    ) -> Self {
        let known_arch = arch == "X86_64" || arch == "Aarch64";
        let hardware_trust = known_arch
            && logical_cpus > 0
            && backend.contains("native")
            && !developer_mode
            && trust_score >= 60;
        let recommended_anchor = if hardware_trust && secure_boot_attested {
            TrustAnchor::Hardware
        } else if biometric_available {
            TrustAnchor::Biometric
        } else {
            TrustAnchor::UiEvent
        };
        let posture_summary = format!(
            "arch={arch} os={os} cpus={logical_cpus} backend={backend} trust={trust_score} dev={developer_mode} secure_boot={secure_boot_attested} bio={biometric_available}"
        );
        Self {
            hardware_trust,
            known_arch,
            logical_cpus,
            trust_score,
            developer_mode,
            secure_boot_attested,
            biometric_available,
            recommended_anchor,
            posture_summary,
        }
    }

    /// Minimum anchor required for high-risk operations under enterprise posture.
    pub fn min_anchor_for_high_risk(&self) -> TrustAnchor {
        if self.developer_mode || self.trust_score < 50 {
            TrustAnchor::Biometric
        } else if self.hardware_trust {
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
        let s = ThresholdSignals::from_platform_and_posture(
            "X86_64",
            "Windows",
            8,
            "win32-native",
            false,
            true,
            false,
            85,
        );
        assert!(s.hardware_trust);
        assert_eq!(s.recommended_anchor, TrustAnchor::Hardware);
    }

    #[test]
    fn developer_mode_lowers_trust() {
        let s = ThresholdSignals::from_platform_and_posture(
            "X86_64",
            "Windows",
            8,
            "win32-native",
            true,
            true,
            true,
            40,
        );
        assert!(!s.hardware_trust);
        assert_eq!(s.min_anchor_for_high_risk(), TrustAnchor::Biometric);
    }
}