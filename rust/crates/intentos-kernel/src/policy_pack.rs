//! Policy packs — environment-specific threshold profiles (Phase 1).

use crate::threshold::ThresholdLevel;
use serde::{Deserialize, Serialize};

/// Named policy profile for personal vs enterprise environments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PolicyPack {
    #[default]
    Personal,
    Enterprise,
}

impl PolicyPack {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Personal => "personal",
            Self::Enterprise => "enterprise",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "personal" | "home" => Some(Self::Personal),
            "enterprise" | "ent" | "work" => Some(Self::Enterprise),
            _ => None,
        }
    }

    pub fn default_threshold(self) -> ThresholdLevel {
        match self {
            Self::Personal => ThresholdLevel::Medium,
            Self::Enterprise => ThresholdLevel::High,
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Personal => "balanced gating for single-user workstations",
            Self::Enterprise => "stricter confirms for regulated / managed environments",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enterprise_is_stricter() {
        assert_eq!(
            PolicyPack::Enterprise.default_threshold(),
            ThresholdLevel::High
        );
    }
}