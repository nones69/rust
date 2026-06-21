//! Financial markets pilot readiness assessment (SEC/MiFID II / Reg NMS blockers).

use intentos_hal::PlatformInfo;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketsPilotReport {
    pub sector: String,
    pub pilot_ready: bool,
    pub readiness_score: u8,
    pub capabilities_ready: Vec<String>,
    pub blockers: Vec<String>,
    pub compliance_targets: Vec<String>,
}

pub struct MarketsAssessor;

impl MarketsAssessor {
    pub fn assess(_platform: &PlatformInfo) -> MarketsPilotReport {
        MarketsPilotReport {
            sector: "financial_markets".into(),
            pilot_ready: false,
            readiness_score: 12,
            capabilities_ready: vec![
                "FIX/ITCH-shaped intent mapper (stub)".into(),
                "kernel audit chain (prototype)".into(),
            ],
            blockers: vec![
                "FIX/ITCH live market data feed handler not shipped".into(),
                "OMS vendor bridge (FlexTrade/ION) not shipped".into(),
                "Pre-trade risk engine (≤250µs P99) not shipped".into(),
                "PTP/NTP nanosecond clock sync module not shipped".into(),
                "FPGA / kernel-bypass (DPDK/RDMA) offload not shipped".into(),
                "CAT / MiFID II regulatory reporting pipeline not shipped".into(),
                "Market surveillance rules engine not shipped".into(),
            ],
            compliance_targets: vec![
                "SEC Reg NMS".into(),
                "MiFID II".into(),
                "CFTC".into(),
                "SOC 2 Type II".into(),
            ],
        }
    }
}