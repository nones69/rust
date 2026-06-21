//! Cross-sector market deployment status — aggregates all Phase 2 assessors.

use crate::sectors::banking::{BankingAssessor, BankingPilotReport};
use crate::sectors::enterprise::{
    EnterpriseHardeningAssessor, EnterpriseHardeningReport, MigrationAssessor, MigrationReport,
};
use crate::sectors::financial_markets::{MarketsAssessor, MarketsPilotReport};
use crate::sectors::healthcare::{HealthcareAssessor, HealthcarePilotReport};
use crate::sectors::iot::{IotAssessor, IotPilotReport};
use crate::sectors::public_safety::{PublicSafetyAssessor, PublicSafetyPilotReport};
use intentos_audit::AuditLog;
use intentos_hal::PlatformInfo;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectorStatus {
    pub sector: String,
    pub readiness_score: u8,
    pub pilot_ready: bool,
    pub blocker_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketDeploymentStatus {
    pub sectors: Vec<SectorStatus>,
    pub enterprise_migration: MigrationReport,
    pub enterprise_hardening: EnterpriseHardeningReport,
    pub healthcare: HealthcarePilotReport,
    pub public_safety: PublicSafetyPilotReport,
    pub banking: BankingPilotReport,
    pub iot: IotPilotReport,
    pub financial_markets: MarketsPilotReport,
    pub phase2_scaffolds_complete: bool,
    pub wave1_pilot_exit_ready: bool,
}

pub struct MarketDeploymentReporter;

impl MarketDeploymentReporter {
    pub fn status(
        platform: &PlatformInfo,
        audit: &AuditLog,
        identity: &crate::IdentityBridge,
    ) -> MarketDeploymentStatus {
        let migration = MigrationAssessor::assess(platform);
        let hardening = EnterpriseHardeningAssessor::assess(platform, audit, identity);
        let healthcare = HealthcareAssessor::assess(platform);
        let public_safety = PublicSafetyAssessor::assess(platform);
        let banking = BankingAssessor::assess(platform);
        let iot = IotAssessor::assess(platform);
        let financial_markets = MarketsAssessor::assess(platform);

        let sectors = vec![
            sector_row(&migration.sector, migration.readiness_score, migration.pilot_ready, &migration.blockers),
            sector_row(&healthcare.sector, healthcare.readiness_score, healthcare.pilot_ready, &healthcare.blockers),
            sector_row(
                &public_safety.sector,
                public_safety.readiness_score,
                public_safety.pilot_ready,
                &public_safety.blockers,
            ),
            sector_row(&banking.sector, banking.readiness_score, banking.pilot_ready, &banking.blockers),
            sector_row(&iot.sector, iot.readiness_score, iot.pilot_ready, &iot.blockers),
            sector_row(
                &financial_markets.sector,
                financial_markets.readiness_score,
                financial_markets.pilot_ready,
                &financial_markets.blockers,
            ),
        ];

        MarketDeploymentStatus {
            phase2_scaffolds_complete: sectors.len() == 6,
            wave1_pilot_exit_ready: hardening.pilot_exit_ready,
            sectors,
            enterprise_migration: migration,
            enterprise_hardening: hardening,
            healthcare,
            public_safety,
            banking,
            iot,
            financial_markets,
        }
    }
}

fn sector_row(sector: &str, score: u8, pilot_ready: bool, blockers: &[String]) -> SectorStatus {
    SectorStatus {
        sector: sector.into(),
        readiness_score: score,
        pilot_ready,
        blocker_count: blockers.len(),
    }
}