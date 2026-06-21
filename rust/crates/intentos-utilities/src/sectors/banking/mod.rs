//! Banking/ATM sector plugin scaffold (Phase 2).

mod mapper;
mod migration;

pub use mapper::BankingMapper;
pub use migration::{BankingAssessor, BankingPilotReport};