//! Financial markets (trading/exchanges) sector plugin scaffold (Phase 2).

mod mapper;
mod migration;

pub use mapper::MarketsMapper;
pub use migration::{MarketsAssessor, MarketsPilotReport};