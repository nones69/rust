//! IoT/embedded sector plugin scaffold (Phase 2).

mod mapper;
mod migration;

pub use mapper::IotMapper;
pub use migration::{IotAssessor, IotPilotReport};