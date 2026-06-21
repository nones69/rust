//! Healthcare sector plugin scaffold (Phase 2).

mod mapper;
mod migration;

pub use mapper::{ClinicalMapping, HealthcareMapper};
pub use migration::{HealthcareAssessor, HealthcarePilotReport};