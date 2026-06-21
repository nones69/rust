//! Enterprise sector — command mapping, identity, compatibility, migration.

mod compatibility;
mod hardening;
mod identity;
mod ldap_live;
mod mapper;
mod migration;

pub use compatibility::{CompatReport, CompatibilityMatrix};
pub use hardening::{
    EnterpriseHardeningAssessor, EnterpriseHardeningReport, HardeningGate, RollbackCheckpoint,
    TARGET_COMPAT_PASS_PCT, TARGET_MIGRATION_READINESS,
};
pub use identity::{IdentityBackend, IdentityBridge, Principal};
pub use ldap_live::LdapConfig;
pub use mapper::EnterpriseMapper;
pub use migration::{MigrationAssessor, MigrationReport};