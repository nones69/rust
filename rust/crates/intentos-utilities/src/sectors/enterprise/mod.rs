//! Enterprise sector — command mapping, identity, compatibility, migration.

mod compatibility;
mod identity;
mod ldap_live;
mod mapper;
mod migration;

pub use compatibility::{CompatReport, CompatibilityMatrix};
pub use identity::{IdentityBackend, IdentityBridge, Principal};
pub use ldap_live::LdapConfig;
pub use mapper::EnterpriseMapper;
pub use migration::{MigrationAssessor, MigrationReport};