//! # intentos-utilities — Tier 1
//!
//! Utilities are **component #1** in IntentOS:
//!
//! 1. **Utilities** (`intentos-utilities`) ← this crate
//! 2. Shell (`intentos-shell`)
//! 3. Kernel (`intentos-kernel`)
//!
//! Native VFS, AI gateway, HAL probe, audit log, sector plugins,
//! and system tools — all gated through the kernel.

mod ai;
mod federation;
mod ip_discrambler;
mod recognizer;
mod sectors;
mod tools;
mod vfs;

pub use ai::{AiError, AiGateway};
pub use ip_discrambler::{
    IpDiscramblerBridge, IpDiscramblerError, IpLookupResult, IpPolicyVerdict,
};
pub use federation::{FederationError, FederationHub};
pub use intentos_audit::{AuditEntry, AuditEventKind, AuditLog};
pub use intentos_hal::{native_hal, CpuArch, HardwareAbstraction, HostOs, PlatformInfo};
pub use recognizer::{OllamaClient, PilotRecognizer};
pub use sectors::enterprise::{
    CompatReport, CompatibilityMatrix, EnterpriseHardeningAssessor, EnterpriseHardeningReport,
    EnterpriseMapper, HardeningGate, IdentityBackend, IdentityBridge, LdapConfig,
    MigrationAssessor, MigrationReport, Principal, RollbackCheckpoint, TARGET_COMPAT_PASS_PCT,
    TARGET_MIGRATION_READINESS,
};
pub use sectors::banking::{BankingAssessor, BankingMapper, BankingPilotReport};
pub use sectors::healthcare::{
    ClinicalMapping, HealthcareAssessor, HealthcareMapper, HealthcarePilotReport,
};
pub use sectors::financial_markets::{MarketsAssessor, MarketsMapper, MarketsPilotReport};
pub use sectors::iot::{IotAssessor, IotMapper, IotPilotReport};
pub use sectors::public_safety::{
    PublicSafetyAssessor, PublicSafetyMapper, PublicSafetyPilotReport,
};
pub use tools::SysTools;
pub use vfs::{VfsError, VirtualFs};

use intentos_kernel::{Kernel, KernelConfig};
use std::sync::{Arc, Mutex};

/// IntentOS tier number for utilities.
pub const TIER: u8 = 1;

/// Utility subsystem bundle wired to a kernel instance.
pub struct Utilities {
    pub vfs: VirtualFs,
    pub federation: FederationHub,
    kernel: Arc<Kernel>,
}

impl Utilities {
    pub fn attach(kernel: Kernel) -> Self {
        Self {
            vfs: VirtualFs::new(),
            federation: FederationHub::new("intentos-local"),
            kernel: Arc::new(kernel),
        }
    }

    pub fn kernel(&self) -> &Kernel {
        self.kernel.as_ref()
    }

    pub fn kernel_arc(&self) -> Arc<Kernel> {
        Arc::clone(&self.kernel)
    }
}

/// Thread-safe OS runtime: HAL + audit + kernel + utilities.
pub struct OsRuntime {
    pub platform: PlatformInfo,
    pub audit: Arc<AuditLog>,
    pub identity: IdentityBridge,
    pub ip_discrambler: Option<IpDiscramblerBridge>,
    pub utilities: Arc<Mutex<Utilities>>,
}

impl OsRuntime {
    pub fn boot() -> Result<Self, intentos_kernel::KernelError> {
        Self::boot_with_audit(Arc::new(AuditLog::new()))
    }

    pub fn boot_with_audit(audit: Arc<AuditLog>) -> Result<Self, intentos_kernel::KernelError> {
        let hal = native_hal();
        let platform = hal.probe();

        let kernel = Kernel::boot_with(KernelConfig {
            audit: Some(Arc::clone(&audit)),
            recognizer: Some(Arc::new(PilotRecognizer::boot())),
        })?;

        let _ = audit.record(
            AuditEventKind::Boot,
            "utilities",
            format!(
                "hal={} arch={:?} os={:?} cpus={} recognizer={}",
                platform.backend,
                platform.arch,
                platform.os,
                platform.logical_cpus,
                kernel.recognizer_name()
            ),
        );

        let ip_discrambler = IpDiscramblerBridge::discover().ok();
        if let Some(ref bridge) = ip_discrambler {
            let _ = audit.record(
                AuditEventKind::Boot,
                "utilities",
                format!("ip-discrambler=online root={}", bridge.root().display()),
            );
        }

        Ok(Self {
            platform,
            audit,
            identity: IdentityBridge::from_env(),
            ip_discrambler,
            utilities: Arc::new(Mutex::new(Utilities::attach(kernel))),
        })
    }

    pub fn kernel(&self) -> Arc<Kernel> {
        self.utilities.lock().unwrap().kernel_arc()
    }

    /// Resolve the boot actor from the identity bridge (AD/LDAP stub or local).
    pub fn boot_actor(&self) -> String {
        let principal = self.identity.whoami();
        self.identity.actor_id(&principal)
    }
}