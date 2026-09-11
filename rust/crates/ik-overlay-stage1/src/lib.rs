//! # Stage 1 — Windows VBS / Micro-VM overlay foundations
//!
//! Compile-tested interfaces and a mock broker harness. On non-Windows hosts
//! this crate provides the **same API surface** with `PlatformSupport::Stubbed`
//! so Linux CI can type-check the design.
//!
//! **Not** a VBS driver, HVCI enclave, or ransomware-immunity claim.
//! See `docs/overlay/stage1-windows-vbs.md`.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// What this build can actually do on the current host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlatformSupport {
    /// Windows APIs may be linked in a future MSVC build.
    #[cfg(target_os = "windows")]
    WindowsNative,
    /// Interfaces only — expected on Linux CI.
    Stubbed,
}

impl PlatformSupport {
    pub fn current() -> Self {
        #[cfg(target_os = "windows")]
        {
            PlatformSupport::WindowsNative
        }
        #[cfg(not(target_os = "windows"))]
        {
            PlatformSupport::Stubbed
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OverlayError {
    #[error("not supported on this platform: {0}")]
    Unsupported(&'static str),
    #[error("policy denied: {0}")]
    Denied(String),
    #[error("invalid config: {0}")]
    Invalid(String),
}

/// VBS / VSM-aligned enclave placement for the intent broker (design).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VbsBrokerSpec {
    pub service_name: String,
    /// Prefer Virtualization-Based Security isolation when available.
    pub require_vbs: bool,
    /// HVCI / code integrity expectation (policy flag, not enforced here).
    pub prefer_hvci: bool,
}

impl Default for VbsBrokerSpec {
    fn default() -> Self {
        Self {
            service_name: "IntentKernelBroker".into(),
            require_vbs: true,
            prefer_hvci: true,
        }
    }
}

/// Short-lived Micro-VM task (optional Stage-1 path).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MicroVmTaskSpec {
    pub image_ref: String,
    pub memory_mib: u32,
    pub ttl_ms: u64,
    /// Capability JTIs that may be injected into the guest.
    pub granted_jtis: Vec<String>,
}

/// Host-facing broker operations Stage 1 must eventually provide.
pub trait Stage1Broker {
    fn platform(&self) -> PlatformSupport;
    fn mint_file_write(&self, actor: &str, path: &str) -> Result<ScopedGrant, OverlayError>;
    fn revoke(&self, jti: &str) -> Result<(), OverlayError>;
}

/// Prototype grant returned by the mock broker.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScopedGrant {
    pub jti: String,
    pub resource: String,
    pub action: String,
    pub target: String,
    pub ttl_ms: u64,
    pub max_uses: u32,
}

/// In-process mock used on all platforms for unit tests / CI.
#[derive(Debug, Default)]
pub struct MockVbsBroker {
    pub spec: VbsBrokerSpec,
    next_id: std::sync::atomic::AtomicU64,
    revoked: std::sync::Mutex<std::collections::BTreeSet<String>>,
}

impl Stage1Broker for MockVbsBroker {
    fn platform(&self) -> PlatformSupport {
        PlatformSupport::current()
    }

    fn mint_file_write(&self, actor: &str, path: &str) -> Result<ScopedGrant, OverlayError> {
        if actor.trim().is_empty() || path.trim().is_empty() {
            return Err(OverlayError::Invalid("empty actor or path".into()));
        }
        if path.contains("..") {
            return Err(OverlayError::Denied("path traversal rejected".into()));
        }
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(ScopedGrant {
            jti: format!("stage1-{id}"),
            resource: "file".into(),
            action: "write".into(),
            target: path.to_string(),
            ttl_ms: 10_000,
            max_uses: 1,
        })
    }

    fn revoke(&self, jti: &str) -> Result<(), OverlayError> {
        self.revoked.lock().unwrap().insert(jti.to_string());
        Ok(())
    }
}

impl MockVbsBroker {
    pub fn is_revoked(&self, jti: &str) -> bool {
        self.revoked.lock().unwrap().contains(jti)
    }

    /// Validate a Micro-VM task spec (no VM started).
    pub fn validate_microvm(&self, task: &MicroVmTaskSpec) -> Result<(), OverlayError> {
        if task.memory_mib == 0 || task.memory_mib > 8192 {
            return Err(OverlayError::Invalid("memory_mib out of range".into()));
        }
        if task.ttl_ms == 0 {
            return Err(OverlayError::Invalid("ttl_ms must be > 0".into()));
        }
        if task.image_ref.trim().is_empty() {
            return Err(OverlayError::Invalid("empty image_ref".into()));
        }
        Ok(())
    }

    /// Attempt to start a Micro-VM — stubbed everywhere for now.
    pub fn start_microvm(&self, task: &MicroVmTaskSpec) -> Result<(), OverlayError> {
        self.validate_microvm(task)?;
        Err(OverlayError::Unsupported(
            "Micro-VM launch not implemented in this scaffold",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_broker_mints_and_revokes() {
        let b = MockVbsBroker::default();
        let g = b
            .mint_file_write("user", "C\\\\Users\\\\a\\\\x.txt")
            .unwrap();
        assert_eq!(g.action, "write");
        assert_eq!(g.max_uses, 1);
        b.revoke(&g.jti).unwrap();
        assert!(b.is_revoked(&g.jti));
    }

    #[test]
    fn rejects_traversal() {
        let b = MockVbsBroker::default();
        assert!(matches!(
            b.mint_file_write("user", "..\\\\Windows\\\\System32"),
            Err(OverlayError::Denied(_))
        ));
    }

    #[test]
    fn microvm_validate_ok_start_unsupported() {
        let b = MockVbsBroker::default();
        let task = MicroVmTaskSpec {
            image_ref: "intentos-guest:dev".into(),
            memory_mib: 512,
            ttl_ms: 30_000,
            granted_jtis: vec!["stage1-0".into()],
        };
        b.validate_microvm(&task).unwrap();
        assert!(matches!(
            b.start_microvm(&task),
            Err(OverlayError::Unsupported(_))
        ));
    }

    #[test]
    fn platform_support_is_defined() {
        let _ = PlatformSupport::current();
    }
}
