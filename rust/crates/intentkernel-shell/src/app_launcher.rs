//! # Capability-Aware App Launcher
//!
//! Registers app manifests that declare required capability scopes.
//! Before launching, the launcher verifies that all required capabilities
//! can be satisfied, and allocates a task + token pair passed to the GWM.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ShellError;
use crate::window_manager::{Rect, WindowManager};

// ── Capability scope declarations ────────────────────────────────────────────

/// Capabilities that an app may declare in its manifest.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AppCapability {
    /// Read access to a filesystem path prefix.
    FsRead(String),
    /// Write access to a filesystem path prefix.
    FsWrite(String),
    /// Network access to a list of allowed hosts.
    Network(Vec<String>),
    /// AI inference capability.
    AiInference,
    /// Global clipboard read/write.
    Clipboard,
    /// Global keyboard capture (e.g. accessibility tools).
    KeyboardCapture,
    /// Screen-capture outside own window bounds.
    ScreenCapture,
}

// ── App manifest ─────────────────────────────────────────────────────────────

/// Static description of a governed application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppManifest {
    /// Unique application identifier (e.g. `com.example.MyApp`).
    pub id: String,
    /// Human-readable display name.
    pub name: String,
    /// Version string.
    pub version: String,
    /// Capabilities this app requires to function.
    pub required_capabilities: Vec<AppCapability>,
    /// Preferred initial window size.
    pub default_bounds: Rect,
}

impl AppManifest {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        version: impl Into<String>,
        required_capabilities: Vec<AppCapability>,
        default_bounds: Rect,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            version: version.into(),
            required_capabilities,
            default_bounds,
        }
    }
}

// ── Running app instance ─────────────────────────────────────────────────────

/// A live instance of a launched application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppInstance {
    pub instance_id: Uuid,
    pub manifest_id: String,
    pub task_id: Uuid,
    pub token_id: Uuid,
    pub window_id: Uuid,
}

// ── App Launcher ─────────────────────────────────────────────────────────────

/// The Capability-Aware App Launcher.
///
/// Maintains a registry of [`AppManifest`]s and manages live [`AppInstance`]s.
/// Every launch goes through a capability check; sensitive capabilities
/// (keyboard capture, screen capture) require an explicit policy override.
#[derive(Debug, Default)]
pub struct AppLauncher {
    manifests: HashMap<String, AppManifest>,
    instances: HashMap<Uuid, AppInstance>,
    /// Set of capabilities that have been pre-approved by a policy authority.
    approved_capabilities: Vec<AppCapability>,
}

impl AppLauncher {
    pub fn new() -> Self {
        Self::default()
    }

    // ── Manifest registry ──────────────────────────────────────────────────

    /// Register an application manifest so it can be launched.
    pub fn register(&mut self, manifest: AppManifest) {
        self.manifests.insert(manifest.id.clone(), manifest);
    }

    /// Remove a manifest (and refuse future launches of that app).
    pub fn unregister(&mut self, app_id: &str) {
        self.manifests.remove(app_id);
    }

    pub fn manifests(&self) -> Vec<&AppManifest> {
        let mut list: Vec<&AppManifest> = self.manifests.values().collect();
        list.sort_by_key(|m| m.name.as_str());
        list
    }

    // ── Policy overrides ───────────────────────────────────────────────────

    /// Pre-approve a capability so that apps requesting it are allowed to
    /// launch.  Call this after verifying a signed policy decision.
    pub fn approve_capability(&mut self, cap: AppCapability) {
        if !self.approved_capabilities.contains(&cap) {
            self.approved_capabilities.push(cap);
        }
    }

    // ── Launch ─────────────────────────────────────────────────────────────

    /// Launch `app_id`, opening its window via `wm`.
    ///
    /// Returns the new [`AppInstance`] on success, or a [`ShellError`] if a
    /// required capability cannot be satisfied.
    pub fn launch(
        &mut self,
        app_id: &str,
        wm: &mut WindowManager,
    ) -> Result<AppInstance, ShellError> {
        let manifest = self
            .manifests
            .get(app_id)
            .ok_or_else(|| ShellError::AppNotFound(app_id.to_string()))?
            .clone();

        // Capability check — refuse launch if any required cap is not approved.
        for cap in &manifest.required_capabilities {
            if !self.capability_allowed(cap) {
                return Err(ShellError::CapabilityNotApproved(format!("{cap:?}")));
            }
        }

        // Mint synthetic task / token identifiers.
        let task_id = Uuid::new_v4();
        let token_id = Uuid::new_v4();

        // Create a governed window.
        let window_id = wm.create_window(
            task_id,
            token_id,
            &manifest.name,
            manifest.default_bounds,
        );

        // Apply approved sensitive capabilities to the window.
        for cap in &manifest.required_capabilities {
            match cap {
                AppCapability::Clipboard => {
                    wm.grant_clipboard(window_id)?;
                }
                AppCapability::KeyboardCapture => {
                    wm.grant_keyboard_capture(window_id)?;
                }
                AppCapability::ScreenCapture => {
                    wm.grant_screen_capture(window_id)?;
                }
                _ => {}
            }
        }

        let instance = AppInstance {
            instance_id: Uuid::new_v4(),
            manifest_id: manifest.id.clone(),
            task_id,
            token_id,
            window_id,
        };
        self.instances.insert(instance.instance_id, instance.clone());
        Ok(instance)
    }

    /// Terminate a running instance, closing its window.
    pub fn terminate(
        &mut self,
        instance_id: Uuid,
        wm: &mut WindowManager,
    ) -> Result<(), ShellError> {
        let inst = self
            .instances
            .remove(&instance_id)
            .ok_or(ShellError::InstanceNotFound(instance_id))?;
        wm.close_window(inst.window_id)?;
        Ok(())
    }

    // ── Queries ───────────────────────────────────────────────────────────

    pub fn instances(&self) -> Vec<&AppInstance> {
        self.instances.values().collect()
    }

    pub fn instance_count(&self) -> usize {
        self.instances.len()
    }

    // ── Internal ──────────────────────────────────────────────────────────

    fn capability_allowed(&self, cap: &AppCapability) -> bool {
        // Basic capabilities are always allowed; sensitive ones need approval.
        match cap {
            AppCapability::FsRead(_)
            | AppCapability::FsWrite(_)
            | AppCapability::Network(_)
            | AppCapability::AiInference => true,
            AppCapability::Clipboard
            | AppCapability::KeyboardCapture
            | AppCapability::ScreenCapture => self.approved_capabilities.contains(cap),
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::window_manager::Rect;

    fn default_rect() -> Rect {
        Rect::new(0, 0, 1024, 768)
    }

    fn basic_manifest() -> AppManifest {
        AppManifest::new(
            "com.example.notes",
            "Notes",
            "1.0.0",
            vec![AppCapability::FsRead("/home/user/notes".into())],
            default_rect(),
        )
    }

    #[test]
    fn launch_basic_app() {
        let mut launcher = AppLauncher::new();
        let mut wm = WindowManager::new();
        launcher.register(basic_manifest());
        let inst = launcher.launch("com.example.notes", &mut wm).unwrap();
        assert_eq!(launcher.instance_count(), 1);
        assert_eq!(wm.window_count(), 1);
        launcher.terminate(inst.instance_id, &mut wm).unwrap();
        assert_eq!(launcher.instance_count(), 0);
        assert_eq!(wm.window_count(), 0);
    }

    #[test]
    fn launch_unknown_app_fails() {
        let mut launcher = AppLauncher::new();
        let mut wm = WindowManager::new();
        assert!(launcher.launch("com.unknown", &mut wm).is_err());
    }

    #[test]
    fn sensitive_cap_requires_approval() {
        let mut launcher = AppLauncher::new();
        let mut wm = WindowManager::new();
        let manifest = AppManifest::new(
            "com.example.spy",
            "Spy",
            "1.0.0",
            vec![AppCapability::ScreenCapture],
            default_rect(),
        );
        launcher.register(manifest);
        // Should fail without approval.
        assert!(launcher.launch("com.example.spy", &mut wm).is_err());
        // Should succeed after approval.
        launcher.approve_capability(AppCapability::ScreenCapture);
        assert!(launcher.launch("com.example.spy", &mut wm).is_ok());
    }
}
