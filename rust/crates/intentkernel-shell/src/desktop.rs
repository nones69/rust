//! # IntentKernel Desktop Environment (IKDE)
//!
//! Wires the Governed Window Manager, Capability-Aware App Launcher,
//! Governed UI Toolkit, and Notification Bus into a single governed
//! desktop session.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::app_launcher::{AppInstance, AppLauncher, AppManifest};
use crate::error::ShellError;
use crate::notifications::{KernelEvent, NotificationBus, NotificationLevel, NotificationSink};
use crate::ui_toolkit::GovernedUiToolkit;
use crate::window_manager::{Rect, WindowManager};

// ── Desktop session state ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DesktopState {
    Stopped,
    Running,
}

// ── Desktop session stats ────────────────────────────────────────────────────

/// A snapshot of the current desktop session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesktopStats {
    pub state: DesktopState,
    pub window_count: usize,
    pub app_instance_count: usize,
    pub widget_count: usize,
    pub notification_count: usize,
    pub unacknowledged_notifications: usize,
}

// ── Desktop Environment ──────────────────────────────────────────────────────

/// IntentKernel Desktop Environment (IKDE).
///
/// Single entry point that owns all shell subsystems:
/// - [`WindowManager`] — GWM
/// - [`AppLauncher`] — capability-aware launch control
/// - [`GovernedUiToolkit`] — GUT
/// - [`NotificationBus`] — kernel-backed event bus
pub struct DesktopEnvironment {
    state: DesktopState,
    pub wm: WindowManager,
    pub launcher: AppLauncher,
    pub gut: GovernedUiToolkit,
    pub notifications: NotificationBus,
    /// Session identifier.
    pub session_id: Uuid,
}

impl DesktopEnvironment {
    /// Initialise a new desktop session (does **not** start the event loop).
    pub fn new() -> Self {
        Self {
            state: DesktopState::Stopped,
            wm: WindowManager::new(),
            launcher: AppLauncher::new(),
            gut: GovernedUiToolkit::new(),
            notifications: NotificationBus::new(),
            session_id: Uuid::new_v4(),
        }
    }

    // ── Lifecycle ──────────────────────────────────────────────────────────

    /// Mark the desktop as running.
    pub fn start(&mut self) -> Result<(), ShellError> {
        if self.state == DesktopState::Running {
            return Err(ShellError::AlreadyRunning);
        }
        self.state = DesktopState::Running;
        self.notifications.emit(KernelEvent::TokenMinted {
            jti: self.session_id.to_string(),
            actor: "ikde".into(),
        });
        Ok(())
    }

    /// Gracefully stop the desktop session.
    pub fn stop(&mut self) {
        self.state = DesktopState::Stopped;
    }

    pub fn state(&self) -> DesktopState {
        self.state
    }

    // ── App management ─────────────────────────────────────────────────────

    /// Register an app manifest with the launcher.
    pub fn register_app(&mut self, manifest: AppManifest) {
        self.launcher.register(manifest);
    }

    /// Launch a registered app and return its instance.
    pub fn launch_app(&mut self, app_id: &str) -> Result<AppInstance, ShellError> {
        let instance = self.launcher.launch(app_id, &mut self.wm)?;
        self.notifications.emit(KernelEvent::TokenMinted {
            jti: instance.token_id.to_string(),
            actor: app_id.to_string(),
        });
        Ok(instance)
    }

    /// Terminate a running app instance.
    pub fn terminate_app(&mut self, instance_id: Uuid) -> Result<(), ShellError> {
        self.launcher.terminate(instance_id, &mut self.wm)
    }

    // ── Notification helpers ───────────────────────────────────────────────

    /// Subscribe to desktop notifications.
    pub fn on_notification(&self, sink: NotificationSink) -> Uuid {
        self.notifications.subscribe(sink)
    }

    /// Emit an arbitrary kernel event into the bus.
    pub fn emit_event(&self, event: KernelEvent) {
        self.notifications.emit(event);
    }

    // ── Stats ──────────────────────────────────────────────────────────────

    pub fn stats(&self) -> DesktopStats {
        let unacked = self.notifications.unacknowledged().len();
        DesktopStats {
            state: self.state,
            window_count: self.wm.window_count(),
            app_instance_count: self.launcher.instance_count(),
            widget_count: self.gut.widget_count(),
            notification_count: self.notifications.log_len(),
            unacknowledged_notifications: unacked,
        }
    }

    /// Acknowledge all pending notifications below `Critical` level.
    pub fn dismiss_non_critical(&self) {
        for n in self.notifications.unacknowledged() {
            if n.level != NotificationLevel::Critical {
                self.notifications.acknowledge(n.id);
            }
        }
    }

    // ── Windowing convenience ──────────────────────────────────────────────

    /// Create a raw window (bypassing the launcher — useful for system UIs).
    pub fn create_system_window(
        &mut self,
        title: impl Into<String>,
        bounds: Rect,
    ) -> Uuid {
        self.wm.create_window(
            self.session_id,
            Uuid::new_v4(),
            title,
            bounds,
        )
    }
}

impl Default for DesktopEnvironment {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_launcher::{AppCapability, AppManifest};
    use crate::window_manager::Rect;

    fn notes_manifest() -> AppManifest {
        AppManifest::new(
            "com.example.notes",
            "Notes",
            "1.0.0",
            vec![AppCapability::FsRead("/home/user/notes".into())],
            Rect::new(0, 0, 800, 600),
        )
    }

    #[test]
    fn desktop_start_stop() {
        let mut de = DesktopEnvironment::new();
        assert_eq!(de.state(), DesktopState::Stopped);
        de.start().unwrap();
        assert_eq!(de.state(), DesktopState::Running);
        de.stop();
        assert_eq!(de.state(), DesktopState::Stopped);
    }

    #[test]
    fn start_twice_errors() {
        let mut de = DesktopEnvironment::new();
        de.start().unwrap();
        assert!(de.start().is_err());
    }

    #[test]
    fn launch_app_updates_stats() {
        let mut de = DesktopEnvironment::new();
        de.start().unwrap();
        de.register_app(notes_manifest());
        de.launch_app("com.example.notes").unwrap();
        let stats = de.stats();
        assert_eq!(stats.window_count, 1);
        assert_eq!(stats.app_instance_count, 1);
    }

    #[test]
    fn terminate_app_cleans_window() {
        let mut de = DesktopEnvironment::new();
        de.start().unwrap();
        de.register_app(notes_manifest());
        let inst = de.launch_app("com.example.notes").unwrap();
        de.terminate_app(inst.instance_id).unwrap();
        let stats = de.stats();
        assert_eq!(stats.window_count, 0);
        assert_eq!(stats.app_instance_count, 0);
    }

    #[test]
    fn notification_bus_receives_events() {
        let de = DesktopEnvironment::new();
        de.emit_event(KernelEvent::PolicyViolation {
            actor: "bad-app".into(),
            resource: "fs".into(),
            action: "delete".into(),
        });
        assert_eq!(de.notifications.log_len(), 1);
    }

    #[test]
    fn system_window_created() {
        let mut de = DesktopEnvironment::new();
        let wid = de.create_system_window("System Panel", Rect::new(0, 0, 1920, 40));
        assert!(de.wm.get(wid).is_ok());
    }
}
