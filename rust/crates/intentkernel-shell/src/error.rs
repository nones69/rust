//! # Shell error types

use uuid::Uuid;

use crate::window_manager::Rect;

/// Unified error type for the IntentKernel Desktop Shell.
#[derive(Debug, thiserror::Error)]
pub enum ShellError {
    #[error("window not found: {0}")]
    WindowNotFound(Uuid),

    #[error("app not found: {0}")]
    AppNotFound(String),

    #[error("app instance not found: {0}")]
    InstanceNotFound(Uuid),

    #[error("draw out of bounds for window {window_id}: rect {target:?}")]
    DrawOutOfBounds { window_id: Uuid, target: Rect },

    #[error("capability '{capability}' not granted to window {window_id}")]
    CapabilityDenied { window_id: Uuid, capability: String },

    #[error("capability not approved for launch: {0}")]
    CapabilityNotApproved(String),

    #[error("desktop already running")]
    AlreadyRunning,
}
