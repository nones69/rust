//! # Governed Window Manager (GWM)
//!
//! Tracks windows, enforces per-window capability boundaries, and prevents
//! apps from drawing outside their allocated region or accessing global
//! input / screen state without an explicit scope grant.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ShellError;

// ── Geometry ────────────────────────────────────────────────────────────────

/// Axis-aligned bounding rectangle in desktop-pixel coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

impl Rect {
    pub fn new(x: i32, y: i32, width: u32, height: u32) -> Self {
        Self { x, y, width, height }
    }

    /// True if `other` is fully contained within `self`.
    pub fn contains_rect(&self, other: &Rect) -> bool {
        other.x >= self.x
            && other.y >= self.y
            && other.x + other.width as i32 <= self.x + self.width as i32
            && other.y + other.height as i32 <= self.y + self.height as i32
    }
}

// ── Capability scope for a single window ────────────────────────────────────

/// Per-window capability scopes.  Each field is `false` by default;
/// the app must hold a valid token granting the scope before the GWM
/// will allow the operation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WindowCapabilities {
    /// May read from / write to the global clipboard.
    pub clipboard: bool,
    /// May receive raw keyboard events (global hotkeys / keylogger guard).
    pub keyboard_capture: bool,
    /// May capture pixels from outside its own bounds (screenshot guard).
    pub screen_capture: bool,
}

// ── Window ──────────────────────────────────────────────────────────────────

/// A single governed application window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Window {
    /// Unique window identifier.
    pub id: Uuid,
    /// Owning task (process / fibre) identifier.
    pub task_id: Uuid,
    /// Capability token that authorised this window.
    pub token_id: Uuid,
    pub title: String,
    pub bounds: Rect,
    /// Capabilities explicitly granted to this window.
    pub capabilities: WindowCapabilities,
    /// Whether the window is currently visible.
    pub visible: bool,
}

impl Window {
    fn new(task_id: Uuid, token_id: Uuid, title: impl Into<String>, bounds: Rect) -> Self {
        Self {
            id: Uuid::new_v4(),
            task_id,
            token_id,
            title: title.into(),
            bounds,
            capabilities: WindowCapabilities::default(),
            visible: true,
        }
    }
}

// ── WindowManager ────────────────────────────────────────────────────────────

/// The Governed Window Manager — single authority for all desktop windows.
#[derive(Debug, Default)]
pub struct WindowManager {
    windows: HashMap<Uuid, Window>,
}

impl WindowManager {
    pub fn new() -> Self {
        Self::default()
    }

    // ── Lifecycle ──────────────────────────────────────────────────────────

    /// Create a new window for the given task / token pair.
    pub fn create_window(
        &mut self,
        task_id: Uuid,
        token_id: Uuid,
        title: impl Into<String>,
        bounds: Rect,
    ) -> Uuid {
        let window = Window::new(task_id, token_id, title, bounds);
        let id = window.id;
        self.windows.insert(id, window);
        id
    }

    /// Close (destroy) a window.  Returns `Err` if the window does not exist.
    pub fn close_window(&mut self, window_id: Uuid) -> Result<(), ShellError> {
        self.windows
            .remove(&window_id)
            .map(|_| ())
            .ok_or(ShellError::WindowNotFound(window_id))
    }

    // ── Capability grants ──────────────────────────────────────────────────

    /// Grant clipboard access to a window (requires a verified token upstream).
    pub fn grant_clipboard(&mut self, window_id: Uuid) -> Result<(), ShellError> {
        self.get_mut(window_id)?.capabilities.clipboard = true;
        Ok(())
    }

    /// Grant global keyboard-capture to a window.
    pub fn grant_keyboard_capture(&mut self, window_id: Uuid) -> Result<(), ShellError> {
        self.get_mut(window_id)?.capabilities.keyboard_capture = true;
        Ok(())
    }

    /// Grant screen-capture outside the window's own bounds.
    pub fn grant_screen_capture(&mut self, window_id: Uuid) -> Result<(), ShellError> {
        self.get_mut(window_id)?.capabilities.screen_capture = true;
        Ok(())
    }

    // ── Enforcement ───────────────────────────────────────────────────────

    /// Verify that a draw call stays inside the window's allocated bounds.
    /// Returns `Err(ShellError::DrawOutOfBounds)` if the target rect exceeds
    /// the window region.
    pub fn check_draw_bounds(&self, window_id: Uuid, target: Rect) -> Result<(), ShellError> {
        let w = self.get(window_id)?;
        if !w.bounds.contains_rect(&target) {
            return Err(ShellError::DrawOutOfBounds { window_id, target });
        }
        Ok(())
    }

    /// Check whether the window holds clipboard access.
    pub fn check_clipboard(&self, window_id: Uuid) -> Result<(), ShellError> {
        if self.get(window_id)?.capabilities.clipboard {
            Ok(())
        } else {
            Err(ShellError::CapabilityDenied {
                window_id,
                capability: "clipboard".into(),
            })
        }
    }

    /// Check whether the window holds keyboard-capture access.
    pub fn check_keyboard_capture(&self, window_id: Uuid) -> Result<(), ShellError> {
        if self.get(window_id)?.capabilities.keyboard_capture {
            Ok(())
        } else {
            Err(ShellError::CapabilityDenied {
                window_id,
                capability: "keyboard_capture".into(),
            })
        }
    }

    /// Check whether the window holds screen-capture access.
    pub fn check_screen_capture(&self, window_id: Uuid) -> Result<(), ShellError> {
        if self.get(window_id)?.capabilities.screen_capture {
            Ok(())
        } else {
            Err(ShellError::CapabilityDenied {
                window_id,
                capability: "screen_capture".into(),
            })
        }
    }

    // ── Queries ───────────────────────────────────────────────────────────

    pub fn get(&self, window_id: Uuid) -> Result<&Window, ShellError> {
        self.windows
            .get(&window_id)
            .ok_or(ShellError::WindowNotFound(window_id))
    }

    fn get_mut(&mut self, window_id: Uuid) -> Result<&mut Window, ShellError> {
        self.windows
            .get_mut(&window_id)
            .ok_or(ShellError::WindowNotFound(window_id))
    }

    pub fn list(&self) -> Vec<&Window> {
        let mut list: Vec<&Window> = self.windows.values().collect();
        list.sort_by_key(|w| w.title.as_str());
        list
    }

    pub fn window_count(&self) -> usize {
        self.windows.len()
    }

    /// Return all windows owned by a given task.
    pub fn windows_for_task(&self, task_id: Uuid) -> Vec<&Window> {
        self.windows
            .values()
            .filter(|w| w.task_id == task_id)
            .collect()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn bounds() -> Rect {
        Rect::new(0, 0, 800, 600)
    }

    #[test]
    fn create_and_close_window() {
        let mut wm = WindowManager::new();
        let task = Uuid::new_v4();
        let token = Uuid::new_v4();
        let id = wm.create_window(task, token, "Test App", bounds());
        assert_eq!(wm.window_count(), 1);
        wm.close_window(id).unwrap();
        assert_eq!(wm.window_count(), 0);
    }

    #[test]
    fn draw_outside_bounds_is_denied() {
        let mut wm = WindowManager::new();
        let id = wm.create_window(Uuid::new_v4(), Uuid::new_v4(), "App", bounds());
        let outside = Rect::new(0, 0, 1920, 1080);
        assert!(wm.check_draw_bounds(id, outside).is_err());
    }

    #[test]
    fn draw_inside_bounds_is_allowed() {
        let mut wm = WindowManager::new();
        let id = wm.create_window(Uuid::new_v4(), Uuid::new_v4(), "App", bounds());
        let inside = Rect::new(10, 10, 100, 100);
        assert!(wm.check_draw_bounds(id, inside).is_ok());
    }

    #[test]
    fn clipboard_denied_without_grant() {
        let mut wm = WindowManager::new();
        let id = wm.create_window(Uuid::new_v4(), Uuid::new_v4(), "App", bounds());
        assert!(wm.check_clipboard(id).is_err());
        wm.grant_clipboard(id).unwrap();
        assert!(wm.check_clipboard(id).is_ok());
    }

    #[test]
    fn keyboard_capture_denied_without_grant() {
        let mut wm = WindowManager::new();
        let id = wm.create_window(Uuid::new_v4(), Uuid::new_v4(), "App", bounds());
        assert!(wm.check_keyboard_capture(id).is_err());
    }

    #[test]
    fn screen_capture_denied_without_grant() {
        let mut wm = WindowManager::new();
        let id = wm.create_window(Uuid::new_v4(), Uuid::new_v4(), "App", bounds());
        assert!(wm.check_screen_capture(id).is_err());
    }
}
