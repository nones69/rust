//! # Governed UI Toolkit (GUT)
//!
//! Widgets that carry their owning window ID and automatically route all
//! draw calls through the Governed Window Manager for bounds enforcement.
//! No widget may render outside the window it belongs to.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ShellError;
use crate::window_manager::{Rect, WindowManager};

// ── Widget types ─────────────────────────────────────────────────────────────

/// Axis-aligned colour (RGBA, 8-bit channels).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

impl Color {
    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 255 }
    }

    pub const WHITE: Color = Color::rgb(255, 255, 255);
    pub const BLACK: Color = Color::rgb(0, 0, 0);
    pub const TRANSPARENT: Color = Color { r: 0, g: 0, b: 0, a: 0 };
}

/// The visual properties shared by every governed widget.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WidgetStyle {
    pub background: Color,
    pub foreground: Color,
    pub font_size: u8,
}

impl Default for WidgetStyle {
    fn default() -> Self {
        Self {
            background: Color::WHITE,
            foreground: Color::BLACK,
            font_size: 14,
        }
    }
}

/// Discriminant for the concrete widget variant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WidgetKind {
    Label { text: String },
    Button { label: String },
    TextInput { placeholder: String, value: String },
    Panel,
    Image { src: String },
}

/// A single governed widget.
///
/// Every widget is bound to a window (`window_id`) and carries an absolute
/// `bounds` rectangle that must stay inside the parent window's bounds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Widget {
    pub id: Uuid,
    pub window_id: Uuid,
    pub bounds: Rect,
    pub style: WidgetStyle,
    pub kind: WidgetKind,
    pub visible: bool,
}

impl Widget {
    fn new(window_id: Uuid, bounds: Rect, kind: WidgetKind) -> Self {
        Self {
            id: Uuid::new_v4(),
            window_id,
            bounds,
            style: WidgetStyle::default(),
            kind,
            visible: true,
        }
    }
}

// ── Governed drawing context ─────────────────────────────────────────────────

/// A draw command that has passed GWM bounds enforcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrawCommand {
    pub window_id: Uuid,
    pub widget_id: Uuid,
    pub bounds: Rect,
    pub kind: WidgetKind,
    pub style: WidgetStyle,
}

/// Governed UI Toolkit — creates and renders widgets for a set of governed windows.
///
/// All draw calls are verified against the [`WindowManager`] before being
/// accepted into the command queue.
#[derive(Debug, Default)]
pub struct GovernedUiToolkit {
    widgets: std::collections::HashMap<Uuid, Widget>,
    /// Ordered list of verified draw commands emitted this frame.
    frame: Vec<DrawCommand>,
}

impl GovernedUiToolkit {
    pub fn new() -> Self {
        Self::default()
    }

    // ── Widget factory ─────────────────────────────────────────────────────

    /// Add a `Label` widget to a governed window.
    pub fn add_label(
        &mut self,
        wm: &WindowManager,
        window_id: Uuid,
        bounds: Rect,
        text: impl Into<String>,
    ) -> Result<Uuid, ShellError> {
        self.add_widget(wm, window_id, bounds, WidgetKind::Label { text: text.into() })
    }

    /// Add a `Button` widget.
    pub fn add_button(
        &mut self,
        wm: &WindowManager,
        window_id: Uuid,
        bounds: Rect,
        label: impl Into<String>,
    ) -> Result<Uuid, ShellError> {
        self.add_widget(wm, window_id, bounds, WidgetKind::Button { label: label.into() })
    }

    /// Add a `TextInput` widget.
    pub fn add_text_input(
        &mut self,
        wm: &WindowManager,
        window_id: Uuid,
        bounds: Rect,
        placeholder: impl Into<String>,
    ) -> Result<Uuid, ShellError> {
        self.add_widget(
            wm,
            window_id,
            bounds,
            WidgetKind::TextInput {
                placeholder: placeholder.into(),
                value: String::new(),
            },
        )
    }

    /// Add a `Panel` widget.
    pub fn add_panel(
        &mut self,
        wm: &WindowManager,
        window_id: Uuid,
        bounds: Rect,
    ) -> Result<Uuid, ShellError> {
        self.add_widget(wm, window_id, bounds, WidgetKind::Panel)
    }

    // ── Rendering ──────────────────────────────────────────────────────────

    /// Emit all visible widgets into `self.frame`.
    ///
    /// Each widget's bounds are re-checked against the GWM before inclusion.
    pub fn render_frame(&mut self, wm: &WindowManager) -> Result<&[DrawCommand], ShellError> {
        self.frame.clear();
        for widget in self.widgets.values() {
            if !widget.visible {
                continue;
            }
            wm.check_draw_bounds(widget.window_id, widget.bounds)?;
            self.frame.push(DrawCommand {
                window_id: widget.window_id,
                widget_id: widget.id,
                bounds: widget.bounds,
                kind: widget.kind.clone(),
                style: widget.style.clone(),
            });
        }
        Ok(&self.frame)
    }

    /// Return the number of draw commands in the last rendered frame.
    pub fn frame_command_count(&self) -> usize {
        self.frame.len()
    }

    // ── Widget queries ─────────────────────────────────────────────────────

    pub fn widget_count(&self) -> usize {
        self.widgets.len()
    }

    pub fn get_widget(&self, id: Uuid) -> Option<&Widget> {
        self.widgets.get(&id)
    }

    pub fn remove_widget(&mut self, id: Uuid) -> Option<Widget> {
        self.widgets.remove(&id)
    }

    // ── Internal ──────────────────────────────────────────────────────────

    fn add_widget(
        &mut self,
        wm: &WindowManager,
        window_id: Uuid,
        bounds: Rect,
        kind: WidgetKind,
    ) -> Result<Uuid, ShellError> {
        // Enforce that the widget stays inside its window.
        wm.check_draw_bounds(window_id, bounds)?;
        let widget = Widget::new(window_id, bounds, kind);
        let id = widget.id;
        self.widgets.insert(id, widget);
        Ok(id)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::window_manager::WindowManager;

    fn setup() -> (WindowManager, Uuid) {
        let mut wm = WindowManager::new();
        let wid = wm.create_window(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "Test",
            Rect::new(0, 0, 800, 600),
        );
        (wm, wid)
    }

    #[test]
    fn add_label_inside_bounds() {
        let (wm, wid) = setup();
        let mut gut = GovernedUiToolkit::new();
        let label_id = gut
            .add_label(&wm, wid, Rect::new(10, 10, 200, 30), "Hello")
            .unwrap();
        assert!(gut.get_widget(label_id).is_some());
    }

    #[test]
    fn add_widget_outside_bounds_rejected() {
        let (wm, wid) = setup();
        let mut gut = GovernedUiToolkit::new();
        // 900 > 800 — outside window width
        let result = gut.add_label(&wm, wid, Rect::new(0, 0, 900, 600), "Bad");
        assert!(result.is_err());
    }

    #[test]
    fn render_frame_emits_visible_widgets() {
        let (wm, wid) = setup();
        let mut gut = GovernedUiToolkit::new();
        gut.add_button(&wm, wid, Rect::new(0, 0, 100, 40), "OK")
            .unwrap();
        gut.add_panel(&wm, wid, Rect::new(0, 50, 800, 500)).unwrap();
        let cmds = gut.render_frame(&wm).unwrap();
        assert_eq!(cmds.len(), 2);
    }
}
