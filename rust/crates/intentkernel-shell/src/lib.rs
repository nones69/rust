//! # intentkernel-shell
//!
//! IntentKernel Desktop Shell — the governed UI layer of IntentOS.
//!
//! ## Subsystems
//!
//! | Module | Responsibility |
//! |---|---|
//! | [`window_manager`] | Governed Window Manager (GWM) — bounds + capability enforcement |
//! | [`app_launcher`]   | Capability-Aware App Launcher |
//! | [`ui_toolkit`]     | Governed UI Toolkit (GUT) |
//! | [`notifications`]  | Kernel-Backed Notifications + Events |
//! | [`desktop`]        | Desktop Environment (IKDE) — wires all subsystems |
//!
//! ## Quick start
//!
//! ```rust
//! use intentkernel_shell::desktop::DesktopEnvironment;
//! use intentkernel_shell::app_launcher::{AppManifest, AppCapability};
//! use intentkernel_shell::window_manager::Rect;
//!
//! let mut de = DesktopEnvironment::new();
//! de.start().unwrap();
//!
//! de.register_app(AppManifest::new(
//!     "com.example.notes",
//!     "Notes",
//!     "1.0.0",
//!     vec![AppCapability::FsRead("/home/user/notes".into())],
//!     Rect::new(100, 100, 800, 600),
//! ));
//!
//! let inst = de.launch_app("com.example.notes").unwrap();
//! println!("window id = {}", inst.window_id);
//! de.terminate_app(inst.instance_id).unwrap();
//! ```

pub mod app_launcher;
pub mod desktop;
pub mod error;
pub mod notifications;
pub mod ui_toolkit;
pub mod window_manager;

pub use desktop::DesktopEnvironment;
pub use error::ShellError;
