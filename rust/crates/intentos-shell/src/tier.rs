//! IntentOS tier numbering (canonical):
//!
//! | # | Tier       | Crate                |
//! |---|------------|----------------------|
//! | 1 | Utilities  | `intentos-utilities` |
//! | 2 | Shell      | `intentos-shell`     |
//! | 3 | Kernel     | `intentos-kernel`    |

/// Tier 1 — capability-gated utilities (VFS, AI, system tools).
pub const TIER_UTILITIES: u8 = 1;
/// Tier 2 — interactive shell (this crate). User session layer.
pub const TIER_SHELL: u8 = 2;
/// Tier 3 — kernel (policy, tokens, capability table, leases).
pub const TIER_KERNEL: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsTier {
    Utilities = TIER_UTILITIES as isize,
    Shell = TIER_SHELL as isize,
    Kernel = TIER_KERNEL as isize,
}

impl OsTier {
    pub fn number(self) -> u8 {
        self as u8
    }

    pub fn name(self) -> &'static str {
        match self {
            OsTier::Utilities => "utilities",
            OsTier::Shell => "shell",
            OsTier::Kernel => "kernel",
        }
    }
}

pub const PROMPT: &str = "shell[2]> ";

pub fn banner() -> &'static str {
    r#"
  IntentOS 0.1 — ground-up AI capability operating system

  ┌──────────────────────────────────────────────────────┐
  │ 1. UTILITIES  vfs · ai gateway · system tools        │
  │ 2. SHELL      interactive session (you are here)     │
  │ 3. KERNEL     policy · tokens · table · leases       │
  └──────────────────────────────────────────────────────┘
"#
}