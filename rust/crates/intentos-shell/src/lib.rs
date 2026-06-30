//! # intentos-shell — Tier 2
//!
//! The shell is **component #2** in IntentOS:
//!
//! 1. Utilities (`intentos-utilities`)
//! 2. **Shell** (`intentos-shell`) ← this crate
//! 3. Kernel (`intentos-kernel`)
//!
//! The shell is the user session: it parses commands and calls into utilities
//! and the kernel directly. No TCP RPC, no external daemons.

mod ai_os;
mod builtins;
mod policy_cmd;
mod parser;
mod session;
mod tier;

pub use parser::ParsedLine;
pub use session::ShellSession;
pub use tier::{banner, OsTier, PROMPT, TIER_KERNEL, TIER_SHELL, TIER_UTILITIES};

/// Tier-2 shell entry point.
pub struct Shell {
    session: ShellSession,
}

impl Shell {
    pub fn open(runtime: std::sync::Arc<intentos_utilities::OsRuntime>) -> Self {
        Self {
            session: ShellSession::new(runtime),
        }
    }

    pub fn run(&mut self) -> anyhow::Result<()> {
        self.session.run_repl()
    }

    pub fn eval(&mut self, line: &str) -> anyhow::Result<bool> {
        self.session.eval(line)
    }
}

