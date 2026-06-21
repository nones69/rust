//! # IntentOS — three-tier operating system layout
//!
//! A working IntentKernel AI OS is organized into three major components:
//!
//! | Tier | Role | Components |
//! |------|------|------------|
//! | **Kernel** | Capability enforcement, intent broker, leases | `capd`, `intentd`, `leasebroker`, `eventscope` |
//! | **Shell** | Interactive user session — intent → token → action | `ikrl-shell` |
//! | **Utilities** | Capability-gated services (AI, FS, federation, bridge) | `ikrl-ai`, `ikrl-fs`, `ikrl-federation`, `ikrl-bridge` |
//!
//! `ikrl-init` boots the kernel (always) and utilities (optional). The shell is
//! the primary interface a user launches after boot.

use serde::{Deserialize, Serialize};

/// One of the three major IntentOS tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OsLayer {
    /// Core capability kernel — tokens, policy, enforcement table.
    Kernel,
    /// Interactive session — translates user intent into kernel RPCs.
    Shell,
    /// User-space services gated by capabilities.
    Utilities,
}

impl OsLayer {
    pub fn label(self) -> &'static str {
        match self {
            OsLayer::Kernel => "KERNEL",
            OsLayer::Shell => "SHELL",
            OsLayer::Utilities => "UTILITIES",
        }
    }
}

/// A binary that belongs to one OS tier.
#[derive(Debug, Clone, Copy)]
pub struct OsComponent {
    pub name: &'static str,
    pub binary: &'static str,
    pub layer: OsLayer,
    pub default_listen: &'static str,
    pub description: &'static str,
    /// When true, `ikrl-init` starts this process during boot.
    pub boot_daemon: bool,
}

/// Kernel tier — always started by `ikrl-init`.
pub const KERNEL: &[OsComponent] = &[
    OsComponent {
        name: "capd",
        binary: "capd",
        layer: OsLayer::Kernel,
        default_listen: "tcp://127.0.0.1:9101",
        description: "PQC capability token minting and verification",
        boot_daemon: true,
    },
    OsComponent {
        name: "intentd",
        binary: "intentd",
        layer: OsLayer::Kernel,
        default_listen: "tcp://127.0.0.1:9100",
        description: "Intent broker and policy decisions",
        boot_daemon: true,
    },
    OsComponent {
        name: "leasebroker",
        binary: "leasebroker",
        layer: OsLayer::Kernel,
        default_listen: "tcp://127.0.0.1:9102",
        description: "Renewable process lease watchdog",
        boot_daemon: true,
    },
    OsComponent {
        name: "eventscope",
        binary: "eventscope",
        layer: OsLayer::Kernel,
        default_listen: "tcp://127.0.0.1:9103",
        description: "Runtime wrapper and capability table enforcement",
        boot_daemon: true,
    },
];

/// Shell tier — user-launched interactive session (not a background daemon).
pub const SHELL: OsComponent = OsComponent {
    name: "ikrl-shell",
    binary: "ikrl-shell",
    layer: OsLayer::Shell,
    default_listen: "",
    description: "Interactive IntentOS shell — intent, AI, and filesystem commands",
    boot_daemon: false,
};

/// Utility tier — optional services started with `--with-utilities`.
pub const UTILITIES: &[OsComponent] = &[
    OsComponent {
        name: "ikrl-ai",
        binary: "ikrl-ai",
        layer: OsLayer::Utilities,
        default_listen: "tcp://127.0.0.1:9200",
        description: "Capability-gated AI inference and tool-use gateway",
        boot_daemon: true,
    },
    OsComponent {
        name: "ikrl-fs",
        binary: "ikrl-fs",
        layer: OsLayer::Utilities,
        default_listen: "tcp://127.0.0.1:9400",
        description: "Filesystem capability mediator",
        boot_daemon: true,
    },
    OsComponent {
        name: "ikrl-federation",
        binary: "ikrl-federation",
        layer: OsLayer::Utilities,
        default_listen: "tcp://127.0.0.1:9310",
        description: "Cross-device capability discovery and exchange",
        boot_daemon: true,
    },
    OsComponent {
        name: "ikrl-bridge",
        binary: "ikrl-bridge",
        layer: OsLayer::Utilities,
        default_listen: "tcp://127.0.0.1:9300",
        description: "CRASS OS ↔ host IntentKernel IPC bridge",
        boot_daemon: true,
    },
];

/// Default RPC endpoints the shell uses to reach each tier.
#[derive(Debug, Clone)]
pub struct OsEndpoints {
    pub intentd: String,
    pub capd: String,
    pub leasebroker: String,
    pub eventscope: String,
    pub ikrl_ai: String,
    pub ikrl_fs: String,
    pub ikrl_federation: String,
    pub ikrl_bridge: String,
}

impl Default for OsEndpoints {
    fn default() -> Self {
        Self {
            intentd: KERNEL[1].default_listen.to_string(),
            capd: KERNEL[0].default_listen.to_string(),
            leasebroker: KERNEL[2].default_listen.to_string(),
            eventscope: KERNEL[3].default_listen.to_string(),
            ikrl_ai: UTILITIES[0].default_listen.to_string(),
            ikrl_fs: UTILITIES[1].default_listen.to_string(),
            ikrl_federation: UTILITIES[2].default_listen.to_string(),
            ikrl_bridge: UTILITIES[3].default_listen.to_string(),
        }
    }
}

/// ASCII boot banner listing all three tiers.
pub fn boot_banner() -> String {
    let lines = vec![
        String::new(),
        "  ╔══════════════════════════════════════════════════════╗".into(),
        "  ║              IntentOS — AI Capability OS             ║".into(),
        "  ╠══════════════════════════════════════════════════════╣".into(),
        format!("  ║  {:<12} capd · intentd · leasebroker · eventscope ║", "1. KERNEL"),
        format!(
            "  ║  {:<12} {} (interactive session)          ║",
            "2. SHELL",
            SHELL.binary
        ),
        format!(
            "  ║  {:<12} ikrl-ai · ikrl-fs · federation · bridge ║",
            "3. UTILITIES"
        ),
        "  ╚══════════════════════════════════════════════════════╝".into(),
        String::new(),
    ];
    lines.join("\n")
}

/// Components for a given tier.
pub fn components_in(layer: OsLayer) -> Vec<&'static OsComponent> {
    match layer {
        OsLayer::Kernel => KERNEL.iter().collect(),
        OsLayer::Shell => vec![&SHELL],
        OsLayer::Utilities => UTILITIES.iter().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_tiers_are_defined() {
        assert_eq!(KERNEL.len(), 4);
        assert_eq!(UTILITIES.len(), 4);
        assert_eq!(SHELL.layer, OsLayer::Shell);
        assert!(KERNEL.iter().all(|c| c.layer == OsLayer::Kernel));
        assert!(UTILITIES.iter().all(|c| c.layer == OsLayer::Utilities));
    }

    #[test]
    fn kernel_boot_order_starts_with_capd() {
        assert_eq!(KERNEL[0].name, "capd");
    }
}