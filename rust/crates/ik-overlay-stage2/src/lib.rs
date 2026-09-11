//! # Stage 2 — Linux LSM / eBPF overlay foundations
//!
//! Userspace **token gate** that Stage-2 hooks would call after intercepting
//! file / network / exec operations. Backed by [`intentos_kernel::Kernel`] so
//! Linux CI can exercise allow/deny without loading a kernel module.
//!
//! See `docs/overlay/stage2-linux-lsm.md` and `overlay/linux/lsm_stub/`.

use intentos_kernel::{
    wall_ms, Intent, Kernel, SyscallOp, SyscallRequest, SyscallResult, Token, TrustAnchor,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;

/// LSM / eBPF hook kinds Stage 2 targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum HookKind {
    FileOpen = 1,
    SocketConnect = 2,
    BprmCheck = 3,
}

impl HookKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FileOpen => "file_open",
            Self::SocketConnect => "socket_connect",
            Self::BprmCheck => "bprm_check",
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GateError {
    #[error("denied: {0}")]
    Denied(String),
    #[error("missing capability for hook {0}")]
    MissingCapability(&'static str),
    #[error("kernel: {0}")]
    Kernel(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateVerdict {
    Allow { remaining_uses: u32 },
    Deny { reason: String },
}

/// Userspace overlay gate — prototype stand-in for LSM/eBPF decision path.
pub struct OverlayGate {
    kernel: Arc<Kernel>,
    actor: String,
}

impl OverlayGate {
    pub fn new(kernel: Arc<Kernel>, actor: impl Into<String>) -> Self {
        Self {
            kernel,
            actor: actor.into(),
        }
    }

    pub fn boot(actor: impl Into<String>) -> Result<Self, GateError> {
        let kernel = Kernel::boot().map_err(|e| GateError::Kernel(e.to_string()))?;
        Ok(Self::new(Arc::new(kernel), actor))
    }

    pub fn kernel(&self) -> &Kernel {
        &self.kernel
    }

    fn mint(&self, resource: &str, action: &str) -> Result<Token, GateError> {
        let intent = Intent {
            actor: self.actor.clone(),
            resource: resource.into(),
            action: action.into(),
            anchor: TrustAnchor::UiEvent,
            timestamp_ms: wall_ms(),
            metadata: Default::default(),
        };
        let decision = self.kernel.submit_intent(intent.clone());
        if !decision.allowed {
            return Err(GateError::Denied(decision.reason));
        }
        self.kernel
            .mint_token_confirmed(intent, true)
            .map_err(|e| GateError::Denied(e.to_string()))
    }

    /// Issue a capability appropriate for `hook` (broker side).
    pub fn issue_for_hook(&self, hook: HookKind) -> Result<Token, GateError> {
        match hook {
            HookKind::FileOpen => self.mint("file", "read"),
            HookKind::SocketConnect => self.mint("network", "send"),
            HookKind::BprmCheck => {
                // Exec mediation: reuse lease/background as stand-in until
                // a dedicated exec capability lands in policy.
                self.mint("lease", "background")
            }
        }
    }

    /// Check an intercepted operation using a previously minted token.
    pub fn check(
        &self,
        hook: HookKind,
        token: &Token,
        target: &str,
    ) -> Result<GateVerdict, GateError> {
        let handle = match self.kernel.register_token(token.clone()) {
            Ok(h) => h,
            Err(e) => {
                return Ok(GateVerdict::Deny {
                    reason: e.to_string(),
                })
            }
        };

        let (op, expected_resource) = match hook {
            HookKind::FileOpen => (SyscallOp::Read, "file"),
            HookKind::SocketConnect => (SyscallOp::Send, "network"),
            HookKind::BprmCheck => {
                // Table has no Exec op yet — treat as lease tick via Infer denial
                // unless scope is lease/background: use List as non-match → deny
                // unless we map lease to a no-op allow via synthetic path.
                // Practical prototype: require scope lease/background and allow
                // without table op by checking scope only.
                if token.scope.resource != "lease" || token.scope.action != "background" {
                    return Ok(GateVerdict::Deny {
                        reason: "bprm_check requires lease/background capability".into(),
                    });
                }
                // Burn one use via revoke simulation: register already consumed
                // replay protection; mark allow with uses from token.
                let uses = token.uses.saturating_sub(1);
                let _ = handle;
                return Ok(GateVerdict::Allow {
                    remaining_uses: uses,
                });
            }
        };

        if token.scope.resource != expected_resource {
            return Ok(GateVerdict::Deny {
                reason: format!(
                    "scope mismatch: token {}/{} for hook {}",
                    token.scope.resource,
                    token.scope.action,
                    hook.as_str()
                ),
            });
        }

        match self.kernel.syscall(
            handle,
            SyscallRequest {
                op,
                target: target.to_string(),
                payload: vec![],
            },
        ) {
            SyscallResult::Allowed { remaining_uses, .. } => {
                Ok(GateVerdict::Allow { remaining_uses })
            }
            SyscallResult::Denied(reason) => Ok(GateVerdict::Deny { reason }),
        }
    }

    /// Deny path when interceptor sees no token.
    pub fn missing_token(hook: HookKind) -> GateVerdict {
        GateVerdict::Deny {
            reason: format!("no capability for {}", hook.as_str()),
        }
    }
}

/// Simulated eBPF map entry (design aid for future programs).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BpfTokenMapEntry {
    pub pid: u32,
    pub jti: String,
    pub exp_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_open_allows_with_token_denies_without() {
        let gate = OverlayGate::boot("overlay").unwrap();
        assert_eq!(
            OverlayGate::missing_token(HookKind::FileOpen),
            GateVerdict::Deny {
                reason: "no capability for file_open".into()
            }
        );
        let tok = gate.issue_for_hook(HookKind::FileOpen).unwrap();
        let v = gate.check(HookKind::FileOpen, &tok, "/tmp/x").unwrap();
        assert!(matches!(v, GateVerdict::Allow { remaining_uses: 0 }));
        // replay denied
        let v2 = gate.check(HookKind::FileOpen, &tok, "/tmp/x").unwrap();
        assert!(
            matches!(v2, GateVerdict::Deny { .. }),
            "replay must deny: {v2:?}"
        );
    }

    #[test]
    fn socket_connect_requires_network_cap() {
        let gate = OverlayGate::boot("overlay").unwrap();
        let file_tok = gate.issue_for_hook(HookKind::FileOpen).unwrap();
        let v = gate
            .check(HookKind::SocketConnect, &file_tok, "93.184.216.34:443")
            .unwrap();
        assert!(matches!(v, GateVerdict::Deny { .. }));

        let net = gate.issue_for_hook(HookKind::SocketConnect).unwrap();
        let v = gate
            .check(HookKind::SocketConnect, &net, "example.com:443")
            .unwrap();
        assert!(matches!(v, GateVerdict::Allow { .. }));
    }

    #[test]
    fn bprm_check_lease_background() {
        let gate = OverlayGate::boot("overlay").unwrap();
        let tok = gate.issue_for_hook(HookKind::BprmCheck).unwrap();
        let v = gate
            .check(HookKind::BprmCheck, &tok, "/usr/bin/id")
            .unwrap();
        assert!(matches!(v, GateVerdict::Allow { .. }));
    }

    #[test]
    fn hook_kind_names() {
        assert_eq!(HookKind::FileOpen.as_str(), "file_open");
        assert_eq!(HookKind::SocketConnect.as_str(), "socket_connect");
        assert_eq!(HookKind::BprmCheck.as_str(), "bprm_check");
    }
}
