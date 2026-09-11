//! Evidence produced by policy rules — the building block of explainability.

/// Structured evidence emitted by a policy rule evaluation.
///
/// Each variant captures *why* a rule allowed or denied a syscall.  The full
/// evidence chain is surfaced by the Policy Inspector and stored in audit logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Evidence {
    // ── Scope ────────────────────────────────────────────────────────────────
    /// The syscall target is covered by this scope.
    ScopeMatch { scope: String },
    /// The syscall target falls outside this scope.
    ScopeMismatch { scope: String },

    // ── Quota ────────────────────────────────────────────────────────────────
    /// Quota headroom remaining after this call.
    QuotaRemaining { bytes: u64, requests: u64 },
    /// A quota limit has been reached.
    QuotaExceeded { field: String },

    // ── TTL / Expiry ─────────────────────────────────────────────────────────
    /// Token lifetime is still within the allowed window.
    TTLValid,
    /// Token lifetime has lapsed.
    TTLExpired,

    // ── Token integrity ──────────────────────────────────────────────────────
    /// Token fields verified successfully.
    TokenValid,
    /// Token has expired (clock-based).
    TokenExpired,

    // ── Rule trace ───────────────────────────────────────────────────────────
    /// Records which rule was applied (always appended on denial).
    RuleApplied { rule_id: String },

    // ── Sandbox ──────────────────────────────────────────────────────────────
    /// Syscall originates from an isolated sandbox context.
    SandboxIsolated,
    /// Syscall originates from an unrestricted context; sandbox rules may deny.
    SandboxUnisolated,

    // ── Federation ───────────────────────────────────────────────────────────
    /// Remote kernel trust verified against the federation policy.
    FederationTrusted { peer: String },
    /// Remote kernel not present in the federation trust list.
    FederationUntrusted { peer: String },
    /// Policy hash matches the cluster-agreed value.
    PolicyHashMatch,
    /// Policy hash diverges from the cluster-agreed value.
    PolicyHashMismatch,
}

impl Evidence {
    /// Short label used in log / inspector output.
    pub fn label(&self) -> &'static str {
        match self {
            Evidence::ScopeMatch { .. } => "scope_match",
            Evidence::ScopeMismatch { .. } => "scope_mismatch",
            Evidence::QuotaRemaining { .. } => "quota_remaining",
            Evidence::QuotaExceeded { .. } => "quota_exceeded",
            Evidence::TTLValid => "ttl_valid",
            Evidence::TTLExpired => "ttl_expired",
            Evidence::TokenValid => "token_valid",
            Evidence::TokenExpired => "token_expired",
            Evidence::RuleApplied { .. } => "rule_applied",
            Evidence::SandboxIsolated => "sandbox_isolated",
            Evidence::SandboxUnisolated => "sandbox_unisolated",
            Evidence::FederationTrusted { .. } => "federation_trusted",
            Evidence::FederationUntrusted { .. } => "federation_untrusted",
            Evidence::PolicyHashMatch => "policy_hash_match",
            Evidence::PolicyHashMismatch => "policy_hash_mismatch",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_non_empty() {
        let samples = [
            Evidence::ScopeMatch {
                scope: "fs:/tmp".into(),
            },
            Evidence::ScopeMismatch {
                scope: "net:example.com".into(),
            },
            Evidence::QuotaRemaining {
                bytes: 1024,
                requests: 10,
            },
            Evidence::QuotaExceeded {
                field: "bytes".into(),
            },
            Evidence::TTLValid,
            Evidence::TTLExpired,
            Evidence::TokenValid,
            Evidence::TokenExpired,
            Evidence::RuleApplied {
                rule_id: "ttl-check".into(),
            },
            Evidence::SandboxIsolated,
            Evidence::SandboxUnisolated,
            Evidence::FederationTrusted {
                peer: "node-a".into(),
            },
            Evidence::FederationUntrusted {
                peer: "node-b".into(),
            },
            Evidence::PolicyHashMatch,
            Evidence::PolicyHashMismatch,
        ];
        for e in &samples {
            assert!(!e.label().is_empty());
        }
    }
}
