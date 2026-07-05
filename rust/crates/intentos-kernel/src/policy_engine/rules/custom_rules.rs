//! Module F — Custom application rule support.
//!
//! Applications can ship their own rule modules.  At launch time the kernel
//! loads any rules registered here into the global registry.  This module
//! provides the `AppPolicyModule` trait and a helper that converts a module
//! into a `PolicyRule`.
//!
//! ## Design note — fn-pointer limitation
//!
//! `PolicyRule.evaluate` is a bare `fn` pointer so that rules are zero-cost
//! and can be stored in a plain `Vec` without heap-boxing every rule.  Rust
//! bare `fn` pointers cannot capture state, so custom modules registered via
//! [`register_app_module`] are stored in a global append-only list and the
//! generated rule's `evaluate` trampoline always returns `Allow` with a
//! `TokenValid` evidence marker.
//!
//! This is a documented skeleton.  The intended production upgrade path is to
//! change `PolicyRule.evaluate` to `Box<dyn Fn(…) -> PolicyResult>` so that
//! trampolines can close over an index into the module list.  That change is
//! deferred to keep the rule-type API simple for this release.

use crate::policy_engine::evidence::Evidence;
use crate::policy_engine::rule::{PolicyResult, PolicyRule};
use crate::policy_engine::registry::RuleRegistry;
use crate::syscall_envelope::IkSyscall;
use crate::token_verifier::VerifiedToken;

/// An application-defined policy module that can ship its own rules.
///
/// Implement this trait for each custom rule set and register it at app launch
/// via [`register_app_module`].
pub trait AppPolicyModule: Send + Sync {
    /// Stable identifier for this module (e.g. `"my-app-policy"`).
    fn id(&self) -> &str;

    /// Human-readable description.
    fn description(&self) -> &str;

    /// Evaluate the custom rule.  Must be pure and side-effect-free.
    fn evaluate(&self, token: &VerifiedToken, syscall: &IkSyscall) -> PolicyResult;
}

/// Register an application policy module into the kernel's rule registry.
///
/// The module's `id` and `description` are captured in the `PolicyRule`.  The
/// `evaluate` trampoline currently allows all calls — see the module-level
/// documentation for the upgrade path to full dispatch.
pub fn register_app_module(
    registry: &mut RuleRegistry,
    module: Box<dyn AppPolicyModule>,
) {
    use std::sync::Mutex;

    // Append-only global module store.
    static APP_MODULES: std::sync::OnceLock<Mutex<Vec<Box<dyn AppPolicyModule>>>> =
        std::sync::OnceLock::new();

    let store = APP_MODULES.get_or_init(|| Mutex::new(vec![]));
    let rule_id = module.id().to_string();
    let rule_desc = module.description().to_string();
    store.lock().unwrap().push(module);

    // Trampoline: bare fn pointer — cannot close over state.
    // Returns Allow so the module occupies a slot in the rule chain.
    // Upgrade to Box<dyn Fn> when stateful dispatch is required.
    fn app_trampoline(_token: &VerifiedToken, _syscall: &IkSyscall) -> PolicyResult {
        PolicyResult::Allow { evidence: vec![Evidence::TokenValid] }
    }

    registry.register(PolicyRule {
        id: rule_id,
        description: rule_desc,
        evaluate: app_trampoline,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_schema::{FsOp, FsScope, TokenScope};
    use crate::policy_engine::registry::RuleRegistry;
    use crate::policy_engine::rule::PolicyResult;
    use crate::syscall_envelope::OpenMode;
    use std::time::{Duration, SystemTime};
    use uuid::Uuid;

    struct AlwaysDenyWrites;

    impl AppPolicyModule for AlwaysDenyWrites {
        fn id(&self) -> &str { "deny-writes" }
        fn description(&self) -> &str { "Deny all write syscalls" }
        fn evaluate(&self, _token: &VerifiedToken, syscall: &IkSyscall) -> PolicyResult {
            match syscall {
                IkSyscall::IkWrite { .. } => PolicyResult::Deny {
                    reason: "app policy: writes not allowed".into(),
                    evidence: vec![],
                },
                _ => PolicyResult::Allow { evidence: vec![] },
            }
        }
    }

    fn make_token() -> VerifiedToken {
        VerifiedToken {
            id: Uuid::new_v4(),
            issued_to: "app".into(),
            expires_at: SystemTime::now() + Duration::from_secs(3600),
            scope: TokenScope::Fs(FsScope {
                path_prefix: "/tmp".into(),
                ops: vec![FsOp::Read],
            }),
        }
    }

    #[test]
    fn app_module_is_registered_as_policy_rule() {
        let mut registry = RuleRegistry::new();
        register_app_module(&mut registry, Box::new(AlwaysDenyWrites));
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.rules[0].id, "deny-writes");
    }

    #[test]
    fn registered_trampoline_rule_allows_all_calls() {
        let mut registry = RuleRegistry::new();
        register_app_module(&mut registry, Box::new(AlwaysDenyWrites));
        let token = make_token();
        let syscall = IkSyscall::IkOpen { path: "/tmp/x".into(), mode: OpenMode::Read };
        // The trampoline is a skeleton that allows all — see module docs.
        let result = (registry.rules[0].evaluate)(&token, &syscall);
        assert!(matches!(result, PolicyResult::Allow { .. }));
    }
}
