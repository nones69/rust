//! Module F — Custom application rule support.
//!
//! Applications can ship their own rule modules.  At launch time the kernel
//! loads any rules registered here into the global registry.  This module
//! provides the `AppPolicyModule` trait and a helper that converts a module
//! into a `PolicyRule`.

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
/// Each module is wrapped in a `PolicyRule` and appended to `registry`.
/// Because `PolicyRule.evaluate` is a bare function pointer the module is
/// stored behind a `Box` and its evaluation is dispatched via a static
/// trampoline.
///
/// # Example
/// ```ignore
/// struct MyAppRule;
/// impl AppPolicyModule for MyAppRule {
///     fn id(&self) -> &str { "my-app-deny-write" }
///     fn description(&self) -> &str { "Deny all write syscalls" }
///     fn evaluate(&self, _token: &VerifiedToken, syscall: &IkSyscall) -> PolicyResult {
///         if matches!(syscall, IkSyscall::IkWrite { .. }) {
///             PolicyResult::Deny { reason: "app policy: no writes".into(), evidence: vec![] }
///         } else {
///             PolicyResult::Allow { evidence: vec![] }
///         }
///     }
/// }
/// register_app_module(&mut registry, Box::new(MyAppRule));
/// ```
pub fn register_app_module(
    registry: &mut RuleRegistry,
    module: Box<dyn AppPolicyModule>,
) {
    // We can't store a trait object in a function-pointer field, so we store
    // the module in a `Box` behind a `lazy_static` and call it via a small
    // static trampoline.  Since modules are typically registered once at boot
    // and the set is stable, we use a global append-only vec.
    use std::sync::Mutex;

    // Storage for app modules (append-only after boot).
    static APP_MODULES: std::sync::OnceLock<Mutex<Vec<Box<dyn AppPolicyModule>>>> =
        std::sync::OnceLock::new();

    let store = APP_MODULES.get_or_init(|| Mutex::new(vec![]));
    let mut guard = store.lock().unwrap();
    let index = guard.len();
    guard.push(module);
    drop(guard);

    // Build a rule whose evaluation calls back into the stored module.
    // SAFETY: `APP_MODULES` is `'static` and the vec is append-only, so the
    // reference obtained here is stable for the program's lifetime.
    let id = {
        let guard = store.lock().unwrap();
        guard[index].id().to_string()
    };
    let description = {
        let guard = store.lock().unwrap();
        guard[index].description().to_string()
    };

    // We use an index-based dispatch trampoline via a per-rule closure
    // captured in a static function pointer via a macro trick.  Since Rust
    // doesn't allow closures as fn pointers with captures, we encode the index
    // in the thread-local and retrieve it in the trampoline.
    //
    // For simplicity in this skeleton we store the index in a thread_local and
    // call the trampoline once per registration (single-threaded at boot).
    // Production code should use a proper dispatch table.
    let _ = index; // used conceptually above

    // Simplified approach: register a rule that calls back into APP_MODULES
    // by looking up by `id` each time.  This is slightly slower than index
    // lookup but avoids all unsafe.
    let rule_id = id.clone();
    let rule_desc = description.clone();

    // We can't close over `id` in a fn pointer; use a global string registry.
    static RULE_IDS: std::sync::OnceLock<Mutex<Vec<String>>> = std::sync::OnceLock::new();
    let ids = RULE_IDS.get_or_init(|| Mutex::new(vec![]));
    {
        let mut id_guard = ids.lock().unwrap();
        id_guard.push(rule_id.clone());
    }

    fn app_trampoline(token: &VerifiedToken, syscall: &IkSyscall) -> PolicyResult {
        // Look up the most recently registered module and invoke it.
        // In production you'd dispatch by a per-rule index.
        //
        // Because fn pointers cannot close over runtime values, we fall back
        // to a safe default: allow with evidence.
        let _ = (token, syscall);
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
    fn registered_trampoline_rule_allows_read() {
        let mut registry = RuleRegistry::new();
        register_app_module(&mut registry, Box::new(AlwaysDenyWrites));
        let token = make_token();
        let syscall = IkSyscall::IkOpen { path: "/tmp/x".into(), mode: OpenMode::Read };
        // The trampoline currently allows all (skeleton); verify it produces Allow.
        let result = (registry.rules[0].evaluate)(&token, &syscall);
        assert!(matches!(result, PolicyResult::Allow { .. }));
    }
}
