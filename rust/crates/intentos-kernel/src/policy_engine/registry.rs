//! Rule registry — stores and manages all active policy rules.

use crate::policy_engine::rule::PolicyRule;

/// The set of policy rules active in the kernel.
///
/// Rules are evaluated in registration order by
/// [`evaluate`](super::evaluator::evaluate).  Register stricter (i.e. more
/// likely to deny) rules first to minimise wasted evaluation work on the
/// common allow path.
pub struct RuleRegistry {
    pub rules: Vec<PolicyRule>,
}

impl RuleRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self { rules: vec![] }
    }

    /// Append a rule to the registry.
    pub fn register(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
    }

    /// Number of registered rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// True when no rules have been registered.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

impl Default for RuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_engine::rule::PolicyResult;

    #[test]
    fn empty_registry_has_zero_rules() {
        let r = RuleRegistry::new();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn register_adds_rules_in_order() {
        let mut r = RuleRegistry::new();
        r.register(PolicyRule {
            id: "rule-a".into(),
            description: "first".into(),
            evaluate: |_, _| PolicyResult::Allow { evidence: vec![] },
        });
        r.register(PolicyRule {
            id: "rule-b".into(),
            description: "second".into(),
            evaluate: |_, _| PolicyResult::Allow { evidence: vec![] },
        });
        assert_eq!(r.len(), 2);
        assert_eq!(r.rules[0].id, "rule-a");
        assert_eq!(r.rules[1].id, "rule-b");
    }
}
