//! Policy evaluator — multi-rule evaluation with short-circuit denial.

use crate::policy_engine::evidence::Evidence;
use crate::policy_engine::registry::RuleRegistry;
use crate::policy_engine::rule::PolicyResult;
use crate::syscall_envelope::IkSyscall;
use crate::token_verifier::VerifiedToken;

/// The outcome of evaluating all registered rules against a single syscall.
#[derive(Debug, Clone)]
pub struct IkpeDecision {
    /// Whether the syscall is permitted.
    pub allow: bool,
    /// Collected evidence from every rule that was evaluated.
    pub evidence: Vec<Evidence>,
    /// IDs of every rule evaluated, in evaluation order (for the inspector).
    pub rule_chain: Vec<String>,
    /// Reason string from the denying rule (empty on allow).
    pub deny_reason: String,
}

impl IkpeDecision {
    /// Compact textual summary suitable for audit log fields.
    pub fn summary(&self) -> String {
        if self.allow {
            format!(
                "ALLOW rules=[{}] evidence=[{}]",
                self.rule_chain.join(","),
                self.evidence
                    .iter()
                    .map(|e| e.label())
                    .collect::<Vec<_>>()
                    .join(",")
            )
        } else {
            format!(
                "DENY reason=\"{}\" rules=[{}] evidence=[{}]",
                self.deny_reason,
                self.rule_chain.join(","),
                self.evidence
                    .iter()
                    .map(|e| e.label())
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    }
}

/// Evaluate every registered rule against `token` + `syscall`.
///
/// Rules are evaluated in registration order.  The first [`PolicyResult::Deny`]
/// short-circuits evaluation: no further rules are consulted.  On a successful
/// allow path all evidence is collected and the decision's `allow` field is
/// `true`.
///
/// If the registry is empty the call is **denied** (fail-closed /
/// IntentKernel default-deny). Register rules explicitly to allow traffic.
pub fn evaluate(
    registry: &RuleRegistry,
    token: &VerifiedToken,
    syscall: &IkSyscall,
) -> IkpeDecision {
    if registry.is_empty() {
        return IkpeDecision {
            allow: false,
            evidence: vec![],
            rule_chain: vec![],
            deny_reason: "default-deny: empty rule registry".into(),
        };
    }

    let mut evidence: Vec<Evidence> = Vec::new();
    let mut chain: Vec<String> = Vec::new();

    for rule in &registry.rules {
        let result = (rule.evaluate)(token, syscall);
        chain.push(rule.id.clone());

        match result {
            PolicyResult::Allow { evidence: ev } => {
                evidence.extend(ev);
            }
            PolicyResult::Deny {
                reason,
                evidence: ev,
            } => {
                evidence.extend(ev);
                evidence.push(Evidence::RuleApplied {
                    rule_id: rule.id.clone(),
                });
                return IkpeDecision {
                    allow: false,
                    evidence,
                    rule_chain: chain,
                    deny_reason: reason,
                };
            }
        }
    }

    IkpeDecision {
        allow: true,
        evidence,
        rule_chain: chain,
        deny_reason: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_schema::{FsOp, FsScope, TokenScope};
    use crate::policy_engine::evidence::Evidence;
    use crate::policy_engine::registry::RuleRegistry;
    use crate::policy_engine::rule::{PolicyResult, PolicyRule};
    use crate::syscall_envelope::OpenMode;
    use std::time::{Duration, SystemTime};
    use uuid::Uuid;

    fn test_token() -> VerifiedToken {
        VerifiedToken {
            id: Uuid::new_v4(),
            issued_to: "tester".into(),
            expires_at: SystemTime::now() + Duration::from_secs(3600),
            scope: TokenScope::Fs(FsScope {
                path_prefix: "/tmp".into(),
                ops: vec![FsOp::Read],
            }),
            quota: crate::token_verifier::TokenQuota::unlimited_now(),
        }
    }

    fn open_read() -> IkSyscall {
        IkSyscall::IkOpen {
            path: "/tmp/x.txt".into(),
            mode: OpenMode::Read,
        }
    }

    #[test]
    fn empty_registry_default_denies() {
        let reg = RuleRegistry::new();
        let decision = evaluate(&reg, &test_token(), &open_read());
        assert!(!decision.allow);
        assert!(decision.deny_reason.contains("default-deny"));
        assert!(decision.rule_chain.is_empty());
    }

    #[test]
    fn single_allow_rule_collects_evidence() {
        let mut reg = RuleRegistry::new();
        reg.register(PolicyRule {
            id: "allow-all".into(),
            description: "stub allow".into(),
            evaluate: |_, _| PolicyResult::Allow {
                evidence: vec![Evidence::TTLValid, Evidence::TokenValid],
            },
        });
        let d = evaluate(&reg, &test_token(), &open_read());
        assert!(d.allow);
        assert_eq!(d.rule_chain, vec!["allow-all"]);
        assert!(d.evidence.contains(&Evidence::TTLValid));
        assert!(d.evidence.contains(&Evidence::TokenValid));
    }

    #[test]
    fn single_deny_rule_short_circuits() {
        let mut reg = RuleRegistry::new();
        reg.register(PolicyRule {
            id: "deny-all".into(),
            description: "stub deny".into(),
            evaluate: |_, _| PolicyResult::Deny {
                reason: "nope".into(),
                evidence: vec![Evidence::TTLExpired],
            },
        });
        // This rule would allow — it must never be reached.
        reg.register(PolicyRule {
            id: "allow-all".into(),
            description: "should not run".into(),
            evaluate: |_, _| PolicyResult::Allow { evidence: vec![] },
        });
        let d = evaluate(&reg, &test_token(), &open_read());
        assert!(!d.allow);
        assert_eq!(d.deny_reason, "nope");
        // Only the denying rule appears in the chain.
        assert_eq!(d.rule_chain, vec!["deny-all"]);
        // Evidence includes TTLExpired + RuleApplied.
        assert!(d
            .evidence
            .iter()
            .any(|e| matches!(e, Evidence::RuleApplied { rule_id } if rule_id == "deny-all")));
    }

    #[test]
    fn multiple_allow_rules_accumulate_evidence() {
        let mut reg = RuleRegistry::new();
        reg.register(PolicyRule {
            id: "scope-check".into(),
            description: "scope".into(),
            evaluate: |_, _| PolicyResult::Allow {
                evidence: vec![Evidence::ScopeMatch {
                    scope: "fs:/tmp".into(),
                }],
            },
        });
        reg.register(PolicyRule {
            id: "ttl-check".into(),
            description: "ttl".into(),
            evaluate: |_, _| PolicyResult::Allow {
                evidence: vec![Evidence::TTLValid],
            },
        });
        let d = evaluate(&reg, &test_token(), &open_read());
        assert!(d.allow);
        assert_eq!(d.rule_chain.len(), 2);
        assert!(d
            .evidence
            .iter()
            .any(|e| matches!(e, Evidence::ScopeMatch { .. })));
        assert!(d.evidence.contains(&Evidence::TTLValid));
    }

    #[test]
    fn summary_is_non_empty_for_allow_and_deny() {
        let mut allow_reg = RuleRegistry::new();
        allow_reg.register(PolicyRule {
            id: "allow-all".into(),
            description: "a".into(),
            evaluate: |_, _| PolicyResult::Allow {
                evidence: vec![Evidence::TTLValid],
            },
        });
        let allow_d = evaluate(&allow_reg, &test_token(), &open_read());
        assert!(allow_d.summary().contains("ALLOW"));

        let mut deny_reg = RuleRegistry::new();
        deny_reg.register(PolicyRule {
            id: "deny-all".into(),
            description: "d".into(),
            evaluate: |_, _| PolicyResult::Deny {
                reason: "blocked".into(),
                evidence: vec![],
            },
        });
        let deny_d = evaluate(&deny_reg, &test_token(), &open_read());
        assert!(deny_d.summary().contains("DENY"));
        assert!(deny_d.summary().contains("blocked"));
    }
}
