//! Application compatibility matrix — automated pass/fail for enterprise pilot.

use super::mapper::EnterpriseMapper;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatCase {
    pub name: String,
    pub command: String,
    pub expected_resource: String,
    pub expected_action: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatResult {
    pub name: String,
    pub command: String,
    pub pass: bool,
    pub expected_resource: String,
    pub expected_action: String,
    pub actual_resource: Option<String>,
    pub actual_action: Option<String>,
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatReport {
    pub sector: String,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub pass_rate_pct: u8,
    pub pilot_gate_met: bool,
    pub results: Vec<CompatResult>,
}

pub struct CompatibilityMatrix;

impl CompatibilityMatrix {
    pub fn default_cases() -> Vec<CompatCase> {
        vec![
            CompatCase {
                name: "powershell-list".into(),
                command: "Get-ChildItem C:\\Users".into(),
                expected_resource: "dir".into(),
                expected_action: "list".into(),
            },
            CompatCase {
                name: "powershell-read".into(),
                command: "Get-Content C:\\logs\\app.log".into(),
                expected_resource: "file".into(),
                expected_action: "read".into(),
            },
            CompatCase {
                name: "cmd-dir".into(),
                command: "dir C:\\Windows".into(),
                expected_resource: "dir".into(),
                expected_action: "list".into(),
            },
            CompatCase {
                name: "bash-ls".into(),
                command: "ls /var/log".into(),
                expected_resource: "dir".into(),
                expected_action: "list".into(),
            },
            CompatCase {
                name: "bash-cat".into(),
                command: "cat /etc/hosts".into(),
                expected_resource: "file".into(),
                expected_action: "read".into(),
            },
            CompatCase {
                name: "bash-curl".into(),
                command: "curl https://example.com".into(),
                expected_resource: "network".into(),
                expected_action: "send".into(),
            },
            CompatCase {
                name: "docker-ps".into(),
                command: "docker ps".into(),
                expected_resource: "dir".into(),
                expected_action: "list".into(),
            },
            CompatCase {
                name: "kubectl-get".into(),
                command: "kubectl get pods".into(),
                expected_resource: "dir".into(),
                expected_action: "list".into(),
            },
            CompatCase {
                name: "powershell-process".into(),
                command: "Get-Process".into(),
                expected_resource: "process".into(),
                expected_action: "list".into(),
            },
            CompatCase {
                name: "unmapped-legacy".into(),
                command: "legacy-proprietary-app --start".into(),
                expected_resource: String::new(),
                expected_action: String::new(),
            },
        ]
    }

    pub fn run(cases: &[CompatCase]) -> CompatReport {
        let mut results = Vec::with_capacity(cases.len());
        let mut passed = 0usize;

        for case in cases {
            let mapped = EnterpriseMapper::map(&case.command);
            let negative = case.expected_resource.is_empty();

            let (pass, actual_resource, actual_action, notes) = if negative {
                let ok = mapped.is_none();
                (ok, None, None, "negative case".into())
            } else {
                match mapped {
                    Some(m) => {
                        let ok = m.resource == case.expected_resource
                            && m.action == case.expected_action;
                        (
                            ok,
                            Some(m.resource),
                            Some(m.action),
                            format!("{:?} family", m.shell_family),
                        )
                    }
                    None => (false, None, None, "no mapping".into()),
                }
            };

            if pass {
                passed += 1;
            }

            results.push(CompatResult {
                name: case.name.clone(),
                command: case.command.clone(),
                pass,
                expected_resource: case.expected_resource.clone(),
                expected_action: case.expected_action.clone(),
                actual_resource,
                actual_action,
                notes,
            });
        }

        let total = cases.len();
        let failed = total.saturating_sub(passed);
        let pass_rate_pct = if total == 0 {
            0
        } else {
            ((passed as f64 / total as f64) * 100.0).round() as u8
        };

        CompatReport {
            sector: "enterprise".into(),
            total,
            passed,
            failed,
            pass_rate_pct,
            pilot_gate_met: pass_rate_pct >= 80,
            results,
        }
    }

    pub fn run_default() -> CompatReport {
        Self::run(&Self::default_cases())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matrix_meets_pilot_gate() {
        let report = CompatibilityMatrix::run_default();
        assert!(report.pilot_gate_met, "pass_rate={}", report.pass_rate_pct);
        assert_eq!(report.passed, 10);
    }
}