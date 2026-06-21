//! IP-Discrambler bridge — invokes the Python toolchain from IntentOS utilities tier.

use intentos_audit::{AuditEventKind, AuditLog};
use intentos_kernel::{
    evaluate_ip, verdict_from_threat_score, Intent, PolicyDecision, PolicyEngine, TrustAnchor,
    wall_ms,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;

/// Resolved IP enrichment payload from the Python bridge.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IpLookupResult {
    pub ip: String,
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub city: Option<String>,
    pub asn: Option<String>,
    pub org: Option<String>,
    pub isp: Option<String>,
    pub reverse_dns: Option<String>,
    pub threat_score: u8,
    pub abuse_confidence: u8,
    #[serde(default)]
    pub errors: Vec<String>,
}

/// Policy verdict combining local kernel rules and optional enrichment.
#[derive(Debug, Clone)]
pub struct IpPolicyVerdict {
    pub ip: String,
    pub allowed: bool,
    pub threat_score: u8,
    pub reason: String,
    pub enrichment: Option<IpLookupResult>,
    pub kernel: PolicyDecision,
}

#[derive(Debug, Error)]
pub enum IpDiscramblerError {
    #[error("IP-Discrambler root not found — set INTENTOS_IP_DISCRAMBLER_ROOT")]
    RootNotFound,
    #[error("python executable not found — set INTENTOS_PYTHON")]
    PythonNotFound,
    #[error("bridge failed: {0}")]
    BridgeFailed(String),
    #[error("invalid bridge JSON: {0}")]
    InvalidJson(String),
}

/// Bridge to `tools/ip-discrambler` Python package.
#[derive(Debug, Clone)]
pub struct IpDiscramblerBridge {
    root: PathBuf,
    python: String,
}

impl IpDiscramblerBridge {
    pub fn discover() -> Result<Self, IpDiscramblerError> {
        let root = resolve_root().ok_or(IpDiscramblerError::RootNotFound)?;
        let python = std::env::var("INTENTOS_PYTHON").unwrap_or_else(|_| {
            if cfg!(windows) {
                "python".into()
            } else {
                "python3".into()
            }
        });
        Ok(Self { root, python })
    }

    pub fn from_root(root: PathBuf) -> Self {
        let python = std::env::var("INTENTOS_PYTHON").unwrap_or_else(|_| "python".into());
        Self { root, python }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn lookup(&self, ip: &str) -> Result<IpLookupResult, IpDiscramblerError> {
        let value = self.run_bridge("lookup", ip)?;
        serde_json::from_value(value).map_err(|e| IpDiscramblerError::InvalidJson(e.to_string()))
    }

    pub fn subnet_json(&self, cidr: &str) -> Result<Value, IpDiscramblerError> {
        self.run_bridge("subnet", cidr)
    }

    pub fn policy_check(&self, ip: &str, actor: &str) -> Result<IpPolicyVerdict, IpDiscramblerError> {
        let local = evaluate_ip(ip);
        let enrichment = self.lookup(ip).ok();

        let mut metadata = BTreeMap::new();
        metadata.insert("dest_ip".into(), ip.into());
        if let Some(ref e) = enrichment {
            metadata.insert("threat_score".into(), e.threat_score.to_string());
        }

        let intent = Intent {
            actor: actor.into(),
            resource: "network".into(),
            action: "descramble".into(),
            anchor: TrustAnchor::UiEvent,
            timestamp_ms: wall_ms(),
            metadata,
        };

        let kernel = PolicyEngine::evaluate(&intent);
        let threat_score = enrichment.as_ref().map(|e| e.threat_score).unwrap_or(0);
        let threat_verdict = verdict_from_threat_score(ip, threat_score);

        let allowed = local.allowed && kernel.allowed && threat_verdict.allowed;
        let reason = if !local.allowed {
            local.reason
        } else if !threat_verdict.allowed {
            threat_verdict.reason
        } else if !kernel.allowed {
            kernel.reason.clone()
        } else if threat_score >= 50 {
            format!("elevated threat score {threat_score}")
        } else {
            "allowed".into()
        };

        Ok(IpPolicyVerdict {
            ip: ip.into(),
            allowed,
            threat_score,
            reason,
            enrichment,
            kernel,
        })
    }

    pub fn policy_check_local(&self, ip: &str, actor: &str) -> IpPolicyVerdict {
        let local = evaluate_ip(ip);
        let mut metadata = BTreeMap::new();
        metadata.insert("dest_ip".into(), ip.into());
        let intent = Intent {
            actor: actor.into(),
            resource: "network".into(),
            action: "descramble".into(),
            anchor: TrustAnchor::UiEvent,
            timestamp_ms: wall_ms(),
            metadata,
        };
        let kernel = PolicyEngine::evaluate(&intent);
        let allowed = local.allowed && kernel.allowed;
        let reason = if !local.allowed {
            local.reason
        } else {
            kernel.reason.clone()
        };
        IpPolicyVerdict {
            ip: ip.into(),
            allowed,
            threat_score: 0,
            reason,
            enrichment: None,
            kernel,
        }
    }

    pub fn serve(&self, host: &str, port: u16) -> Result<std::process::Child, IpDiscramblerError> {
        let src = self.root.join("src");
        let child = Command::new(&self.python)
            .current_dir(&self.root)
            .env("PYTHONPATH", &src)
            .args([
                "-m",
                "ip_discrambler.cli",
                "serve",
                "--host",
                host,
                "--port",
                &port.to_string(),
            ])
            .spawn()
            .map_err(|e| IpDiscramblerError::BridgeFailed(e.to_string()))?;
        Ok(child)
    }

    pub fn audit_lookup(&self, ip: &str, actor: &str, audit: &AuditLog) -> Result<IpLookupResult, IpDiscramblerError> {
        let result = self.lookup(ip)?;
        let _ = audit.record(
            AuditEventKind::SectorMap,
            actor,
            format!(
                "ip-discrambler `{}` country={:?} threat={}",
                result.ip, result.country, result.threat_score
            ),
        );
        Ok(result)
    }

    fn run_bridge(&self, command: &str, arg: &str) -> Result<Value, IpDiscramblerError> {
        let src = self.root.join("src");
        let output = Command::new(&self.python)
            .current_dir(&self.root)
            .env("PYTHONPATH", &src)
            .args(["-m", "ip_discrambler.bridge", command, arg])
            .output()
            .map_err(|e| IpDiscramblerError::BridgeFailed(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(IpDiscramblerError::BridgeFailed(stderr.trim().into()));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        serde_json::from_str(&stdout).map_err(|e| IpDiscramblerError::InvalidJson(e.to_string()))
    }
}

pub fn resolve_root() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("INTENTOS_IP_DISCRAMBLER_ROOT") {
        let p = PathBuf::from(path);
        if p.join("pyproject.toml").exists() {
            return Some(p);
        }
    }

    let mut dir = std::env::current_dir().ok()?;
    for _ in 0..10 {
        let candidate = dir.join("tools").join("ip-discrambler");
        if candidate.join("pyproject.toml").exists() {
            return Some(candidate);
        }
        if !dir.pop() {
            break;
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_root_from_workspace() {
        if let Some(root) = resolve_root() {
            assert!(root.join("src").join("ip_discrambler").exists());
        }
    }

    #[test]
    fn local_policy_blocks_bogon() {
        let bridge = IpDiscramblerBridge::from_root(PathBuf::from("."));
        let verdict = bridge.policy_check_local("192.0.2.1", "tester");
        assert!(!verdict.allowed);
    }
}