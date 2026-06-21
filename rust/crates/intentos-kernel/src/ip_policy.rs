//! IP policy enforcement for network-scoped intents (IP-Discrambler integration).

use crate::types::{Intent, PolicyDecision};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub const META_DEST_IP: &str = "dest_ip";
pub const META_THREAT_SCORE: &str = "threat_score";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpVerdict {
    pub ip: String,
    pub allowed: bool,
    pub threat: ThreatLevel,
    pub reason: String,
}

pub fn evaluate_ip(ip: &str) -> IpVerdict {
    let trimmed = ip.trim();
    match trimmed.parse::<IpAddr>() {
        Ok(addr) => evaluate_parsed(addr, trimmed),
        Err(_) => IpVerdict {
            ip: trimmed.to_string(),
            allowed: false,
            threat: ThreatLevel::High,
            reason: "invalid IP address".into(),
        },
    }
}

fn evaluate_parsed(addr: IpAddr, raw: &str) -> IpVerdict {
    if addr.is_unspecified() || addr.is_loopback() {
        return IpVerdict {
            ip: raw.to_string(),
            allowed: true,
            threat: ThreatLevel::Low,
            reason: "loopback/unspecified allowed for local development".into(),
        };
    }

    if is_bogon(addr) {
        return IpVerdict {
            ip: raw.to_string(),
            allowed: false,
            threat: ThreatLevel::Critical,
            reason: "bogon/reserved address blocked".into(),
        };
    }

    if addr.is_multicast() {
        return IpVerdict {
            ip: raw.to_string(),
            allowed: false,
            threat: ThreatLevel::High,
            reason: "multicast destination blocked".into(),
        };
    }

    IpVerdict {
        ip: raw.to_string(),
        allowed: true,
        threat: ThreatLevel::Low,
        reason: "public unicast".into(),
    }
}

/// Apply threat score from IP-Discrambler (0–100). Scores ≥ 75 are blocked.
pub fn verdict_from_threat_score(ip: &str, score: u8) -> IpVerdict {
    let mut v = evaluate_ip(ip);
    if !v.allowed {
        return v;
    }
    v.threat = match score {
        0..=24 => ThreatLevel::Low,
        25..=49 => ThreatLevel::Medium,
        50..=74 => ThreatLevel::High,
        _ => ThreatLevel::Critical,
    };
    if score >= 75 {
        v.allowed = false;
        v.reason = format!("IP-Discrambler threat score {score} exceeds policy threshold");
    } else if score >= 50 {
        v.reason = format!("elevated threat score {score}; confirmation recommended");
    }
    v
}

pub fn extract_ipv4_literals(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            if let Some(end) = scan_ipv4_end(bytes, i) {
                let candidate = &text[i..end];
                if candidate.parse::<IpAddr>().is_ok() {
                    out.push(candidate.to_string());
                }
                i = end;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn scan_ipv4_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut dots = 0u8;
    let mut end = start;
    while end < bytes.len() {
        let b = bytes[end];
        if b.is_ascii_digit() {
            end += 1;
            continue;
        }
        if b == b'.' && dots < 3 {
            dots += 1;
            end += 1;
            continue;
        }
        break;
    }
    if dots == 3 && end > start {
        Some(end)
    } else {
        None
    }
}

fn is_bogon(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            matches!(
                o,
                [0, _, _, _]
                    | [10, _, _, _]
                    | [100, 64..=127, _, _]
                    | [127, _, _, _]
                    | [169, 254, _, _]
                    | [172, 16..=31, _, _]
                    | [192, 0, 0, _]
                    | [192, 0, 2, _]
                    | [192, 88, 99, _]
                    | [192, 168, _, _]
                    | [198, 18..=19, _, _]
                    | [198, 51, 100, _]
                    | [203, 0, 113, _]
                    | [224, _, _, _]
                    | [240, _, _, _]
                    | [255, 255, 255, 255]
            )
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unique_local()
                || is_documentation_v6(v6)
        }
    }
}

fn is_documentation_v6(addr: std::net::Ipv6Addr) -> bool {
    let segments = addr.segments();
    segments[0] == 0x2001 && segments[1] == 0x0db8
}

pub fn apply_ip_policy(intent: &Intent, mut base: PolicyDecision) -> PolicyDecision {
    let is_network = intent.resource == "network"
        || intent.action == "descramble"
        || intent.metadata.contains_key(META_DEST_IP);

    if !is_network || !base.allowed {
        return base;
    }

    let ips: Vec<String> = intent
        .metadata
        .get(META_DEST_IP)
        .map(|s| vec![s.clone()])
        .unwrap_or_default();

    for ip in ips {
        let verdict = if let Some(score) = intent
            .metadata
            .get(META_THREAT_SCORE)
            .and_then(|s| s.parse::<u8>().ok())
        {
            verdict_from_threat_score(&ip, score)
        } else {
            evaluate_ip(&ip)
        };

        if !verdict.allowed {
            base.allowed = false;
            base.reason = format!("IP policy: {} — {}", verdict.ip, verdict.reason);
            base.ttl_ms = 0;
            base.max_uses = 0;
            return base;
        }
        if verdict.threat == ThreatLevel::High || verdict.threat == ThreatLevel::Medium {
            base.reason = format!("IP policy: {} — {}", verdict.ip, verdict.reason);
        }
    }

    base
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Intent, TrustAnchor, wall_ms};
    use std::collections::BTreeMap;

    #[test]
    fn blocks_bogon_ipv4() {
        let v = evaluate_ip("192.0.2.1");
        assert!(!v.allowed);
        assert_eq!(v.threat, ThreatLevel::Critical);
    }

    #[test]
    fn allows_public_ip() {
        let v = evaluate_ip("8.8.8.8");
        assert!(v.allowed);
    }

    #[test]
    fn threat_score_blocks_high_risk() {
        let v = verdict_from_threat_score("8.8.8.8", 90);
        assert!(!v.allowed);
    }

    #[test]
    fn network_policy_denies_reserved_dest() {
        let mut meta = BTreeMap::new();
        meta.insert(META_DEST_IP.into(), "192.0.2.55".into());
        let intent = Intent {
            actor: "app".into(),
            resource: "network".into(),
            action: "send".into(),
            anchor: TrustAnchor::UiEvent,
            timestamp_ms: wall_ms(),
            metadata: meta,
        };
        let base = PolicyDecision {
            allowed: true,
            reason: "ok".into(),
            ttl_ms: 1000,
            max_uses: 1,
        };
        let out = apply_ip_policy(&intent, base);
        assert!(!out.allowed);
    }
}