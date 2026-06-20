//! CRASS OS ↔ IntentKernel host protocol bridge.
//!
//! Maps CRASS IPC channel slots and message types to the JSON-RPC transport
//! used by `capd`, `intentd`, `leasebroker`, and `eventscope`.

use anyhow::{anyhow, Result};
use intentkernel_core::{default_policy, IntentEvent, TrustAnchor};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// CRASS IPC channel slot → host daemon address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrassChannel {
    Capd = 1,
    Intentd = 2,
    Leasebroker = 3,
    Eventscope = 4,
    IpDescrambler = 12,
}

impl CrassChannel {
    pub fn from_slot(slot: u64) -> Option<Self> {
        match slot {
            1 => Some(Self::Capd),
            2 => Some(Self::Intentd),
            3 => Some(Self::Leasebroker),
            4 => Some(Self::Eventscope),
            12 => Some(Self::IpDescrambler),
            _ => None,
        }
    }

    pub fn default_host_addr(self) -> &'static str {
        match self {
            Self::Capd => "127.0.0.1:9101",
            Self::Intentd => "127.0.0.1:9100",
            Self::Leasebroker => "127.0.0.1:9102",
            Self::Eventscope => "127.0.0.1:9103",
            Self::IpDescrambler => "127.0.0.1:9100",
        }
    }
}

/// Wire envelope from CRASS user-space daemons or the bridge TCP client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrassIpcMessage {
    pub channel_slot: u64,
    pub msg_type: u32,
    pub data: Vec<u8>,
}

/// Host JSON response wrapper returned to CRASS-side clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum BridgeResponse {
    Ok { data: serde_json::Value },
    Denied { reason: String },
    Error { message: String },
}

/// Map a CRASS IPC message to an IntentKernel JSON-RPC request.
pub fn map_to_host_request(msg: &CrassIpcMessage) -> Result<(CrassChannel, serde_json::Value)> {
    let channel = CrassChannel::from_slot(msg.channel_slot)
        .ok_or_else(|| anyhow!("unsupported CRASS channel slot {}", msg.channel_slot))?;

    let payload = String::from_utf8_lossy(&msg.data);
    let req = match (channel, msg.msg_type) {
        (CrassChannel::Intentd, 0x01) | (CrassChannel::Intentd, 0x10) => {
            let mut meta: BTreeMap<String, String> = BTreeMap::new();
            if let Some(ip) = extract_dest_ip(&payload) {
                meta.insert("dest_ip".into(), ip);
            }
            serde_json::json!({
                "method": "SubmitIntent",
                "params": {
                    "actor_id": "crass-os",
                    "action": infer_action(&payload),
                    "resource": infer_resource(&payload),
                    "anchor": "UiEvent",
                    "timestamp_ms": 0u64,
                    "metadata": meta,
                }
            })
        }
        (CrassChannel::Intentd, _) => serde_json::json!({
            "method": "GetPolicy",
            "params": {
                "actor_id": "crass-os",
                "action": infer_action(&payload),
                "resource": infer_resource(&payload),
                "anchor": "UiEvent",
                "timestamp_ms": 0u64,
                "metadata": {},
            }
        }),
        (CrassChannel::Capd, 0x01) => serde_json::json!({"method": "GetPublicKey"}),
        (CrassChannel::Capd, 0x03) => serde_json::json!({
            "method": "RevokeToken",
            "params": payload.trim()
        }),
        (CrassChannel::Leasebroker, 0x20) => serde_json::json!({
            "method": "RequestLease",
            "params": {"pid": 1, "ttl_ms": 30_000}
        }),
        (CrassChannel::Eventscope, _) => serde_json::json!({"method": "GetPublicKey"}),
        (CrassChannel::IpDescrambler, _) => {
            let event = IntentEvent {
                actor_id: "crass-os".into(),
                action: "descramble".into(),
                resource: "network".into(),
                anchor: TrustAnchor::UiEvent,
                timestamp_ms: 0,
                metadata: extract_dest_ip(&payload)
                    .map(|ip| BTreeMap::from([("dest_ip".into(), ip)]))
                    .unwrap_or_default(),
            };
            let decision = default_policy(&event);
            return Ok((
                CrassChannel::Intentd,
                serde_json::json!({
                    "method": "GetPolicy",
                    "params": event,
                    "crass_local": {
                        "allowed": decision.allowed,
                        "reason": decision.reason,
                    }
                }),
            ));
        }
        (CrassChannel::Capd, _) => serde_json::json!({"method": "GetPublicKey"}),
        (CrassChannel::Leasebroker, _) => serde_json::json!({"method": "ListLeases"}),
    };

    Ok((channel, req))
}

fn infer_action(payload: &str) -> &'static str {
    if payload.contains("descramble") {
        "descramble"
    } else if payload.contains("write") {
        "write"
    } else if payload.contains("network") || payload.contains("send") {
        "send"
    } else {
        "read"
    }
}

fn infer_resource(payload: &str) -> &'static str {
    if payload.contains("descramble") || payload.contains("network") {
        "network"
    } else {
        "file"
    }
}

fn extract_dest_ip(payload: &str) -> Option<String> {
    intentkernel_core::extract_ipv4_literals(payload).into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_intentd_token_issue() {
        let msg = CrassIpcMessage {
            channel_slot: 2,
            msg_type: 0x01,
            data: b"send network 8.8.8.8".to_vec(),
        };
        let (ch, req) = map_to_host_request(&msg).unwrap();
        assert_eq!(ch, CrassChannel::Intentd);
        assert_eq!(req["method"], "SubmitIntent");
        assert_eq!(req["params"]["metadata"]["dest_ip"], "8.8.8.8");
    }

    #[test]
    fn maps_capd_get_pubkey() {
        let msg = CrassIpcMessage {
            channel_slot: 1,
            msg_type: 0x01,
            data: vec![],
        };
        let (ch, req) = map_to_host_request(&msg).unwrap();
        assert_eq!(ch, CrassChannel::Capd);
        assert_eq!(req["method"], "GetPublicKey");
    }

    #[test]
    fn rejects_unknown_channel() {
        let msg = CrassIpcMessage {
            channel_slot: 99,
            msg_type: 0,
            data: vec![],
        };
        assert!(map_to_host_request(&msg).is_err());
    }
}