//! Intent Broker peer registry — local federation continuity in Loom.

use serde::{Deserialize, Serialize};

/// Remote intent broker registered for federated capability exchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerPeer {
    pub peer_id: String,
    pub public_key_hex: String,
    pub registered_at_ms: u64,
    #[serde(default)]
    pub label: String,
    /// Optional wire endpoint (`file://` inbox path prefix).
    #[serde(default)]
    pub endpoint: String,
}

impl BrokerPeer {
    pub fn new(peer_id: impl Into<String>, public_key_hex: impl Into<String>, at_ms: u64) -> Self {
        Self {
            peer_id: peer_id.into(),
            public_key_hex: public_key_hex.into(),
            registered_at_ms: at_ms,
            label: String::new(),
            endpoint: String::new(),
        }
    }
}