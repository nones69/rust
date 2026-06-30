//! Native Intent Broker federation — in-process peer registry and delegation.

use intentos_kernel::{BrokerPeer, Handle, Kernel, SyscallOp, SyscallRequest, SyscallResult};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FederationError {
    #[error("denied: {0}")]
    Denied(String),
    #[error("unknown peer: {0}")]
    UnknownPeer(String),
}

/// In-process broker hub for cross-device capability exchange.
pub struct FederationHub {
    device_id: String,
    peers: Vec<BrokerPeer>,
}

impl FederationHub {
    pub fn new(device_id: impl Into<String>) -> Self {
        Self {
            device_id: device_id.into(),
            peers: Vec::new(),
        }
    }

    pub fn from_peers(device_id: impl Into<String>, peers: Vec<BrokerPeer>) -> Self {
        Self {
            device_id: device_id.into(),
            peers,
        }
    }

    pub fn advertise(&self) -> &str {
        &self.device_id
    }

    pub fn register_peer(&mut self, peer: BrokerPeer) {
        if let Some(existing) = self.peers.iter_mut().find(|p| p.peer_id == peer.peer_id) {
            *existing = peer;
        } else {
            self.peers.push(peer);
        }
    }

    pub fn peers(&self) -> &[BrokerPeer] {
        &self.peers
    }

    pub fn find_peer(&self, peer_id: &str) -> Option<&BrokerPeer> {
        self.peers.iter().find(|p| p.peer_id == peer_id)
    }

    pub fn delegate(
        kernel: &Kernel,
        handle: Handle,
        peer: &str,
        payload: &[u8],
    ) -> Result<Vec<u8>, FederationError> {
        match kernel.syscall(
            handle,
            SyscallRequest {
                op: SyscallOp::Send,
                target: peer.into(),
                payload: payload.to_vec(),
            },
        ) {
            SyscallResult::Allowed { .. } => {
                Ok(format!("delegated:{peer}:{}B", payload.len()).into_bytes())
            }
            SyscallResult::Denied(r) => Err(FederationError::Denied(r)),
        }
    }

    pub fn delegate_to_registered(
        &self,
        kernel: &Kernel,
        handle: Handle,
        peer_id: &str,
        payload: &[u8],
    ) -> Result<Vec<u8>, FederationError> {
        let peer = self
            .find_peer(peer_id)
            .ok_or_else(|| FederationError::UnknownPeer(peer_id.into()))?;
        Self::delegate(kernel, handle, &peer.peer_id, payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_peer_is_idempotent_by_id() {
        let mut hub = FederationHub::new("local");
        let p1 = BrokerPeer::new("peer-a", "aa".repeat(64), 1);
        let p2 = BrokerPeer::new("peer-a", "bb".repeat(64), 2);
        hub.register_peer(p1);
        hub.register_peer(p2);
        assert_eq!(hub.peers().len(), 1);
        assert_eq!(hub.peers()[0].public_key_hex, "bb".repeat(64));
    }
}