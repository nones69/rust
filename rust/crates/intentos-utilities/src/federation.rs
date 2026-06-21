//! Native federation utility stub — ground-up, no ikrl-federation daemon.

use intentos_kernel::{Handle, Kernel, SyscallOp, SyscallRequest, SyscallResult};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FederationError {
    #[error("denied: {0}")]
    Denied(String),
}

/// In-process peer registry for future cross-device capability exchange.
pub struct FederationHub {
    device_id: String,
    peers: Vec<String>,
}

impl FederationHub {
    pub fn new(device_id: impl Into<String>) -> Self {
        Self {
            device_id: device_id.into(),
            peers: Vec::new(),
        }
    }

    pub fn advertise(&self) -> &str {
        &self.device_id
    }

    pub fn discover_peer(&mut self, peer_id: impl Into<String>) {
        self.peers.push(peer_id.into());
    }

    pub fn peers(&self) -> &[String] {
        &self.peers
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
            SyscallResult::Allowed { .. } => Ok(format!("delegated:{peer}:{}B", payload.len()).into_bytes()),
            SyscallResult::Denied(r) => Err(FederationError::Denied(r)),
        }
    }
}