//! # intentkernel-sys — IntentKernel IPC client
//!
//! Provides a high-level async client for the IntentKernel IPC protocol.
//! Supports three transport modes:
//!
//! | Mode    | Address format                       | Authentication    |
//! |---------|--------------------------------------|-------------------|
//! | Local   | `unix:///tmp/intentos.sock`          | none (local)      |
//! | TCP     | `tcp://127.0.0.1:9500`               | none (local net)  |
//! | mTLS    | `tls://10.0.0.5:9443`                | mutual TLS        |
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use intentkernel_sys::KernelClient;
//!
//! #[tokio::main]
//! async fn main() {
//!     let mut client = KernelClient::connect_local("tcp://127.0.0.1:9500").await.unwrap();
//!     let stats = client.health().await.unwrap();
//!     println!("{stats:?}");
//! }
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use ikrl_remote::{
    Handshake, HandshakeAck, OpenMode, TrustAnchorHint, PROTOCOL_VERSION,
};
use ikrl_transport::Channel;
use uuid::Uuid;

pub use ikrl_remote::{KernelRpcRequest, KernelRpcResponse, PeerIdentity, SyscallOp, TransportKind};

// Re-export TLS config types for callers that opt in to mTLS.
#[cfg(feature = "tls")]
pub use ikrl_transport::{TlsClientConfig, TlsServerConfig};

// ─── Error type ───────────────────────────────────────────────────────────────

#[derive(thiserror::Error, Debug)]
pub enum ClientError {
    #[error("transport error: {0}")]
    Transport(#[from] anyhow::Error),
    #[error("kernel denied: {0}")]
    Denied(String),
    #[error("protocol version mismatch: server supports {supported}, client requested {requested}")]
    VersionMismatch { supported: u32, requested: u32 },
    #[error("handshake rejected: {0}")]
    Rejected(String),
    #[error("unexpected response")]
    UnexpectedResponse,
}

// ─── Client ───────────────────────────────────────────────────────────────────

/// An open, handshaked connection to a kernel IPC server.
pub struct KernelClient {
    ch: Channel,
}

impl KernelClient {
    // ── Constructors ─────────────────────────────────────────────────────────

    /// Connect to a kernel over a plain (non-TLS) transport.
    ///
    /// `addr` can be any address accepted by [`ikrl_transport::Channel::connect`]:
    /// `tcp://host:port`, `unix:///path/to/socket`, or a bare `host:port`.
    pub async fn connect_local(addr: &str) -> Result<Self, ClientError> {
        let mut ch = Channel::connect(addr).await?;
        Self::handshake(&mut ch, "intentkernel-sys").await?;
        Ok(Self { ch })
    }

    /// Connect to a remote kernel over mTLS.
    ///
    /// `addr` should use the `tls://` scheme.
    #[cfg(feature = "tls")]
    pub async fn connect_tls(
        addr: &str,
        cfg: &ikrl_transport::TlsClientConfig,
    ) -> Result<Self, ClientError> {
        let mut ch = Channel::connect_tls(addr, cfg).await?;
        Self::handshake(&mut ch, "intentkernel-sys").await?;
        Ok(Self { ch })
    }

    async fn handshake(ch: &mut Channel, client_id: &str) -> Result<(), ClientError> {
        let hs = Handshake {
            protocol_version: PROTOCOL_VERSION,
            client_id: client_id.to_string(),
        };
        ch.send_json(&hs).await?;
        let ack: HandshakeAck = ch.recv_json().await?;
        match ack {
            HandshakeAck::Ok { .. } => Ok(()),
            HandshakeAck::VersionMismatch { supported, requested } => {
                Err(ClientError::VersionMismatch { supported, requested })
            }
            HandshakeAck::Rejected { reason } => Err(ClientError::Rejected(reason)),
        }
    }

    // ── Raw RPC ───────────────────────────────────────────────────────────────

    /// Send a [`KernelRpcRequest`] and receive a [`KernelRpcResponse`].
    pub async fn rpc(&mut self, req: &KernelRpcRequest) -> Result<KernelRpcResponse, ClientError> {
        self.ch.send_json(req).await?;
        let resp: KernelRpcResponse = self.ch.recv_json().await?;
        Ok(resp)
    }

    // ── High-level helpers ────────────────────────────────────────────────────

    /// Ping the kernel; returns the raw JSON stats value.
    pub async fn health(&mut self) -> Result<serde_json::Value, ClientError> {
        match self.rpc(&KernelRpcRequest::Health).await? {
            KernelRpcResponse::Ok(v) => Ok(v),
            KernelRpcResponse::Denied { reason } => Err(ClientError::Denied(reason)),
            _other => Err(ClientError::UnexpectedResponse),
        }
    }

    /// Request a capability token for `resource`/`action` under `UiEvent` trust.
    pub async fn mint_token(
        &mut self,
        actor: &str,
        resource: &str,
        action: &str,
    ) -> Result<String, ClientError> {
        self.mint_token_full(actor, resource, action, TrustAnchorHint::UiEvent, false)
            .await
    }

    /// Request a capability token with full control over the trust anchor.
    pub async fn mint_token_full(
        &mut self,
        actor: &str,
        resource: &str,
        action: &str,
        anchor: TrustAnchorHint,
        user_confirmed: bool,
    ) -> Result<String, ClientError> {
        let req = KernelRpcRequest::MintToken {
            call_id: Uuid::new_v4(),
            actor: actor.to_string(),
            resource: resource.to_string(),
            action: action.to_string(),
            anchor,
            timestamp_ms: now_ms(),
            user_confirmed,
        };
        match self.rpc(&req).await? {
            KernelRpcResponse::Ok(v) => v["jti"]
                .as_str()
                .map(str::to_string)
                .ok_or(ClientError::UnexpectedResponse),
            KernelRpcResponse::Denied { reason } => Err(ClientError::Denied(reason)),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    /// Register a capability token (by JTI) with the kernel.
    pub async fn register_token(
        &mut self,
        token_jti: &str,
        token_cbor: Vec<u8>,
    ) -> Result<(), ClientError> {
        let req = KernelRpcRequest::RegisterToken {
            call_id: Uuid::new_v4(),
            token_jti: token_jti.to_string(),
            token_cbor,
        };
        match self.rpc(&req).await? {
            KernelRpcResponse::Ok(_) => Ok(()),
            KernelRpcResponse::Denied { reason } => Err(ClientError::Denied(reason)),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    /// Revoke a token by JTI.
    pub async fn revoke_token(
        &mut self,
        jti: &str,
        actor: &str,
    ) -> Result<bool, ClientError> {
        let req = KernelRpcRequest::RevokeToken {
            call_id: Uuid::new_v4(),
            jti: jti.to_string(),
            actor: actor.to_string(),
        };
        match self.rpc(&req).await? {
            KernelRpcResponse::Ok(v) => Ok(v["revoked"].as_bool().unwrap_or(false)),
            KernelRpcResponse::Denied { reason } => Err(ClientError::Denied(reason)),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    /// Invoke a governed syscall against a registered handle.
    ///
    /// Returns the JSON result from the kernel on success.
    pub async fn syscall(
        &mut self,
        handle: u64,
        op: SyscallOp,
        target: &str,
        payload: Vec<u8>,
    ) -> Result<serde_json::Value, ClientError> {
        let req = KernelRpcRequest::Syscall {
            call_id: Uuid::new_v4(),
            handle,
            op,
            target: target.to_string(),
            payload,
        };
        match self.rpc(&req).await? {
            KernelRpcResponse::Ok(v) => Ok(v),
            KernelRpcResponse::Denied { reason } => Err(ClientError::Denied(reason)),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    /// Open a file — maps the `OpenMode` to the appropriate syscall op.
    pub async fn open(
        &mut self,
        handle: u64,
        path: &str,
        mode: OpenMode,
    ) -> Result<serde_json::Value, ClientError> {
        let op = match mode {
            OpenMode::Read => SyscallOp::Read,
            OpenMode::Write | OpenMode::Create => SyscallOp::Write,
            OpenMode::ReadWrite => SyscallOp::Read,
        };
        self.syscall(handle, op, path, vec![]).await
    }

    // ── Lease helpers ─────────────────────────────────────────────────────────

    /// Grant a process lease.
    pub async fn grant_lease(
        &mut self,
        pid: u32,
        ttl_ms: u64,
    ) -> Result<serde_json::Value, ClientError> {
        let req = KernelRpcRequest::GrantLease {
            call_id: Uuid::new_v4(),
            pid,
            ttl_ms,
        };
        match self.rpc(&req).await? {
            KernelRpcResponse::Ok(v) => Ok(v),
            KernelRpcResponse::Denied { reason } => Err(ClientError::Denied(reason)),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    /// List active leases.
    pub async fn list_leases(&mut self) -> Result<serde_json::Value, ClientError> {
        let req = KernelRpcRequest::ListLeases {
            call_id: Uuid::new_v4(),
        };
        match self.rpc(&req).await? {
            KernelRpcResponse::Ok(v) => Ok(v),
            KernelRpcResponse::Denied { reason } => Err(ClientError::Denied(reason)),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // These tests require a running kernel IPC server.  They are skipped in
    // unit-test mode; use the integration tests in `intentos-kernel` instead.

    #[test]
    fn now_ms_is_positive() {
        assert!(now_ms() > 0);
    }
}
