//! # ikrl-remote — shared wire protocol for remote IntentKernel IPC
//!
//! This crate defines the canonical request/response types and peer identity
//! used by both the kernel-side IPC server (`intentos-kernel::ipc_server`) and
//! the client-side transport library (`intentkernel-sys`).
//!
//! All messages are serialised as length-prefixed JSON over the
//! `ikrl-transport` channel (TCP, Unix socket, or mTLS).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Current protocol version.  Clients and the server exchange this during
/// the handshake; a mismatch results in an immediate [`KernelRpcResponse::VersionMismatch`].
pub const PROTOCOL_VERSION: u32 = 1;

// ─── Peer identity ────────────────────────────────────────────────────────────

/// Identity of the connecting client, derived either from the mTLS client
/// certificate (Common Name / SAN) or from a synthetic local label.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PeerIdentity {
    /// Human-readable principal (CN from the cert, or a local label).
    pub principal: String,
    /// SHA-256 hex fingerprint of the DER-encoded client certificate, or
    /// `"local"` for Unix-socket or plain-TCP connections.
    pub cert_fingerprint: String,
    /// Transport kind that delivered this connection.
    pub transport: TransportKind,
}

impl PeerIdentity {
    /// Create a synthetic identity for a local (non-TLS) connection.
    pub fn local(principal: impl Into<String>) -> Self {
        Self {
            principal: principal.into(),
            cert_fingerprint: "local".into(),
            transport: TransportKind::Local,
        }
    }

    /// Create an identity from a verified mTLS connection.
    pub fn tls(principal: impl Into<String>, cert_fingerprint: impl Into<String>) -> Self {
        Self {
            principal: principal.into(),
            cert_fingerprint: cert_fingerprint.into(),
            transport: TransportKind::Tls,
        }
    }

    /// Whether the peer authenticated via mTLS.
    pub fn is_remote(&self) -> bool {
        self.transport == TransportKind::Tls
    }
}

/// Which transport delivered the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    Local,
    Tls,
}

// ─── Protocol handshake ───────────────────────────────────────────────────────

/// First message sent by the client after the transport is established.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Handshake {
    pub protocol_version: u32,
    /// Caller-supplied label; the server may override with the cert CN.
    pub client_id: String,
}

/// Server response to the handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum HandshakeAck {
    Ok {
        server_id: String,
        protocol_version: u32,
    },
    VersionMismatch {
        supported: u32,
        requested: u32,
    },
    Rejected {
        reason: String,
    },
}

// ─── Kernel RPC request ───────────────────────────────────────────────────────

/// File-open modes (mirrors `intentos-kernel::IkSyscall`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpenMode {
    Read,
    Write,
    ReadWrite,
    Create,
}

/// HTTP methods for network syscalls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::upper_case_acronyms)]
pub enum HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
}

/// Trust anchor passed by the client when requesting a token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustAnchorHint {
    UiEvent,
    SystemDaemon,
    HardwareSensor,
    Federated,
    None,
}

/// All operations a remote (or local) client can invoke on the kernel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", content = "params", rename_all = "snake_case")]
pub enum KernelRpcRequest {
    // ── Health ────────────────────────────────────────────────────────────────
    /// Ping the kernel; returns uptime and statistics.
    Health,

    // ── Token lifecycle ───────────────────────────────────────────────────────
    /// Request a capability token for the given resource/action.
    MintToken {
        call_id: Uuid,
        actor: String,
        resource: String,
        action: String,
        anchor: TrustAnchorHint,
        timestamp_ms: u64,
        /// Caller confirms a confirmation-required decision.
        user_confirmed: bool,
    },
    /// Register a previously minted (serialised) token and obtain a handle.
    RegisterToken {
        call_id: Uuid,
        token_jti: String,
        /// CBOR-serialised capability token bytes.
        token_cbor: Vec<u8>,
    },
    /// Revoke a capability token by JTI.
    RevokeToken {
        call_id: Uuid,
        jti: String,
        actor: String,
    },
    /// Check whether a JTI is in the revocation list.
    IsRevoked {
        call_id: Uuid,
        jti: String,
    },

    // ── Syscall ───────────────────────────────────────────────────────────────
    /// Invoke a governed syscall against a registered handle.
    Syscall {
        call_id: Uuid,
        /// 64-bit packed kernel handle (table_index | generation | checksum).
        handle: u64,
        op: SyscallOp,
        target: String,
        payload: Vec<u8>,
    },

    // ── Lease ─────────────────────────────────────────────────────────────────
    GrantLease {
        call_id: Uuid,
        pid: u32,
        ttl_ms: u64,
    },
    RenewLease {
        call_id: Uuid,
        lease_id: String,
        ttl_ms: u64,
    },
    ListLeases {
        call_id: Uuid,
    },
}

/// Syscall operation codes (mirrors `SyscallOp` in `intentos-kernel`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyscallOp {
    Read,
    Write,
    Exec,
    Delete,
    List,
    Create,
    Net,
}

// ─── Kernel RPC response ──────────────────────────────────────────────────────

/// Server reply for every `KernelRpcRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", content = "data", rename_all = "snake_case")]
pub enum KernelRpcResponse {
    Ok(serde_json::Value),
    Denied { reason: String },
    Error { message: String },
    VersionMismatch { supported: u32 },
}

impl KernelRpcResponse {
    pub fn ok(data: impl Serialize) -> Self {
        Self::Ok(serde_json::to_value(data).unwrap_or(serde_json::Value::Null))
    }
    pub fn denied(reason: impl Into<String>) -> Self {
        Self::Denied {
            reason: reason.into(),
        }
    }
    pub fn error(msg: impl Into<String>) -> Self {
        Self::Error {
            message: msg.into(),
        }
    }
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_roundtrip() {
        let h = Handshake {
            protocol_version: PROTOCOL_VERSION,
            client_id: "test-client".into(),
        };
        let json = serde_json::to_string(&h).unwrap();
        let h2: Handshake = serde_json::from_str(&json).unwrap();
        assert_eq!(h2.protocol_version, PROTOCOL_VERSION);
    }

    #[test]
    fn mint_token_roundtrip() {
        let req = KernelRpcRequest::MintToken {
            call_id: Uuid::new_v4(),
            actor: "myapp".into(),
            resource: "file".into(),
            action: "read".into(),
            anchor: TrustAnchorHint::UiEvent,
            timestamp_ms: 1_700_000_000_000,
            user_confirmed: false,
        };
        let json = serde_json::to_string(&req).unwrap();
        let req2: KernelRpcRequest = serde_json::from_str(&json).unwrap();
        if let KernelRpcRequest::MintToken { actor, .. } = req2 {
            assert_eq!(actor, "myapp");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn peer_identity_local_is_not_remote() {
        let id = PeerIdentity::local("daemon-1");
        assert!(!id.is_remote());
        assert_eq!(id.cert_fingerprint, "local");
    }

    #[test]
    fn peer_identity_tls_is_remote() {
        let id = PeerIdentity::tls("client-node", "aabbccdd");
        assert!(id.is_remote());
    }

    #[test]
    fn response_ok_is_ok() {
        let r = KernelRpcResponse::ok(serde_json::json!({"handle": 42}));
        assert!(r.is_ok());
    }
}
