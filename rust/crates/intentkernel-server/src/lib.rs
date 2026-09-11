//! # intentkernel-server — kernel-side IPC server
//!
//! Accepts local or remote `Channel` connections, performs the protocol
//! handshake, and dispatches each [`ikrl_remote::KernelRpcRequest`] into the
//! [`intentos_kernel::Kernel`].
//!
//! This crate is the bridge between the `ikrl-transport` network layer and the
//! `intentos-kernel` policy engine. It is intentionally separate so that the
//! pure kernel crate stays free of transport dependencies.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use intentos_kernel::Kernel;
//! use intentkernel_server::serve;
//! use ikrl_transport::Listener;
//!
//! #[tokio::main]
//! async fn main() {
//!     let kernel = Arc::new(Kernel::boot().unwrap());
//!     let listener = Listener::bind("tcp://127.0.0.1:9500").await.unwrap();
//!     serve(kernel, listener).await;
//! }
//! ```

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};

use ikrl_remote::{
    Handshake, HandshakeAck, KernelRpcRequest, KernelRpcResponse, PeerIdentity, SyscallOp,
    TransportKind, TrustAnchorHint, PROTOCOL_VERSION,
};
use ikrl_transport::{Channel, Listener};
use intentos_audit::AuditEventKind;
use intentos_kernel::{
    Handle, Intent, Kernel, KernelError, SyscallOp as KernelSyscallOp, SyscallRequest,
    SyscallResult, Token, TrustAnchor,
};
use tracing::{info, warn};

// ─── Per-client quota counters ────────────────────────────────────────────────

struct QuotaEntry {
    active_connections: u32,
    total_requests: u64,
}

struct ServerState {
    quotas: HashMap<String, QuotaEntry>,
}

impl ServerState {
    fn new() -> Self {
        Self {
            quotas: HashMap::new(),
        }
    }

    fn admit(&mut self, principal: &str) -> bool {
        let entry = self
            .quotas
            .entry(principal.to_string())
            .or_insert(QuotaEntry {
                active_connections: 0,
                total_requests: 0,
            });
        if entry.active_connections >= 32 {
            return false;
        }
        entry.active_connections += 1;
        true
    }

    fn release(&mut self, principal: &str) {
        if let Some(e) = self.quotas.get_mut(principal) {
            e.active_connections = e.active_connections.saturating_sub(1);
        }
    }

    fn increment(&mut self, principal: &str) {
        self.quotas
            .entry(principal.to_string())
            .or_insert(QuotaEntry {
                active_connections: 0,
                total_requests: 0,
            })
            .total_requests += 1;
    }
}

// ─── Public server entry-point ────────────────────────────────────────────────

/// Serve a kernel over a `Listener` indefinitely.
///
/// Each accepted connection is handled in a new Tokio task.
pub async fn serve(kernel: Arc<Kernel>, listener: Listener) {
    let state = Arc::new(StdMutex::new(ServerState::new()));
    let local_addr = listener.local_addr().unwrap_or_else(|_| "?".into());
    info!("kernel IPC server listening on {local_addr}");

    if let Some(audit) = kernel.audit_ref() {
        let _ = audit.record(
            AuditEventKind::BrokerTcpListening,
            "ipc_server",
            format!("addr={local_addr}"),
        );
    }

    loop {
        match listener.accept().await {
            Ok(ch) => {
                let kernel = Arc::clone(&kernel);
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    handle_connection(kernel, state, ch).await;
                });
            }
            Err(e) => {
                warn!("accept error: {e}");
            }
        }
    }
}

// ─── Connection handler ───────────────────────────────────────────────────────

async fn handle_connection(
    kernel: Arc<Kernel>,
    state: Arc<StdMutex<ServerState>>,
    mut ch: Channel,
) {
    let transport = if ch.peer_cert_fingerprint().is_some() {
        TransportKind::Tls
    } else {
        TransportKind::Local
    };

    let handshake: Handshake = match ch.recv_json().await {
        Ok(h) => h,
        Err(e) => {
            warn!("handshake recv error: {e}");
            return;
        }
    };

    if handshake.protocol_version != PROTOCOL_VERSION {
        let _ = ch
            .send_json(&HandshakeAck::VersionMismatch {
                supported: PROTOCOL_VERSION,
                requested: handshake.protocol_version,
            })
            .await;
        if let Some(audit) = kernel.audit_ref() {
            let _ = audit.record(
                AuditEventKind::RemoteRejected,
                &handshake.client_id,
                format!(
                    "version_mismatch requested={} supported={}",
                    handshake.protocol_version, PROTOCOL_VERSION
                ),
            );
        }
        return;
    }

    let peer = PeerIdentity {
        principal: handshake.client_id.clone(),
        cert_fingerprint: ch.peer_cert_fingerprint().unwrap_or("local").to_string(),
        transport,
    };

    let ack = HandshakeAck::Ok {
        server_id: "intentos-kernel".into(),
        protocol_version: PROTOCOL_VERSION,
    };
    if ch.send_json(&ack).await.is_err() {
        return;
    }

    let quota_exceeded = {
        let mut s = state.lock().unwrap();
        !s.admit(&peer.principal)
    };
    if quota_exceeded {
        warn!("quota exceeded for {}", peer.principal);
        let _ = ch
            .send_json(&KernelRpcResponse::denied("quota exceeded"))
            .await;
        if let Some(audit) = kernel.audit_ref() {
            let _ = audit.record(
                AuditEventKind::RemoteRejected,
                &peer.principal,
                "quota_exceeded".to_string(),
            );
        }
        return;
    }

    if peer.is_remote() {
        if let Some(audit) = kernel.audit_ref() {
            let _ = audit.record(
                AuditEventKind::RemoteConnected,
                &peer.principal,
                format!("fp={}", peer.cert_fingerprint),
            );
        }
    }

    info!(
        "new IPC connection principal={} remote={}",
        peer.principal,
        peer.is_remote()
    );

    loop {
        let req: KernelRpcRequest = match ch.recv_json().await {
            Ok(r) => r,
            Err(_) => break,
        };

        {
            let mut s = state.lock().unwrap();
            s.increment(&peer.principal);
        }

        let resp = dispatch(&kernel, &peer, req).await;

        if ch.send_json(&resp).await.is_err() {
            break;
        }
    }

    {
        let mut s = state.lock().unwrap();
        s.release(&peer.principal);
    }

    info!("IPC connection closed principal={}", peer.principal);
}

// ─── Request dispatcher ───────────────────────────────────────────────────────

async fn dispatch(
    kernel: &Kernel,
    peer: &PeerIdentity,
    req: KernelRpcRequest,
) -> KernelRpcResponse {
    use KernelRpcRequest::*;

    match req {
        Health => {
            let stats = kernel.stats();
            KernelRpcResponse::ok(serde_json::to_value(stats).unwrap_or_default())
        }

        MintToken {
            actor,
            resource,
            action,
            anchor,
            timestamp_ms,
            user_confirmed,
            ..
        } => {
            let mut meta = std::collections::BTreeMap::new();
            if peer.is_remote() {
                meta.insert("remote_principal".to_string(), peer.principal.clone());
                meta.insert("cert_fp".to_string(), peer.cert_fingerprint.clone());
            }

            let intent = Intent {
                actor,
                resource: resource.clone(),
                action: action.clone(),
                anchor: map_anchor(anchor),
                timestamp_ms,
                metadata: meta,
            };

            match kernel.mint_token_confirmed(intent, user_confirmed) {
                Ok(token) => {
                    if let Some(audit) = kernel.audit_ref() {
                        let _ = audit.record(
                            if peer.is_remote() {
                                AuditEventKind::RemoteTokenMinted
                            } else {
                                AuditEventKind::TokenMinted
                            },
                            &peer.principal,
                            format!("jti={} resource={} action={}", token.jti, resource, action),
                        );
                    }
                    KernelRpcResponse::ok(serde_json::json!({ "jti": token.jti }))
                }
                Err(KernelError::PolicyDenied(reason)) => KernelRpcResponse::denied(reason),
                Err(e) => KernelRpcResponse::error(e.to_string()),
            }
        }

        RegisterToken {
            token_jti,
            token_cbor,
            ..
        } => match decode_token_cbor(&token_cbor) {
            Ok(token) => {
                if token.jti != token_jti && !token_jti.is_empty() {
                    return KernelRpcResponse::denied(format!(
                        "token_jti mismatch: envelope={token_jti} token={}",
                        token.jti
                    ));
                }
                match kernel.register_token(token) {
                    Ok(handle) => {
                        if let Some(audit) = kernel.audit_ref() {
                            let _ = audit.record(
                                if peer.is_remote() {
                                    AuditEventKind::RemoteHandleRegistered
                                } else {
                                    AuditEventKind::HandleRegistered
                                },
                                &peer.principal,
                                format!("jti={} handle=0x{:X}", token_jti, handle.as_u64()),
                            );
                        }
                        KernelRpcResponse::ok(serde_json::json!({
                            "registered": true,
                            "handle": handle.as_u64(),
                            "jti": token_jti,
                        }))
                    }
                    Err(KernelError::Revoked) => KernelRpcResponse::denied("token revoked"),
                    Err(KernelError::PolicyDenied(r)) => KernelRpcResponse::denied(r),
                    Err(e) => KernelRpcResponse::error(e.to_string()),
                }
            }
            Err(e) => KernelRpcResponse::error(format!("token decode failed: {e}")),
        },

        RevokeToken { jti, actor, .. } => {
            let revoked = kernel.revoke_jti(&jti, &actor);
            KernelRpcResponse::ok(serde_json::json!({ "revoked": revoked }))
        }

        IsRevoked { jti: _, .. } => {
            // Conservative answer: direct revocation queries should go through capd.
            KernelRpcResponse::ok(
                serde_json::json!({ "is_revoked": false, "note": "verify via capd" }),
            )
        }

        Syscall {
            handle,
            op,
            target,
            payload,
            ..
        } => {
            let h = Handle::from_u64(handle);
            let syscall_req = SyscallRequest {
                op: map_op(op),
                target: target.clone(),
                payload,
            };

            let result = kernel.syscall(h, syscall_req);

            if let Some(audit) = kernel.audit_ref() {
                let detail = match &result {
                    SyscallResult::Allowed {
                        kind,
                        remaining_uses,
                    } => {
                        format!("allowed {kind:?} target={target} uses_left={remaining_uses}")
                    }
                    SyscallResult::Denied(r) => format!("denied {r} target={target}"),
                };
                let _ = audit.record(
                    if peer.is_remote() {
                        AuditEventKind::RemoteSyscall
                    } else {
                        AuditEventKind::Syscall
                    },
                    &peer.principal,
                    detail,
                );
            }

            match result {
                SyscallResult::Allowed {
                    kind,
                    remaining_uses,
                } => KernelRpcResponse::ok(serde_json::json!({
                    "allowed": true,
                    "kind": format!("{kind:?}"),
                    "remaining_uses": remaining_uses,
                })),
                SyscallResult::Denied(reason) => KernelRpcResponse::denied(reason),
            }
        }

        GrantLease { pid, ttl_ms, .. } => {
            let lease = kernel.grant_lease(pid, ttl_ms);
            KernelRpcResponse::ok(serde_json::to_value(lease).unwrap_or_default())
        }

        RenewLease {
            lease_id, ttl_ms, ..
        } => match kernel.renew_lease(&lease_id, ttl_ms) {
            Some(lease) => KernelRpcResponse::ok(serde_json::to_value(lease).unwrap_or_default()),
            None => KernelRpcResponse::denied("lease not found or expired"),
        },

        ListLeases { .. } => {
            let leases = kernel.list_leases();
            KernelRpcResponse::ok(serde_json::to_value(leases).unwrap_or_default())
        }
    }
}

// ─── Type mapping helpers ─────────────────────────────────────────────────────

fn map_anchor(hint: TrustAnchorHint) -> TrustAnchor {
    match hint {
        TrustAnchorHint::UiEvent => TrustAnchor::UiEvent,
        TrustAnchorHint::SystemDaemon => TrustAnchor::UiEvent,
        TrustAnchorHint::HardwareSensor => TrustAnchor::Hardware,
        TrustAnchorHint::Federated => TrustAnchor::Federated,
        TrustAnchorHint::None => TrustAnchor::None,
    }
}

fn map_op(op: SyscallOp) -> KernelSyscallOp {
    match op {
        SyscallOp::Read => KernelSyscallOp::Read,
        SyscallOp::Write => KernelSyscallOp::Write,
        SyscallOp::Exec => KernelSyscallOp::Unknown("exec".into()),
        SyscallOp::Delete => KernelSyscallOp::Unknown("delete".into()),
        SyscallOp::List => KernelSyscallOp::List,
        SyscallOp::Create => KernelSyscallOp::Unknown("create".into()),
        SyscallOp::Net => KernelSyscallOp::Send,
    }
}

fn decode_token_cbor(bytes: &[u8]) -> Result<Token, String> {
    ciborium::de::from_reader(bytes).map_err(|e| e.to_string())
}

/// Serve a kernel over an mTLS [`SecureListener`] indefinitely.
///
/// Prototype entry-point for remote IntentKernel IPC. Pair with
/// [`ikrl_transport::DevPki`] for local/dev certificate material — not a
/// production PKI claim.
pub async fn serve_mtls(kernel: Arc<Kernel>, listener: ikrl_transport::SecureListener) {
    let state = Arc::new(StdMutex::new(ServerState::new()));
    let local_addr = listener.local_addr().unwrap_or_else(|_| "?".into());
    info!("kernel IPC mTLS server listening on {local_addr}");

    if let Some(audit) = kernel.audit_ref() {
        let _ = audit.record(
            AuditEventKind::BrokerTcpListening,
            "ipc_server_mtls",
            format!("addr={local_addr}"),
        );
    }

    loop {
        match listener.accept().await {
            Ok(ch) => {
                let kernel = Arc::clone(&kernel);
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    handle_secure_connection(kernel, state, ch).await;
                });
            }
            Err(e) => {
                warn!("mtls accept error: {e}");
            }
        }
    }
}

async fn handle_secure_connection(
    kernel: Arc<Kernel>,
    state: Arc<StdMutex<ServerState>>,
    mut ch: ikrl_transport::SecureChannel,
) {
    // Adapt SecureChannel framing to the same handshake/RPC loop by using its
    // send_json/recv_json API (compatible with Channel framing).
    let fingerprint = ch.peer_cert_fingerprint().unwrap_or("unknown").to_string();

    let handshake: Handshake = match ch.recv_json().await {
        Ok(h) => h,
        Err(e) => {
            warn!("mtls handshake recv error: {e}");
            return;
        }
    };

    if handshake.protocol_version != PROTOCOL_VERSION {
        let _ = ch
            .send_json(&HandshakeAck::VersionMismatch {
                supported: PROTOCOL_VERSION,
                requested: handshake.protocol_version,
            })
            .await;
        return;
    }

    let peer = PeerIdentity {
        principal: handshake.client_id.clone(),
        cert_fingerprint: fingerprint,
        transport: TransportKind::Tls,
    };

    let ack = HandshakeAck::Ok {
        server_id: "intentos-kernel".into(),
        protocol_version: PROTOCOL_VERSION,
    };
    if ch.send_json(&ack).await.is_err() {
        return;
    }

    let admitted = { state.lock().unwrap().admit(&peer.principal) };
    if !admitted {
        let _ = ch
            .send_json(&KernelRpcResponse::denied("quota exceeded"))
            .await;
        return;
    }

    loop {
        let req: KernelRpcRequest = match ch.recv_json().await {
            Ok(r) => r,
            Err(_) => break,
        };
        {
            let mut s = state.lock().unwrap();
            s.increment(&peer.principal);
        }
        let resp = dispatch(&kernel, &peer, req).await;
        if ch.send_json(&resp).await.is_err() {
            break;
        }
    }

    {
        state.lock().unwrap().release(&peer.principal);
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ikrl_remote::{KernelRpcRequest, TrustAnchorHint};
    use ikrl_transport::Listener;
    use intentos_kernel::wall_ms;

    async fn boot_test_server() -> (Arc<Kernel>, String) {
        let kernel = Arc::new(Kernel::boot().unwrap());
        let listener = Listener::bind("tcp://127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap();
        let addr = format!("tcp://127.0.0.1:{}", port.rsplit(':').next().unwrap());
        let k2 = Arc::clone(&kernel);
        tokio::spawn(async move { serve(k2, listener).await });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        (kernel, addr)
    }

    async fn do_handshake(ch: &mut Channel) {
        let hs = Handshake {
            protocol_version: PROTOCOL_VERSION,
            client_id: "test".into(),
        };
        ch.send_json(&hs).await.unwrap();
        let _ack: HandshakeAck = ch.recv_json().await.unwrap();
    }

    #[tokio::test]
    async fn health_rpc() {
        let (_, addr) = boot_test_server().await;
        let mut ch = Channel::connect(&addr).await.unwrap();
        do_handshake(&mut ch).await;
        ch.send_json(&KernelRpcRequest::Health).await.unwrap();
        let resp: KernelRpcResponse = ch.recv_json().await.unwrap();
        assert!(resp.is_ok(), "expected Ok, got {resp:?}");
    }

    #[tokio::test]
    async fn mint_token_rpc() {
        let (_, addr) = boot_test_server().await;
        let mut ch = Channel::connect(&addr).await.unwrap();
        do_handshake(&mut ch).await;
        let req = KernelRpcRequest::MintToken {
            call_id: uuid::Uuid::new_v4(),
            actor: "test-app".into(),
            resource: "file".into(),
            action: "read".into(),
            anchor: TrustAnchorHint::UiEvent,
            timestamp_ms: wall_ms(),
            user_confirmed: false,
        };
        ch.send_json(&req).await.unwrap();
        let resp: KernelRpcResponse = ch.recv_json().await.unwrap();
        assert!(resp.is_ok(), "expected Ok, got {resp:?}");
    }

    #[tokio::test]
    async fn mint_token_denied_for_low_trust() {
        let (_, addr) = boot_test_server().await;
        let mut ch = Channel::connect(&addr).await.unwrap();
        do_handshake(&mut ch).await;
        let req = KernelRpcRequest::MintToken {
            call_id: uuid::Uuid::new_v4(),
            actor: "bad-app".into(),
            resource: "file".into(),
            action: "read".into(),
            anchor: TrustAnchorHint::None,
            timestamp_ms: wall_ms(),
            user_confirmed: false,
        };
        ch.send_json(&req).await.unwrap();
        let resp: KernelRpcResponse = ch.recv_json().await.unwrap();
        assert!(matches!(resp, KernelRpcResponse::Denied { .. }));
    }

    #[tokio::test]
    async fn version_mismatch_rejects() {
        let (_, addr) = boot_test_server().await;
        let mut ch = Channel::connect(&addr).await.unwrap();
        let bad_hs = Handshake {
            protocol_version: 999,
            client_id: "bad".into(),
        };
        ch.send_json(&bad_hs).await.unwrap();
        let ack: HandshakeAck = ch.recv_json().await.unwrap();
        assert!(matches!(ack, HandshakeAck::VersionMismatch { .. }));
    }

    #[tokio::test]
    async fn register_token_rpc_returns_handle() {
        let (kernel, addr) = boot_test_server().await;
        let mut ch = Channel::connect(&addr).await.unwrap();
        do_handshake(&mut ch).await;

        // Mint on the same kernel instance the server holds, then register via RPC.
        let token = kernel
            .mint_token_confirmed(
                intentos_kernel::Intent {
                    actor: "reg-app".into(),
                    resource: "file".into(),
                    action: "read".into(),
                    anchor: intentos_kernel::TrustAnchor::UiEvent,
                    timestamp_ms: wall_ms(),
                    metadata: Default::default(),
                },
                false,
            )
            .unwrap();
        let mut cbor = Vec::new();
        ciborium::ser::into_writer(&token, &mut cbor).unwrap();

        let req = KernelRpcRequest::RegisterToken {
            call_id: uuid::Uuid::new_v4(),
            token_jti: token.jti.clone(),
            token_cbor: cbor,
        };
        ch.send_json(&req).await.unwrap();
        let resp: KernelRpcResponse = ch.recv_json().await.unwrap();
        match resp {
            KernelRpcResponse::Ok(v) => {
                assert_eq!(v["registered"], true);
                assert!(v["handle"].as_u64().is_some());
                assert_eq!(v["jti"], token.jti);
            }
            other => panic!("register failed: {other:?}"),
        }
    }

    #[tokio::test]
    async fn serve_mtls_health_roundtrip() {
        use ikrl_transport::{dev_pki::DevPki, SecureChannel, SecureListener};

        let dir = tempfile::tempdir().unwrap();
        let paths = DevPki::generate().unwrap().materialize(dir.path()).unwrap();
        let kernel = Arc::new(Kernel::boot().unwrap());
        let listener = SecureListener::bind("tcp://127.0.0.1:0", &paths.server_mtls_config())
            .await
            .unwrap();
        let local = listener.local_addr().unwrap();
        let addr = format!("tcp://{local}");
        let k2 = Arc::clone(&kernel);
        tokio::spawn(async move { serve_mtls(k2, listener).await });
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;

        let mut ch = SecureChannel::connect(&addr, &paths.client_mtls_config())
            .await
            .unwrap();
        // Client-side fingerprint population is best-effort in the prototype TLS wrapper.
        let _ = ch.peer_cert_fingerprint();
        do_handshake_secure(&mut ch).await;
        ch.send_json(&KernelRpcRequest::Health).await.unwrap();
        let resp: KernelRpcResponse = ch.recv_json().await.unwrap();
        assert!(resp.is_ok(), "{resp:?}");
    }

    async fn do_handshake_secure(ch: &mut ikrl_transport::SecureChannel) {
        let hs = Handshake {
            protocol_version: PROTOCOL_VERSION,
            client_id: "mtls-test".into(),
        };
        ch.send_json(&hs).await.unwrap();
        let _ack: HandshakeAck = ch.recv_json().await.unwrap();
    }

    #[tokio::test]
    async fn federation_hello_over_tcp_framing() {
        use intentos_kernel::{FederationCluster, FederationRole, HelloMessage, WelcomeMessage};

        let leader = FederationCluster::new(FederationRole::Leader, vec!["file:read".into()]);
        let worker = FederationCluster::new(FederationRole::Worker, vec!["file:read".into()]);

        let listener = Listener::bind("tcp://127.0.0.1:0").await.unwrap();
        let local = listener.local_addr().unwrap();
        let addr = format!("tcp://{local}");

        let server = tokio::spawn(async move {
            let mut ch = listener.accept().await.unwrap();
            let hello: HelloMessage = ch.recv_json().await.unwrap();
            let welcome = leader.process_hello(hello);
            ch.send_json(&welcome).await.unwrap();
            leader.cluster_id()
        });

        let hello = worker.build_hello();
        let client = tokio::spawn(async move {
            let mut ch = Channel::connect(&addr).await.unwrap();
            ch.send_json(&hello).await.unwrap();
            let welcome: WelcomeMessage = ch.recv_json().await.unwrap();
            welcome
        });

        let (leader_cluster, welcome) = tokio::join!(server, client);
        let leader_cid = leader_cluster.unwrap();
        let welcome = welcome.unwrap();
        worker.process_welcome(welcome);
        assert!(worker.cluster_id().is_some());
        assert_eq!(worker.cluster_id(), leader_cid);
    }
}
