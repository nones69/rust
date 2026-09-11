//! # Federation — Remote Kernel Federation Layer
//!
//! This module turns IntentKernel into a multi-kernel mesh.  Each node:
//!
//! * establishes cryptographic identity through a `kernel_id` UUID.
//! * performs a two-step handshake (`IkFederationHello` / `IkFederationWelcome`).
//! * replicates policy hashes across the cluster.
//! * replicates append-only audit log entries to all peers.
//! * forwards governed syscalls to remote kernels (`IkForward`).
//! * delegates sandboxed tasks to worker nodes (`IkTaskDelegate`).
//! * maintains heartbeat connections to all known peers.
//!
//! The implementation is intentionally self-contained so that it can be
//! composed with the existing `Kernel` type without breaking any existing
//! public API.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Sandbox mode for federated task delegation (local to federation mesh).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FedSandboxMode {
    Strict,
    Permissive,
    Wasm,
}

/// Task priority for federated delegation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FedTaskPriority {
    Low,
    #[default]
    Normal,
    High,
}

// ─── Federation roles ──────────────────────────────────────────────────────

/// The role this node plays in the federation cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FederationRole {
    /// Coordinates cluster policy, schedules workloads, and owns the
    /// authoritative audit log chain.
    Leader,
    /// Executes delegated tasks, enforces policy, replicates audit logs.
    Worker,
    /// Full participant in the mesh; forwards syscalls and shares state.
    Peer,
}

impl FederationRole {
    pub fn as_str(self) -> &'static str {
        match self {
            FederationRole::Leader => "leader",
            FederationRole::Worker => "worker",
            FederationRole::Peer => "peer",
        }
    }
}

impl std::fmt::Display for FederationRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─── Peer descriptor ───────────────────────────────────────────────────────

/// A remote kernel that this node knows about.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationPeer {
    /// Stable identifier for the remote kernel.
    pub kernel_id: Uuid,
    /// TCP address (host:port) for the federation transport channel.
    pub addr: String,
    /// Role the peer advertised during the handshake.
    pub role: FederationRole,
    /// Protocol version string the peer reported.
    pub version: String,
    /// Wall-clock milliseconds of the last successful heartbeat.
    pub last_seen_ms: u64,
    /// Capability scopes the peer advertised.
    pub capabilities: Vec<String>,
}

// ─── Replicated audit entry ────────────────────────────────────────────────

/// A single audit-log entry that can be replicated across nodes.
///
/// Entries form an append-only hash chain: each entry's `prev_hash` field
/// commits to the hash of the entry immediately before it, giving
/// tamper-evidence across the distributed log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedAuditEntry {
    pub seq: u64,
    pub timestamp_ms: u64,
    /// JTI of the capability token that caused this event (if any).
    pub token_jti: Option<String>,
    /// Syscall variant name (e.g. `"IkOpen"`).
    pub syscall: String,
    /// Outcome: `"allowed"` or `"denied:<reason>"`.
    pub result: String,
    /// SHA3-256 hex of the previous entry (or all-zeros for the genesis entry).
    pub prev_hash: String,
    /// Originating kernel ID.
    pub node_id: Uuid,
    /// Ed25519 / PQC signature over the canonical JSON of this entry
    /// (excluding the `signature` field itself), encoded as hex.
    pub signature: String,
}

// ─── Handshake messages ────────────────────────────────────────────────────

/// Sent by a node that wants to join or announce itself to a peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloMessage {
    pub kernel_id: Uuid,
    pub role: FederationRole,
    pub version: String,
    pub capabilities: Vec<String>,
    /// Current policy hash so the receiver can detect divergence.
    pub policy_hash: String,
}

/// Reply from the peer that accepted the hello.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WelcomeMessage {
    pub cluster_id: Uuid,
    pub kernel_id: Uuid,
    pub role: FederationRole,
    pub peers: Vec<FederationPeer>,
    /// Authoritative policy hash for the cluster.
    pub policy_hash: String,
}

// ─── Heartbeat ─────────────────────────────────────────────────────────────

/// Periodic keep-alive carrying the sender's current policy hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatMessage {
    pub kernel_id: Uuid,
    pub timestamp_ms: u64,
    pub policy_hash: String,
}

// ─── Policy replication ────────────────────────────────────────────────────

/// Broadcast from the leader when the cluster policy changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyUpdate {
    pub cluster_id: Uuid,
    /// New serialised policy (format is implementation-defined).
    pub policy_json: String,
    /// SHA3-256 hex of `policy_json`.
    pub policy_hash: String,
    /// Hex signature over `policy_hash` by the leader's identity key.
    pub signature: String,
    pub from: Uuid,
}

// ─── Task delegation ───────────────────────────────────────────────────────

/// Request to run a sandboxed program on a remote worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskDelegation {
    pub task_id: Uuid,
    pub from_kernel: Uuid,
    pub target_kernel: Uuid,
    pub program: String,
    pub args: Vec<String>,
    pub mode: FedSandboxMode,
    pub priority: FedTaskPriority,
    /// Capability token JTI that authorises this delegation.
    pub token_jti: String,
}

/// Result returned by the worker after task completion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResult {
    pub task_id: Uuid,
    pub success: bool,
    pub output: String,
    pub exit_code: i32,
}

// ─── Forwarded syscall ─────────────────────────────────────────────────────

/// A governed syscall forwarded from one kernel to another.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardedSyscall {
    pub call_id: Uuid,
    pub from_kernel: Uuid,
    pub target_kernel: Uuid,
    pub token_jti: String,
    /// Opaque syscall payload (JSON), so federation stays free of envelope coupling.
    pub syscall: serde_json::Value,
}

/// Result of a forwarded syscall execution on the target kernel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardResult {
    pub call_id: Uuid,
    pub allowed: bool,
    pub result: serde_json::Value,
}

// ─── Federation cluster state ──────────────────────────────────────────────

/// All federation state for a single kernel node.
pub struct FederationCluster {
    inner: Arc<Mutex<ClusterState>>,
}

struct ClusterState {
    /// This kernel's stable ID.
    pub kernel_id: Uuid,
    /// The cluster this kernel belongs to (set after the first welcome).
    pub cluster_id: Option<Uuid>,
    /// This node's role.
    pub role: FederationRole,
    /// Protocol version string.
    pub version: String,
    /// Capability scopes this kernel supports.
    pub capabilities: Vec<String>,
    /// Known peer table (keyed by `kernel_id`).
    pub peers: HashMap<Uuid, FederationPeer>,
    /// SHA3-256 hex of the current cluster policy.
    pub policy_hash: String,
    /// Append-only local log of replicated audit entries.
    pub audit_chain: Vec<FederatedAuditEntry>,
    /// Pending outbound task delegations.
    pub pending_tasks: HashMap<Uuid, TaskDelegation>,
}

impl FederationCluster {
    /// Create a new cluster node with a freshly generated identity.
    pub fn new(role: FederationRole, capabilities: Vec<String>) -> Self {
        Self::with_id(Uuid::new_v4(), role, capabilities)
    }

    /// Create a node with a specific kernel ID (useful for deterministic tests).
    pub fn with_id(kernel_id: Uuid, role: FederationRole, capabilities: Vec<String>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ClusterState {
                kernel_id,
                cluster_id: None,
                role,
                version: env!("CARGO_PKG_VERSION").to_string(),
                capabilities,
                peers: HashMap::new(),
                policy_hash: String::new(),
                audit_chain: Vec::new(),
                pending_tasks: HashMap::new(),
            })),
        }
    }

    // ── Identity ────────────────────────────────────────────────────────────

    pub fn kernel_id(&self) -> Uuid {
        self.inner.lock().unwrap().kernel_id
    }

    pub fn cluster_id(&self) -> Option<Uuid> {
        self.inner.lock().unwrap().cluster_id
    }

    pub fn role(&self) -> FederationRole {
        self.inner.lock().unwrap().role
    }

    // ── Handshake ───────────────────────────────────────────────────────────

    /// Build the `HelloMessage` this node sends to a peer.
    pub fn build_hello(&self) -> HelloMessage {
        let s = self.inner.lock().unwrap();
        HelloMessage {
            kernel_id: s.kernel_id,
            role: s.role,
            version: s.version.clone(),
            capabilities: s.capabilities.clone(),
            policy_hash: s.policy_hash.clone(),
        }
    }

    /// Process an incoming `HelloMessage` and produce a `WelcomeMessage`.
    ///
    /// Registers the sender as a peer.  Returns the welcome to send back.
    pub fn process_hello(&self, hello: HelloMessage) -> WelcomeMessage {
        let mut s = self.inner.lock().unwrap();

        // Ensure we have a cluster ID.
        let cluster_id = s.cluster_id.get_or_insert_with(Uuid::new_v4).to_owned();

        let peer = FederationPeer {
            kernel_id: hello.kernel_id,
            addr: String::new(), // caller fills in the actual addr if needed
            role: hello.role,
            version: hello.version,
            last_seen_ms: crate::types::wall_ms(),
            capabilities: hello.capabilities,
        };
        s.peers.insert(peer.kernel_id, peer);

        let peers_snapshot: Vec<FederationPeer> = s.peers.values().cloned().collect();

        WelcomeMessage {
            cluster_id,
            kernel_id: s.kernel_id,
            role: s.role,
            peers: peers_snapshot,
            policy_hash: s.policy_hash.clone(),
        }
    }

    /// Process an incoming `WelcomeMessage` (sent back to the original sender).
    pub fn process_welcome(&self, welcome: WelcomeMessage) {
        let mut s = self.inner.lock().unwrap();
        s.cluster_id = Some(welcome.cluster_id);
        // Merge peer list from the welcome without overwriting ourselves.
        for peer in welcome.peers {
            if peer.kernel_id != s.kernel_id {
                s.peers.entry(peer.kernel_id).or_insert(peer);
            }
        }
        // Accept leader policy hash if we do not have one yet.
        if s.policy_hash.is_empty() {
            s.policy_hash = welcome.policy_hash;
        }
    }

    // ── Peer management ─────────────────────────────────────────────────────

    /// Register or update a peer.
    pub fn add_peer(&self, mut peer: FederationPeer) {
        peer.last_seen_ms = crate::types::wall_ms();
        let mut s = self.inner.lock().unwrap();
        s.peers.insert(peer.kernel_id, peer);
    }

    /// Update the last-seen timestamp for an existing peer.
    pub fn touch_peer(&self, kernel_id: Uuid) {
        let mut s = self.inner.lock().unwrap();
        if let Some(p) = s.peers.get_mut(&kernel_id) {
            p.last_seen_ms = crate::types::wall_ms();
        }
    }

    /// Remove a peer that has left the cluster.
    pub fn remove_peer(&self, kernel_id: Uuid) {
        self.inner.lock().unwrap().peers.remove(&kernel_id);
    }

    /// Return a snapshot of all known peers.
    pub fn peers(&self) -> Vec<FederationPeer> {
        self.inner.lock().unwrap().peers.values().cloned().collect()
    }

    /// Return the peer count.
    pub fn peer_count(&self) -> usize {
        self.inner.lock().unwrap().peers.len()
    }

    // ── Heartbeat ───────────────────────────────────────────────────────────

    /// Build a heartbeat message for broadcasting to all peers.
    pub fn build_heartbeat(&self) -> HeartbeatMessage {
        let s = self.inner.lock().unwrap();
        HeartbeatMessage {
            kernel_id: s.kernel_id,
            timestamp_ms: crate::types::wall_ms(),
            policy_hash: s.policy_hash.clone(),
        }
    }

    /// Process an incoming heartbeat from a peer.
    ///
    /// Returns `true` if the peer's policy hash differs from ours (indicating
    /// that a policy sync is needed).
    pub fn process_heartbeat(&self, hb: HeartbeatMessage) -> bool {
        let mut s = self.inner.lock().unwrap();
        if let Some(peer) = s.peers.get_mut(&hb.kernel_id) {
            peer.last_seen_ms = hb.timestamp_ms;
        }
        // Signal policy divergence.
        !s.policy_hash.is_empty() && s.policy_hash != hb.policy_hash
    }

    // ── Policy replication ──────────────────────────────────────────────────

    /// Update local policy hash after verifying the update.
    ///
    /// In production, this must verify the leader's Ed25519/PQC signature
    /// over `update.policy_hash` before accepting the new policy.  The
    /// signature field is checked to be non-empty as a minimum guard; callers
    /// with access to the cluster's verification key should perform full
    /// cryptographic verification here.
    ///
    /// Returns `Err` if the update is unsigned (signature field empty).
    pub fn apply_policy_update(&self, update: &PolicyUpdate) -> Result<(), String> {
        if update.signature.is_empty() {
            return Err("policy update rejected: missing leader signature — \
                 apply_policy_update requires a signed PolicyUpdate"
                .to_string());
        }
        // TODO: verify update.signature over update.policy_hash with the
        // cluster leader's public key stored in cluster state before accepting.
        self.inner.lock().unwrap().policy_hash = update.policy_hash.clone();
        Ok(())
    }

    pub fn policy_hash(&self) -> String {
        self.inner.lock().unwrap().policy_hash.clone()
    }

    pub fn set_policy_hash(&self, hash: String) {
        self.inner.lock().unwrap().policy_hash = hash;
    }

    // ── Distributed audit log ───────────────────────────────────────────────

    /// Append a replicated audit entry to the local chain.
    ///
    /// The caller is responsible for supplying `prev_hash` (SHA3-256 hex of
    /// the previous entry) and the entry's `signature`.
    pub fn append_audit_entry(&self, entry: FederatedAuditEntry) {
        self.inner.lock().unwrap().audit_chain.push(entry);
    }

    /// Build a new audit chain entry for a local event.
    ///
    /// The signature field is left empty; callers with access to the kernel's
    /// private key should fill it in before broadcasting to peers.
    pub fn build_audit_entry(
        &self,
        syscall: impl Into<String>,
        result: impl Into<String>,
        token_jti: Option<String>,
    ) -> FederatedAuditEntry {
        let s = self.inner.lock().unwrap();
        let prev_hash = s
            .audit_chain
            .last()
            .map(|e| {
                use sha3::{Digest, Sha3_256};
                let json = serde_json::to_string(e).unwrap_or_default();
                let mut h = Sha3_256::new();
                h.update(json.as_bytes());
                hex::encode(h.finalize())
            })
            .unwrap_or_else(|| "0".repeat(64));

        FederatedAuditEntry {
            seq: s.audit_chain.len() as u64,
            timestamp_ms: crate::types::wall_ms(),
            token_jti,
            syscall: syscall.into(),
            result: result.into(),
            prev_hash,
            node_id: s.kernel_id,
            signature: String::new(),
        }
    }

    /// Return all audit entries stored locally.
    pub fn audit_chain(&self) -> Vec<FederatedAuditEntry> {
        self.inner.lock().unwrap().audit_chain.clone()
    }

    /// Verify the integrity of the local audit chain.
    ///
    /// Returns `Ok(())` when every entry's `prev_hash` matches the SHA3-256
    /// of the preceding entry.
    pub fn verify_chain(&self) -> Result<(), String> {
        use sha3::{Digest, Sha3_256};

        let s = self.inner.lock().unwrap();
        let genesis_hash = "0".repeat(64);
        let mut prev = genesis_hash.as_str().to_string();

        for entry in &s.audit_chain {
            if entry.prev_hash != prev {
                return Err(format!(
                    "chain broken at seq={}: expected prev_hash={} got {}",
                    entry.seq, prev, entry.prev_hash
                ));
            }
            let json = serde_json::to_string(entry).map_err(|e| e.to_string())?;
            let mut h = Sha3_256::new();
            h.update(json.as_bytes());
            prev = hex::encode(h.finalize());
        }
        Ok(())
    }

    // ── Task delegation ─────────────────────────────────────────────────────

    /// Build a `TaskDelegation` request and record it as pending.
    pub fn delegate_task(
        &self,
        target_kernel: Uuid,
        program: impl Into<String>,
        args: Vec<String>,
        mode: FedSandboxMode,
        priority: FedTaskPriority,
        token_jti: impl Into<String>,
    ) -> TaskDelegation {
        let task_id = Uuid::new_v4();
        let from_kernel = self.inner.lock().unwrap().kernel_id;
        let delegation = TaskDelegation {
            task_id,
            from_kernel,
            target_kernel,
            program: program.into(),
            args,
            mode,
            priority,
            token_jti: token_jti.into(),
        };
        self.inner
            .lock()
            .unwrap()
            .pending_tasks
            .insert(task_id, delegation.clone());
        delegation
    }

    /// Acknowledge a completed task and remove it from the pending map.
    pub fn complete_task(&self, result: &TaskResult) {
        self.inner
            .lock()
            .unwrap()
            .pending_tasks
            .remove(&result.task_id);
    }

    /// Return the number of tasks still awaiting a result.
    pub fn pending_task_count(&self) -> usize {
        self.inner.lock().unwrap().pending_tasks.len()
    }

    // ── Syscall helpers ─────────────────────────────────────────────────────

    /// Wrap a syscall as a `ForwardedSyscall` envelope addressed to a remote
    /// kernel, with a given capability token JTI authorising it.
    pub fn forward_syscall(
        &self,
        target_kernel: Uuid,
        syscall: serde_json::Value,
        token_jti: impl Into<String>,
    ) -> ForwardedSyscall {
        ForwardedSyscall {
            call_id: Uuid::new_v4(),
            from_kernel: self.inner.lock().unwrap().kernel_id,
            target_kernel,
            token_jti: token_jti.into(),
            syscall,
        }
    }

    // ── Status summary ──────────────────────────────────────────────────────

    /// Return a human-readable status summary.
    pub fn status(&self) -> FederationStatus {
        let s = self.inner.lock().unwrap();
        FederationStatus {
            kernel_id: s.kernel_id,
            cluster_id: s.cluster_id,
            role: s.role,
            peer_count: s.peers.len(),
            policy_hash: s.policy_hash.clone(),
            audit_chain_len: s.audit_chain.len(),
            pending_tasks: s.pending_tasks.len(),
        }
    }
}

/// Snapshot of a node's federation state for CLI / monitoring use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationStatus {
    pub kernel_id: Uuid,
    pub cluster_id: Option<Uuid>,
    pub role: FederationRole,
    pub peer_count: usize,
    pub policy_hash: String,
    pub audit_chain_len: usize,
    pub pending_tasks: usize,
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(role: FederationRole) -> FederationCluster {
        FederationCluster::new(role, vec!["file:read".into(), "ai:infer".into()])
    }

    #[test]
    fn hello_welcome_handshake() {
        let leader = make_node(FederationRole::Leader);
        let worker = make_node(FederationRole::Worker);

        let hello = worker.build_hello();
        let welcome = leader.process_hello(hello);

        assert!(leader.cluster_id().is_some());
        assert_eq!(leader.peer_count(), 1);

        worker.process_welcome(welcome);
        assert!(worker.cluster_id().is_some());
        assert_eq!(worker.cluster_id(), leader.cluster_id());
    }

    #[test]
    fn peer_management() {
        let node = make_node(FederationRole::Peer);
        let peer = FederationPeer {
            kernel_id: Uuid::new_v4(),
            addr: "127.0.0.1:9400".into(),
            role: FederationRole::Worker,
            version: "0.1.0".into(),
            last_seen_ms: 0,
            capabilities: vec![],
        };
        let id = peer.kernel_id;
        node.add_peer(peer);
        assert_eq!(node.peer_count(), 1);
        node.touch_peer(id);
        node.remove_peer(id);
        assert_eq!(node.peer_count(), 0);
    }

    #[test]
    fn heartbeat_detects_policy_divergence() {
        let node = make_node(FederationRole::Peer);
        node.set_policy_hash("aabbcc".into());

        let hb = HeartbeatMessage {
            kernel_id: Uuid::new_v4(),
            timestamp_ms: 0,
            policy_hash: "different_hash".into(),
        };
        assert!(node.process_heartbeat(hb));

        let hb_same = HeartbeatMessage {
            kernel_id: Uuid::new_v4(),
            timestamp_ms: 0,
            policy_hash: "aabbcc".into(),
        };
        assert!(!node.process_heartbeat(hb_same));
    }

    #[test]
    fn audit_chain_integrity() {
        let node = make_node(FederationRole::Leader);

        let e1 = node.build_audit_entry("IkOpen", "allowed", None);
        node.append_audit_entry(e1);

        let e2 = node.build_audit_entry("IkWrite", "allowed", Some("jti-abc".into()));
        node.append_audit_entry(e2);

        assert_eq!(node.audit_chain().len(), 2);
        assert!(node.verify_chain().is_ok());
    }

    #[test]
    fn task_delegation_lifecycle() {
        let node = make_node(FederationRole::Leader);
        let target = Uuid::new_v4();
        let delegation = node.delegate_task(
            target,
            "echo",
            vec!["hello".into()],
            FedSandboxMode::Strict,
            FedTaskPriority::Normal,
            "jti-1",
        );
        assert_eq!(node.pending_task_count(), 1);
        node.complete_task(&TaskResult {
            task_id: delegation.task_id,
            success: true,
            output: "ok".into(),
            exit_code: 0,
        });
        assert_eq!(node.pending_task_count(), 0);
    }

    #[test]
    fn policy_update_rejected_without_signature() {
        let node = make_node(FederationRole::Worker);
        let update = PolicyUpdate {
            cluster_id: Uuid::nil(),
            policy_json: "{}".into(),
            policy_hash: "deadbeef".into(),
            signature: String::new(),
            from: Uuid::new_v4(),
        };
        assert!(node.apply_policy_update(&update).is_err());
    }

    #[test]
    fn policy_update_accepted_with_signature() {
        let node = make_node(FederationRole::Worker);
        let update = PolicyUpdate {
            cluster_id: Uuid::nil(),
            policy_json: "{}".into(),
            policy_hash: "cafebabe".into(),
            signature: "signed".into(),
            from: Uuid::new_v4(),
        };
        assert!(node.apply_policy_update(&update).is_ok());
        assert_eq!(node.policy_hash(), "cafebabe");
    }

    #[test]
    fn status_reflects_state() {
        let node = make_node(FederationRole::Leader);
        let status = node.status();
        assert_eq!(status.role, FederationRole::Leader);
        assert_eq!(status.peer_count, 0);
    }

    #[test]
    fn forward_syscall_wraps_json_payload() {
        let node = make_node(FederationRole::Peer);
        let target = Uuid::new_v4();
        let fwd = node.forward_syscall(
            target,
            serde_json::json!({"op": "IkOpen", "path": "/tmp/x"}),
            "jti-x",
        );
        assert_eq!(fwd.target_kernel, target);
        assert_eq!(fwd.token_jti, "jti-x");
        assert_eq!(fwd.syscall["op"], "IkOpen");
    }
}
