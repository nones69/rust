//! Syscall envelope types shared across the dispatch layer.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// File-open mode flags.
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

/// Sandbox isolation mode for delegated tasks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxMode {
    /// Strict capability-only isolation (default).
    Strict,
    /// Permissive mode for trusted workloads.
    Permissive,
    /// Read-only filesystem sandbox.
    ReadOnly,
}

/// Priority level for scheduled or delegated tasks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskPriority {
    Low,
    Normal,
    High,
    Critical,
}

/// All syscalls the dispatch layer can process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IkSyscall {
    IkOpen { path: String, mode: OpenMode },
    IkRead { handle: Uuid, len: u64 },
    IkWrite { handle: Uuid, data: Vec<u8> },
    IkClose { handle: Uuid },
    IkAiInfer { prompt: String, max_tokens: Option<u64> },
    IkNetRequest {
        method: HttpMethod,
        url: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    /// Federation handshake: this kernel announces itself to a peer.
    IkFederationHello {
        kernel_id: Uuid,
        capabilities: Vec<String>,
        version: String,
    },
    /// Federation handshake response: peer acknowledges cluster membership.
    IkFederationWelcome {
        cluster_id: Uuid,
        peers: Vec<String>,
        policy_hash: String,
    },
    /// Forward a governed syscall to a remote kernel for execution.
    IkForward {
        target_kernel: Uuid,
        syscall: Box<IkSyscall>,
    },
    /// Delegate a sandboxed task to a remote kernel.
    IkTaskDelegate {
        target_kernel: Uuid,
        program: String,
        args: Vec<String>,
        mode: SandboxMode,
        priority: TaskPriority,
    },
}

/// Wire envelope wrapping a token ID and a syscall.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IkCallEnvelope {
    pub token_id: Uuid,
    pub call: IkSyscall,
    pub call_id: Uuid,
    pub timestamp_ms: u128,
}
