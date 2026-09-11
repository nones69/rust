//! Syscall envelope types shared across the dispatch layer.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// File-open mode flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

/// All syscalls the dispatch layer can process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IkSyscall {
    IkOpen {
        path: String,
        mode: OpenMode,
    },
    IkRead {
        handle: Uuid,
        len: u64,
    },
    IkWrite {
        handle: Uuid,
        data: Vec<u8>,
    },
    IkClose {
        handle: Uuid,
    },
    IkAiInfer {
        model: String,
        prompt: String,
        max_tokens: Option<u64>,
    },
    IkNetRequest {
        method: HttpMethod,
        url: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    /// Federation hello — advertise this kernel into a mesh.
    IkFederationHello {
        kernel_id: uuid::Uuid,
        capabilities: Vec<String>,
        version: String,
    },
    /// Federation welcome — cluster assignment + peer list.
    IkFederationWelcome {
        cluster_id: uuid::Uuid,
        peers: Vec<String>,
        policy_hash: String,
    },
    /// Forward an opaque syscall JSON payload to a remote kernel id.
    IkForward {
        target_kernel: uuid::Uuid,
        syscall_json: serde_json::Value,
    },
    /// Delegate a sandboxed task to a remote worker.
    IkTaskDelegate {
        target_kernel: uuid::Uuid,
        program: String,
        args: Vec<String>,
        mode: String,
        priority: String,
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
