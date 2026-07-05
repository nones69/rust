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

/// All syscalls the dispatch layer can process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IkSyscall {
    IkOpen { path: String, mode: OpenMode },
    IkRead { handle: Uuid, len: u64 },
    IkWrite { handle: Uuid, data: Vec<u8> },
    IkClose { handle: Uuid },
    IkPolicyExplain { syscall: Box<IkSyscall> },
    IkAiInfer { prompt: String, max_tokens: Option<u64> },
    IkNetRequest {
        method: HttpMethod,
        url: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
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
