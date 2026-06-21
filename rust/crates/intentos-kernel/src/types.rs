use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const CAP_TABLE_SIZE: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TrustAnchor {
    None = 0,
    UiEvent = 1,
    Biometric = 2,
    Hardware = 3,
    Federated = 4,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityScope {
    pub resource: String,
    pub action: String,
    pub constraints: BTreeMap<String, String>,
}

impl CapabilityScope {
    pub fn new(resource: &str, action: &str) -> Self {
        Self {
            resource: resource.to_string(),
            action: action.to_string(),
            constraints: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum LeaseState {
    Granted = 1,
    Expired = 3,
    Revoked = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TokenType {
    Capability = 1,
    Lease = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum CapabilityKind {
    FileRead = 0x0001,
    FileWrite = 0x0002,
    DirList = 0x0004,
    NetSend = 0x0102,
    AiInfer = 0x0502,
    LeaseBackground = 0x0C01,
    Unknown = 0xFFFF,
}

impl CapabilityKind {
    pub fn from_scope(resource: &str, action: &str) -> Self {
        match (resource, action) {
            ("file", "read") => Self::FileRead,
            ("file", "write") => Self::FileWrite,
            ("dir", "list") | ("file", "list") => Self::DirList,
            ("network", "send") | ("network", "descramble") => Self::NetSend,
            ("ai", "infer") => Self::AiInfer,
            ("lease", "background") => Self::LeaseBackground,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Token {
    pub ver: u8,
    pub typ: TokenType,
    pub anchor: TrustAnchor,
    pub iss: String,
    pub sub: String,
    pub scope: CapabilityScope,
    pub exp: u64,
    pub nbf: u64,
    pub uses: u32,
    pub jti: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Intent {
    pub actor: String,
    pub resource: String,
    pub action: String,
    pub anchor: TrustAnchor,
    pub timestamp_ms: u64,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub reason: String,
    pub ttl_ms: u64,
    pub max_uses: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Handle {
    pub slot: u32,
    pub generation: u16,
    pub checksum: u16,
}

impl Handle {
    pub fn as_u64(self) -> u64 {
        ((self.slot as u64) << 32) | ((self.generation as u64) << 16) | (self.checksum as u64)
    }

    pub fn from_u64(v: u64) -> Self {
        Self {
            slot: (v >> 32) as u32,
            generation: ((v >> 16) & 0xFFFF) as u16,
            checksum: (v & 0xFFFF) as u16,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SlotEntry {
    pub generation: u16,
    pub expires_ns: u64,
    pub uses_left: u32,
    pub kind: CapabilityKind,
    pub scope: CapabilityScope,
    pub token_jti: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessLease {
    pub lease_id: String,
    pub pid: u32,
    pub state: LeaseState,
    pub granted_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyscallOp {
    Read,
    Write,
    List,
    Send,
    Infer,
    Unknown(String),
}

impl SyscallOp {
    pub fn parse(name: &str) -> Self {
        match name {
            "read" => Self::Read,
            "write" => Self::Write,
            "list" => Self::List,
            "send" => Self::Send,
            "infer" => Self::Infer,
            other => Self::Unknown(other.to_string()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SyscallRequest {
    pub op: SyscallOp,
    pub target: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyscallResult {
    Allowed {
        kind: CapabilityKind,
        remaining_uses: u32,
    },
    Denied(String),
}

pub fn wall_ms() -> u64 {
    chrono::Utc::now().timestamp_millis() as u64
}

pub fn mono_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

pub fn handle_checksum(slot: u32, generation: u16) -> u16 {
    let bytes = [
        (slot >> 24) as u8,
        (slot >> 16) as u8,
        (slot >> 8) as u8,
        slot as u8,
        (generation >> 8) as u8,
        generation as u8,
    ];
    let mut s1 = 0u16;
    let mut s2 = 0u16;
    for b in bytes {
        s1 = (s1 + b as u16) % 255;
        s2 = (s2 + s1) % 255;
    }
    (s2 << 8) | s1
}