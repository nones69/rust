//! # intentkernel-core
//!
//! Core types, capability table, and token lifecycle for the IntentKernel
//! architecture. This crate implements the three inviolable laws:
//!
//! 1. No code has default authority.
//! 2. All authority is event-scoped.
//! 3. All authority expires automatically.

use chrono::Utc;
use intentkernel_crypto as crypto;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};

pub mod ip_policy;
pub use ip_policy::{
    ai_prompt_ip_allowed, apply_network_policy, evaluate_ip, extract_ipv4_literals,
    verdict_from_threat_score, IpVerdict, ThreatLevel, META_DEST_IP, META_THREAT_SCORE,
};

pub use intentkernel_crypto::{
    ml_dsa87_keygen, ml_dsa87_sign, ml_dsa87_verify, ml_kem1024_decapsulate,
    ml_kem1024_encapsulate, ml_kem1024_keygen, CryptoError, MlDsa87KeyPair, MlKem1024KeyPair,
    ML_DSA_87_PUBLIC_KEY_LEN, ML_DSA_87_SECRET_KEY_LEN, ML_DSA_87_SIGNATURE_LEN,
    ML_KEM_1024_CIPHERTEXT_LEN, ML_KEM_1024_PUBLIC_KEY_LEN, ML_KEM_1024_SECRET_KEY_LEN,
    ML_KEM_1024_SHARED_SECRET_LEN,
};

/// Maximum number of concurrent capabilities in the in-memory table.
pub const CAP_TABLE_SIZE: usize = 65536;

/// 256-bit capability key.
pub type CapKey = [u8; 32];

/// Capability types from the UCCS taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum CapabilityType {
    // Storage
    FileReadOnce = 0x0001,
    FileWriteOnce = 0x0002,
    FileCreate = 0x0003,
    DirListOnce = 0x0004,

    // Network
    NetConnectOnce = 0x0101,
    NetSendOnce = 0x0102,
    NetReceiveOnce = 0x0103,
    NetListenOnce = 0x0104,

    // Device
    CameraCaptureOnce = 0x0201,
    CameraStreamBurst = 0x0202,
    MicCaptureOnce = 0x0203,
    MicStreamBurst = 0x0204,
    LocationReadOnce = 0x0205,
    SensorReadOnce = 0x0206,

    // Display
    DisplayDraw = 0x0301,
    DisplayNotification = 0x0302,
    DisplayFullscreen = 0x0303,

    // Audio
    AudioPlayOnce = 0x0401,
    AudioPlayStream = 0x0402,

    // Compute
    ComputeAllocate = 0x0501,
    ComputeExecute = 0x0502,
    ComputeThreadCreate = 0x0503,

    // IPC
    IpcSendOnce = 0x0601,
    IpcReceiveOnce = 0x0602,

    // Hardware
    GpioSetOnce = 0x0701,
    GpioReadOnce = 0x0702,
    CanSendOnce = 0x0703,
    CanReceiveOnce = 0x0704,
    PwmSetOnce = 0x0705,
    I2cTransaction = 0x0706,
    SpiTransaction = 0x0707,
    DacSetOnce = 0x0708,
    AdcReadOnce = 0x0709,

    // Vehicle
    VehicleThrottleOnce = 0x0801,
    VehicleBrakeOnce = 0x0802,
    VehicleSteerOnce = 0x0803,
    VehicleLightOnce = 0x0804,

    // Industrial
    PlcWriteOnce = 0x0901,
    PlcReadOnce = 0x0902,
    ValveActuateOnce = 0x0903,
    MotorSetOnce = 0x0904,
    SensorPollOnce = 0x0905,

    // Cloud
    ContainerSpawn = 0x0A01,
    ServiceRegister = 0x0A02,
    DataQueryOnce = 0x0A03,
    ComputeScaleOnce = 0x0A04,

    // Cross-device
    DevicePair = 0x0B01,
    DeviceSendOnce = 0x0B02,
    DeviceReceiveOnce = 0x0B03,

    // Lease
    LeaseBackground = 0x0C01,

    // Revocation
    RevocationEntry = 0x0D01,
}

/// Intent trust anchor hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TrustAnchor {
    None = 0,
    UiEvent = 1,
    Biometric = 2,
    Hardware = 3,
    Federated = 4,
}

/// Resource scope for a capability.
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

    pub fn with_constraint(mut self, key: &str, value: &str) -> Self {
        self.constraints.insert(key.to_string(), value.to_string());
        self
    }
}

/// Lease state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum LeaseState {
    Requested = 0,
    Granted = 1,
    Renewing = 2,
    Expired = 3,
    Revoked = 4,
    Suspended = 5,
}

/// Canonical capability token (RFC-INTENT-001).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityToken {
    pub ver: u8,
    pub typ: TokenType,
    pub alg: u8,
    pub anchor: TrustAnchor,
    pub iss: String,
    pub sub: String,
    pub ctx: Vec<u8>,
    pub scope: CapabilityScope,
    pub exp: u64,
    pub nbf: u64,
    pub uses: u32,
    pub state: LeaseState,
    pub jti: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TokenType {
    Capability = 1,
    Lease = 2,
    Delegation = 3,
    Revocation = 4,
}

/// Kernel handle optimization (64-bit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelHandle {
    pub table_index: u32,
    pub generation: u16,
    pub checksum: u16,
}

impl KernelHandle {
    pub fn to_u64(self) -> u64 {
        ((self.table_index as u64) << 32)
            | ((self.generation as u64) << 16)
            | (self.checksum as u64)
    }
}

/// In-memory capability entry.
#[derive(Debug, Clone)]
pub struct CapabilityEntry {
    pub key: CapKey,
    pub expires: u64,
    pub capability_type: CapabilityType,
    pub uses: u32,
    pub id: u32,
    pub generation: u16,
    pub token: CapabilityToken,
}

/// Capability validation result.
#[derive(Debug, Clone)]
pub enum ValidationResult {
    Ok(CapabilityType),
    Expired,
    Exausted,
    InvalidKey,
    Revoked,
    NotYetValid,
}

/// Errors from the core capability engine.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("capability table full")]
    TableFull,
    #[error("invalid capability id")]
    InvalidId,
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("broker key not configured")]
    MissingBrokerKey,
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("policy denied")]
    PolicyDenied,
    #[error("token replay detected")]
    ReplayDetected,
}

/// Monotonic nanosecond timestamp. Replace with VDSO/vDSO call in production.
pub fn monotonic_now_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

/// Wall-clock epoch milliseconds.
pub fn wall_epoch_ms() -> u64 {
    Utc::now().timestamp_millis() as u64
}

/// Build a context hash from action parameters.
pub fn context_hash(
    app_id: &str,
    user_id: &str,
    device_id: &str,
    resource_id: &str,
    timestamp_ms: u64,
) -> Vec<u8> {
    let mut ctx = Vec::new();
    ctx.extend_from_slice(app_id.as_bytes());
    ctx.extend_from_slice(user_id.as_bytes());
    ctx.extend_from_slice(device_id.as_bytes());
    ctx.extend_from_slice(resource_id.as_bytes());
    ctx.extend_from_slice(&timestamp_ms.to_le_bytes());
    crypto::sha3_384(&ctx).to_vec()
}

/// Serialize a token to CBOR wire format.
pub fn token_to_cbor(token: &CapabilityToken) -> Result<Vec<u8>, CoreError> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(token, &mut buf)
        .map_err(|e| CoreError::Serialization(e.to_string()))?;
    Ok(buf)
}

/// Deserialize a token from CBOR wire format.
pub fn token_from_cbor(bytes: &[u8]) -> Result<CapabilityToken, CoreError> {
    ciborium::de::from_reader(bytes).map_err(|e| CoreError::Serialization(e.to_string()))
}

/// Compute a handle checksum (Fletcher-16 variant).
fn handle_checksum(index: u32, generation: u16) -> u16 {
    let bytes = [
        (index >> 24) as u8,
        (index >> 16) as u8,
        (index >> 8) as u8,
        index as u8,
        (generation >> 8) as u8,
        generation as u8,
    ];
    let mut sum1: u16 = 0;
    let mut sum2: u16 = 0;
    for b in bytes {
        sum1 = (sum1 + b as u16) % 255;
        sum2 = (sum2 + sum1) % 255;
    }
    (sum2 << 8) | sum1
}

/// The in-memory capability table.
pub struct CapabilityTable {
    slots: Vec<Mutex<Option<CapabilityEntry>>>,
    generations: Vec<RwLock<u16>>,
    broker_key: Arc<RwLock<Option<[u8; ML_DSA_87_PUBLIC_KEY_LEN]>>>,
    registered_jtis: Mutex<HashSet<String>>,
}

impl CapabilityTable {
    pub fn new() -> Self {
        let mut slots = Vec::with_capacity(CAP_TABLE_SIZE);
        let mut generations = Vec::with_capacity(CAP_TABLE_SIZE);
        for _ in 0..CAP_TABLE_SIZE {
            slots.push(Mutex::new(None));
            generations.push(RwLock::new(1));
        }
        Self {
            slots,
            generations,
            broker_key: Arc::new(RwLock::new(None)),
            registered_jtis: Mutex::new(HashSet::new()),
        }
    }

    pub fn set_broker_key(&self, key: [u8; ML_DSA_87_PUBLIC_KEY_LEN]) {
        *self.broker_key.write().unwrap() = Some(key);
    }

    /// Create and store a capability. Returns its table index.
    pub fn create(
        &self,
        capability_type: CapabilityType,
        ttl_ns: u64,
        uses: u32,
        token: CapabilityToken,
    ) -> Result<u32, CoreError> {
        let now = monotonic_now_ns();
        for i in 0..CAP_TABLE_SIZE {
            let mut slot = self.slots[i].lock().unwrap();
            let expired = slot.as_ref().map(|e| e.expires < now).unwrap_or(true);
            if expired {
                let mut key = [0u8; 32];
                crypto::secure_random(&mut key)?;
                let mut gen = self.generations[i].write().unwrap();
                *gen = gen.wrapping_add(1);
                let generation = *gen;
                let entry = CapabilityEntry {
                    key,
                    expires: now + ttl_ns,
                    capability_type,
                    uses,
                    id: i as u32,
                    generation,
                    token,
                };
                *slot = Some(entry);
                return Ok(i as u32);
            }
        }
        Err(CoreError::TableFull)
    }

    /// Validate a capability by key. On success, consume one use.
    pub fn validate(&self, id: u32, key: &CapKey) -> Result<CapabilityType, ValidationResult> {
        if id as usize >= CAP_TABLE_SIZE {
            return Err(ValidationResult::InvalidKey);
        }
        let mut slot = self.slots[id as usize].lock().unwrap();
        let entry = match slot.as_mut() {
            Some(e) => e,
            None => return Err(ValidationResult::InvalidKey),
        };

        let now = monotonic_now_ns();
        if entry.uses == 0 {
            return Err(ValidationResult::Exausted);
        }
        if entry.expires < now {
            return Err(ValidationResult::Expired);
        }
        if &entry.key != key {
            return Err(ValidationResult::InvalidKey);
        }

        entry.uses = entry.uses.saturating_sub(1);
        if entry.uses == 0 {
            entry.expires = 0;
        }

        Ok(entry.capability_type)
    }

    /// Validate via a kernel handle.
    pub fn validate_handle(
        &self,
        handle: KernelHandle,
    ) -> Result<CapabilityType, ValidationResult> {
        if handle.table_index as usize >= CAP_TABLE_SIZE {
            return Err(ValidationResult::InvalidKey);
        }
        if handle.checksum != handle_checksum(handle.table_index, handle.generation) {
            return Err(ValidationResult::InvalidKey);
        }
        let mut slot = self.slots[handle.table_index as usize].lock().unwrap();
        let entry = match slot.as_mut() {
            Some(e) => e,
            None => return Err(ValidationResult::InvalidKey),
        };
        if entry.generation != handle.generation {
            return Err(ValidationResult::InvalidKey);
        }
        let now = monotonic_now_ns();
        if entry.uses == 0 {
            return Err(ValidationResult::Exausted);
        }
        if entry.expires < now {
            return Err(ValidationResult::Expired);
        }

        entry.uses = entry.uses.saturating_sub(1);
        if entry.uses == 0 {
            entry.expires = 0;
        }

        Ok(entry.capability_type)
    }

    /// Register a full token in the kernel table and return a 64-bit handle.
    pub fn register_full_token(&self, token: &CapabilityToken) -> Result<KernelHandle, CoreError> {
        let pk = self
            .broker_key
            .read()
            .unwrap()
            .ok_or(CoreError::MissingBrokerKey)?;

        // Verify signature over the token payload (signature field excluded).
        let sig_bytes: [u8; ML_DSA_87_SIGNATURE_LEN] = token
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::InvalidSignature)?;
        let mut verify_token = token.clone();
        verify_token.signature.clear();
        let cbor = token_to_cbor(&verify_token)?;
        crypto::ml_dsa87_verify(&pk, &cbor, &sig_bytes).map_err(|_| CoreError::InvalidSignature)?;

        // Anti-replay: full tokens may only be registered once.
        {
            let mut jtis = self.registered_jtis.lock().unwrap();
            if !jtis.insert(token.jti.clone()) {
                return Err(CoreError::ReplayDetected);
            }
        }

        let id = self.create(
            token.scope_to_capability_type(),
            token.exp.saturating_sub(wall_epoch_ms()) * 1_000_000,
            token.uses,
            token.clone(),
        )?;
        let gen = *self.generations[id as usize].read().unwrap();
        let checksum = handle_checksum(id, gen);
        Ok(KernelHandle {
            table_index: id,
            generation: gen,
            checksum,
        })
    }

    /// Revoke a capability immediately.
    pub fn revoke(&self, id: u32) -> Result<(), CoreError> {
        if id as usize >= CAP_TABLE_SIZE {
            return Err(CoreError::InvalidId);
        }
        let mut slot = self.slots[id as usize].lock().unwrap();
        if let Some(e) = slot.as_mut() {
            e.expires = 0;
            e.uses = 0;
            e.key.fill(0);
        }
        Ok(())
    }

    /// Return a kernel handle for an existing entry if valid.
    pub fn get_handle(&self, id: u32) -> Result<KernelHandle, CoreError> {
        if id as usize >= CAP_TABLE_SIZE {
            return Err(CoreError::InvalidId);
        }
        let slot = self.slots[id as usize].lock().unwrap();
        let entry = slot.as_ref().ok_or(CoreError::InvalidId)?;
        Ok(KernelHandle {
            table_index: id,
            generation: entry.generation,
            checksum: handle_checksum(id, entry.generation),
        })
    }
}

impl Default for CapabilityTable {
    fn default() -> Self {
        Self::new()
    }
}

impl CapabilityToken {
    pub fn scope_to_capability_type(&self) -> CapabilityType {
        match (self.scope.resource.as_str(), self.scope.action.as_str()) {
            ("file", "read") => CapabilityType::FileReadOnce,
            ("file", "write") => CapabilityType::FileWriteOnce,
            ("network", "connect") => CapabilityType::NetConnectOnce,
            ("network", "send") => CapabilityType::NetSendOnce,
            ("camera", "capture") => CapabilityType::CameraCaptureOnce,
            ("display", "draw") => CapabilityType::DisplayDraw,
            ("compute", "allocate") => CapabilityType::ComputeAllocate,
            ("lease", "background") => CapabilityType::LeaseBackground,
            _ => CapabilityType::IpcSendOnce,
        }
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>, CoreError> {
        token_to_cbor(self)
    }
}

/// User intent event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentEvent {
    pub actor_id: String,
    pub action: String,
    pub resource: String,
    pub anchor: TrustAnchor,
    pub timestamp_ms: u64,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

/// Broker policy decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub reason: String,
    pub ttl_ms: u64,
    pub max_uses: u32,
    pub requires_confirmation: bool,
}

/// Default policy for a given intent (includes IP-Discrambler network rules).
pub fn default_policy(event: &IntentEvent) -> PolicyDecision {
    let (ttl, uses, confirm) = match (event.action.as_str(), event.resource.as_str()) {
        ("read", "file") => (5_000, 1, false),
        ("write", "file") => (10_000, 1, true),
        ("send", "network") => (30_000, 1, false),
        ("descramble", "network") => (15_000, 1, false),
        ("capture", "camera") => (2_000, 1, true),
        ("draw", "display") => (60_000, u32::MAX, false),
        ("actuate", "vehicle") => (100, 1, true),
        ("background", "lease") => (30_000, 1, false),
        _ => (5_000, 1, false),
    };
    let base = PolicyDecision {
        allowed: event.anchor as u8 >= TrustAnchor::UiEvent as u8,
        reason: "default policy".to_string(),
        ttl_ms: ttl,
        max_uses: uses,
        requires_confirmation: confirm,
    };
    ip_policy::apply_network_policy(event, &event.metadata, base)
}

/// A process lease.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessLease {
    pub lease_id: String,
    pub pid: u32,
    pub state: LeaseState,
    pub granted_at: u64,
    pub expires_at: u64,
    pub renew_interval_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use intentkernel_crypto as crypto;
    use std::collections::BTreeMap;

    #[test]
    fn test_default_policy_blocks_bogon_network_dest() {
        let mut meta = BTreeMap::new();
        meta.insert(META_DEST_IP.into(), "192.0.2.1".into());
        let event = IntentEvent {
            actor_id: "app".into(),
            action: "send".into(),
            resource: "network".into(),
            anchor: TrustAnchor::UiEvent,
            timestamp_ms: wall_epoch_ms(),
            metadata: meta,
        };
        let decision = default_policy(&event);
        assert!(!decision.allowed);
    }

    #[test]
    fn test_capability_lifecycle() {
        let table = CapabilityTable::new();
        let token = CapabilityToken {
            ver: 1,
            typ: TokenType::Capability,
            alg: 1,
            anchor: TrustAnchor::UiEvent,
            iss: "broker".into(),
            sub: "app".into(),
            ctx: vec![0u8; 48],
            scope: CapabilityScope::new("file", "read").with_constraint("path", "/tmp/x"),
            exp: wall_epoch_ms() + 5_000,
            nbf: wall_epoch_ms(),
            uses: 1,
            state: LeaseState::Granted,
            jti: uuid::Uuid::new_v4().to_string(),
            signature: vec![1u8; ML_DSA_87_SIGNATURE_LEN],
        };
        let id = table
            .create(
                CapabilityType::FileReadOnce,
                5_000_000_000,
                1,
                token.clone(),
            )
            .unwrap();
        let entry = table.slots[id as usize].lock().unwrap();
        let key = entry.as_ref().unwrap().key;
        drop(entry);
        assert_eq!(
            table.validate(id, &key).unwrap(),
            CapabilityType::FileReadOnce
        );
        assert!(matches!(
            table.validate(id, &key),
            Err(ValidationResult::Exausted)
        ));
    }

    #[test]
    fn roundtrip_sign_verify() {
        let kp = crypto::ml_dsa87_keygen().unwrap();
        let mut token = CapabilityToken {
            ver: 1,
            typ: TokenType::Capability,
            alg: 1,
            anchor: TrustAnchor::UiEvent,
            iss: "broker-1".into(),
            sub: "myapp".into(),
            ctx: b"ctx".to_vec(),
            scope: CapabilityScope {
                resource: "file".into(),
                action: "read".into(),
                constraints: [("actor".into(), "myapp".into())].into_iter().collect(),
            },
            exp: wall_epoch_ms() + 60_000,
            nbf: wall_epoch_ms(),
            uses: 1,
            state: LeaseState::Granted,
            jti: "test-jti".into(),
            signature: Vec::new(),
        };
        let mut sign_token = token.clone();
        sign_token.signature.clear();
        let cbor1 = token_to_cbor(&sign_token).unwrap();
        let sig = crypto::ml_dsa87_sign(&kp.secret_key, &cbor1).unwrap();
        token.signature = sig.to_vec();
        let cbor_full = token.to_cbor().unwrap();

        let parsed = token_from_cbor(&cbor_full).unwrap();
        assert_eq!(parsed.jti, token.jti);

        let mut verify_token = parsed.clone();
        verify_token.signature.clear();
        let cbor2 = token_to_cbor(&verify_token).unwrap();
        assert_eq!(cbor1, cbor2, "signed and verified CBOR payloads must match");

        let sig_arr: [u8; ML_DSA_87_SIGNATURE_LEN] =
            parsed.signature.as_slice().try_into().unwrap();
        assert!(crypto::ml_dsa87_verify(&kp.public_key, &cbor2, &sig_arr).is_ok());
    }

    #[test]
    fn register_full_token_roundtrip() {
        let table = CapabilityTable::new();
        let kp = crypto::ml_dsa87_keygen().unwrap();
        table.set_broker_key(kp.public_key);
        let mut token = CapabilityToken {
            ver: 1,
            typ: TokenType::Capability,
            alg: 1,
            anchor: TrustAnchor::UiEvent,
            iss: "broker-1".into(),
            sub: "myapp".into(),
            ctx: b"ctx".to_vec(),
            scope: CapabilityScope {
                resource: "file".into(),
                action: "read".into(),
                constraints: [("actor".into(), "myapp".into())].into_iter().collect(),
            },
            exp: wall_epoch_ms() + 60_000,
            nbf: wall_epoch_ms(),
            uses: 1,
            state: LeaseState::Granted,
            jti: uuid::Uuid::new_v4().to_string(),
            signature: Vec::new(),
        };
        let mut sign_token = token.clone();
        sign_token.signature.clear();
        let cbor = token_to_cbor(&sign_token).unwrap();
        let sig = crypto::ml_dsa87_sign(&kp.secret_key, &cbor).unwrap();
        token.signature = sig.to_vec();
        assert!(table.register_full_token(&token).is_ok());
    }
}
