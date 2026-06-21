//! # intentkernel-crypto
//!
//! Post-quantum cryptographic primitives for the IntentKernel ecosystem.
//!
//! This crate implements the NIST-standardized algorithms mandated by the
//! IntentKernel architecture:
//!
//! | Function          | Algorithm         | Standard       |
//! |-------------------|-------------------|----------------|
//! | Signatures        | ML-DSA-87 (Dilithium 5) | FIPS 204 |
//! | Key Encapsulation | ML-KEM-1024 (Kyber)     | FIPS 203 |
//! | Hashing           | SHA3-384 / SHA3-512     | FIPS 202 |
//! | Symmetric         | AES-256-GCM             | FIPS 197 |
//!
//! For the reference implementation, the ML-DSA-87 and ML-KEM-1024
//! operations are **algorithm-compatible mocks** that produce the same
//! wire-format sizes and verification semantics as the real algorithms,
//! but use a hash-based construction tied to a deterministic test seed.
//! This lets the rest of the system exercise token issuance, validation,
//! and federation without requiring the `liboqs` native dependency.
//! A production build MUST link against a certified ML-DSA/ML-KEM library.
//!
//! To use a real PQC backend, build with `--features oqs` and ensure `liboqs`
//! is installed on the host. Without the feature, the crate uses
//! algorithm-compatible mocks.

#[cfg(feature = "oqs")]
mod oqs_impl;

use aes_gcm::{
    aead::{Aead, AeadInPlace, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::{rngs::OsRng, TryRngCore};
use sha3::{Digest, Sha3_256, Sha3_384, Sha3_512};
use std::fmt;

#[cfg(not(feature = "oqs"))]
use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, Verifier, VerifyingKey};

pub const ML_DSA_87_PUBLIC_KEY_LEN: usize = 2592;
pub const ML_DSA_87_SECRET_KEY_LEN: usize = 4896;
pub const ML_DSA_87_SIGNATURE_LEN: usize = 4595;

pub const ML_KEM_1024_PUBLIC_KEY_LEN: usize = 1568;
pub const ML_KEM_1024_SECRET_KEY_LEN: usize = 3168;
pub const ML_KEM_1024_CIPHERTEXT_LEN: usize = 1568;
pub const ML_KEM_1024_SHARED_SECRET_LEN: usize = 32;

/// Cryptographic error type.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("invalid key length")]
    InvalidKeyLength,
    #[error("invalid signature length")]
    InvalidSignatureLength,
    #[error("signature verification failed")]
    SignatureVerificationFailed,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("rng failure: {0}")]
    RngFailure(String),
}

/// Fill a buffer with cryptographically secure random bytes.
pub fn secure_random(buf: &mut [u8]) -> Result<(), CryptoError> {
    OsRng
        .try_fill_bytes(buf)
        .map_err(|e| CryptoError::RngFailure(e.to_string()))
}

/// Return a vector of secure random bytes.
pub fn secure_random_vec(len: usize) -> Result<Vec<u8>, CryptoError> {
    let mut v = vec![0u8; len];
    secure_random(&mut v)?;
    Ok(v)
}

/// Compute SHA3-256 digest.
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(data);
    h.finalize().into()
}

/// Compute SHA3-384 digest.
pub fn sha3_384(data: &[u8]) -> [u8; 48] {
    let mut h = Sha3_384::new();
    h.update(data);
    h.finalize().into()
}

/// Compute SHA3-512 digest.
pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    let mut h = Sha3_512::new();
    h.update(data);
    h.finalize().into()
}

/// AES-256-GCM encryption. Returns (ciphertext, tag, nonce).
pub fn aes_256_gcm_encrypt(
    key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, [u8; 16], [u8; 12]), CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength)?;
    let mut nonce = [0u8; 12];
    secure_random(&mut nonce)?;
    let nonce_obj = Nonce::from_slice(&nonce);
    let mut payload = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(nonce_obj, aad, &mut payload)
        .map_err(|_| CryptoError::RngFailure("aes encrypt".into()))?;
    Ok((payload, tag.into(), nonce))
}

/// AES-256-GCM decryption.
pub fn aes_256_gcm_decrypt(
    key: &[u8; 32],
    ciphertext: &[u8],
    aad: &[u8],
    nonce: &[u8; 12],
    tag: &[u8; 16],
) -> Result<Vec<u8>, CryptoError> {
    use aes_gcm::aead::Payload;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength)?;
    let nonce_obj = Nonce::from_slice(nonce);
    let mut payload_vec = ciphertext.to_vec();
    payload_vec.extend_from_slice(tag);
    let payload = Payload {
        msg: &payload_vec,
        aad,
    };
    cipher
        .decrypt(nonce_obj, payload)
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// ML-DSA-87 key pair.
#[derive(Clone)]
pub struct MlDsa87KeyPair {
    pub public_key: [u8; ML_DSA_87_PUBLIC_KEY_LEN],
    pub secret_key: [u8; ML_DSA_87_SECRET_KEY_LEN],
}

impl fmt::Debug for MlDsa87KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsa87KeyPair")
            .field("public_key", &hex::encode(&self.public_key[..16]))
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

/// Generate an ML-DSA-87 key pair.
#[cfg(not(feature = "oqs"))]
pub fn ml_dsa87_keygen() -> Result<MlDsa87KeyPair, CryptoError> {
    // Generate a 32-byte Ed25519 seed from secure randomness.
    // This seed will be the true secret key material.
    let mut ed25519_seed = [0u8; 32];
    secure_random(&mut ed25519_seed)?;
    
    // Create an Ed25519 signing key from the seed.
    let signing_key = SigningKey::from_bytes(&ed25519_seed);
    let verifying_key = signing_key.verifying_key();
    
    // Populate the ML_DSA_87_SECRET_KEY_LEN buffer:
    // - First 32 bytes: Ed25519 seed (the true secret)
    // - Next 32 bytes: Ed25519 public key
    // - Remaining bytes: random padding (not used cryptographically)
    let mut sk = [0u8; ML_DSA_87_SECRET_KEY_LEN];
    sk[..32].copy_from_slice(&ed25519_seed);
    sk[32..64].copy_from_slice(verifying_key.as_bytes());
    
    // Fill the rest with random data for plausible deniability
    let mut remaining = vec![0u8; ML_DSA_87_SECRET_KEY_LEN - 64];
    secure_random(&mut remaining)?;
    sk[64..].copy_from_slice(&remaining);
    
    // Populate the ML_DSA_87_PUBLIC_KEY_LEN buffer:
    // - First 32 bytes: Ed25519 public key
    // - Remaining bytes: random padding
    let mut pk = [0u8; ML_DSA_87_PUBLIC_KEY_LEN];
    pk[..32].copy_from_slice(verifying_key.as_bytes());
    
    let mut pk_remaining = vec![0u8; ML_DSA_87_PUBLIC_KEY_LEN - 32];
    secure_random(&mut pk_remaining)?;
    pk[32..].copy_from_slice(&pk_remaining);
    
    Ok(MlDsa87KeyPair {
        public_key: pk,
        secret_key: sk,
    })
}

#[cfg(feature = "oqs")]
pub fn ml_dsa87_keygen() -> Result<MlDsa87KeyPair, CryptoError> {
    oqs_impl::ml_dsa87_keygen()
}

/// Sign a message with ML-DSA-87.
///
/// **SECURITY NOTICE**: This implementation uses Ed25519 for the default build.
/// The old mock-based signature was INSECURE and FORGEABLE:
/// - It derived signatures from SHA3(message) and SHA3(public_key) only
/// - Verification never checked the secret key
/// - Anyone with the public key could forge any valid-looking signature
///
/// The new implementation properly binds signatures to the secret key:
/// - Uses Ed25519-Dalek's constant-time signing
/// - Requires the secret key for every signature operation
/// - Verification cryptographically proves knowledge of the secret key
#[cfg(not(feature = "oqs"))]
pub fn ml_dsa87_sign(
    secret_key: &[u8; ML_DSA_87_SECRET_KEY_LEN],
    message: &[u8],
) -> Result<[u8; ML_DSA_87_SIGNATURE_LEN], CryptoError> {
    // Extract the Ed25519 seed from the first 32 bytes of secret_key
    let ed25519_seed: [u8; 32] = secret_key[..32]
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength)?;
    
    // Reconstruct the signing key from the seed
    let signing_key = SigningKey::from_bytes(&ed25519_seed);
    
    // Sign the message using Ed25519
    let ed_sig: Ed25519Signature = signing_key.sign(message);
    
    // Populate the ML_DSA_87_SIGNATURE_LEN buffer with Ed25519 signature + padding
    let mut sig = [0u8; ML_DSA_87_SIGNATURE_LEN];
    
    // First 64 bytes: Ed25519 signature (64 bytes for Ed25519)
    sig[..64].copy_from_slice(&ed_sig.to_bytes());
    
    // Remaining bytes: derive from SHA-512(seed || message) for deterministic padding
    // This maintains wire-format compatibility without compromising security
    let mut ctx = Sha3_512::new();
    ctx.update(&ed25519_seed);
    ctx.update(message);
    let digest = ctx.finalize();
    fill_from_seed(&digest[..], b"ML-DSA-87-PAD", &mut sig[64..]);
    
    Ok(sig)
}

#[cfg(feature = "oqs")]
pub fn ml_dsa87_sign(
    secret_key: &[u8; ML_DSA_87_SECRET_KEY_LEN],
    message: &[u8],
) -> Result<[u8; ML_DSA_87_SIGNATURE_LEN], CryptoError> {
    oqs_impl::ml_dsa87_sign(secret_key, message)
}

/// Verify an ML-DSA-87 signature.
///
/// **SECURITY**: This verification properly checks the Ed25519 signature
/// against the public key. It CANNOT be bypassed by providing a forged signature
/// without knowledge of the corresponding secret key.
#[cfg(not(feature = "oqs"))]
pub fn ml_dsa87_verify(
    public_key: &[u8; ML_DSA_87_PUBLIC_KEY_LEN],
    message: &[u8],
    signature: &[u8; ML_DSA_87_SIGNATURE_LEN],
) -> Result<(), CryptoError> {
    // Extract the Ed25519 public key from the first 32 bytes
    let ed25519_pk_bytes: [u8; 32] = public_key[..32]
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength)?;
    
    // Reconstruct the verifying key
    let verifying_key = VerifyingKey::from_bytes(&ed25519_pk_bytes)
        .map_err(|_| CryptoError::InvalidKeyLength)?;
    
    // Extract the Ed25519 signature from the first 64 bytes
    let ed_sig_bytes: [u8; 64] = signature[..64]
        .try_into()
        .map_err(|_| CryptoError::InvalidSignatureLength)?;
    let ed_sig = Ed25519Signature::from_bytes(&ed_sig_bytes);
    
    // Verify the signature using Ed25519
    verifying_key
        .verify(message, &ed_sig)
        .map_err(|_| CryptoError::SignatureVerificationFailed)
}

#[cfg(feature = "oqs")]
pub fn ml_dsa87_verify(
    public_key: &[u8; ML_DSA_87_PUBLIC_KEY_LEN],
    message: &[u8],
    signature: &[u8; ML_DSA_87_SIGNATURE_LEN],
) -> Result<(), CryptoError> {
    oqs_impl::ml_dsa87_verify(public_key, message, signature)
}

#[cfg(not(feature = "oqs"))]
fn fill_from_seed(seed: &[u8], domain: &[u8], out: &mut [u8]) {
    let mut offset = 0usize;
    let mut counter = 0u32;
    while offset < out.len() {
        let mut h = Sha3_512::new();
        h.update(seed);
        h.update(domain);
        h.update(counter.to_le_bytes());
        let digest = h.finalize();
        let chunk = std::cmp::min(64, out.len() - offset);
        out[offset..offset + chunk].copy_from_slice(&digest[..chunk]);
        offset += chunk;
        counter += 1;
    }
}

/// ML-KEM-1024 key pair (reference mock).
#[derive(Clone)]
pub struct MlKem1024KeyPair {
    pub public_key: [u8; ML_KEM_1024_PUBLIC_KEY_LEN],
    pub secret_key: [u8; ML_KEM_1024_SECRET_KEY_LEN],
}

/// Generate an ML-KEM-1024 key pair.
/// 
/// For the reference mock, we store the public key in the first 32 bytes of the secret key
/// to enable proper KEM round-trip semantics (encapsulation and decapsulation produce the
/// same shared secret).
#[cfg(not(feature = "oqs"))]
pub fn ml_kem1024_keygen() -> Result<MlKem1024KeyPair, CryptoError> {
    let mut seed = [0u8; 64];
    secure_random(&mut seed)?;
    
    let mut pk = [0u8; ML_KEM_1024_PUBLIC_KEY_LEN];
    fill_from_seed(&seed, b"ML-KEM-1024-PK", &mut pk);
    
    let mut sk = [0u8; ML_KEM_1024_SECRET_KEY_LEN];
    // Store public key in first 32 bytes of secret key (for round-trip derivation)
    sk[..32].copy_from_slice(&pk[..32]);
    // Fill the rest with deterministic derivation
    fill_from_seed(&seed, b"ML-KEM-1024-SK", &mut sk[32..]);
    
    Ok(MlKem1024KeyPair {
        public_key: pk,
        secret_key: sk,
    })
}

#[cfg(feature = "oqs")]
pub fn ml_kem1024_keygen() -> Result<MlKem1024KeyPair, CryptoError> {
    oqs_impl::ml_kem1024_keygen()
}

/// ML-KEM-1024 encapsulation.
///
/// Reference mock construction:
/// - Samples `ephemeral_secret` and `nonce`
/// - Derives ciphertext and shared secret from (ephemeral_secret, public_key, nonce)
/// - Encodes ephemeral_secret and nonce into ciphertext for decapsulation
#[cfg(not(feature = "oqs"))]
pub fn ml_kem1024_encapsulate(
    public_key: &[u8; ML_KEM_1024_PUBLIC_KEY_LEN],
) -> Result<
    (
        [u8; ML_KEM_1024_CIPHERTEXT_LEN],
        [u8; ML_KEM_1024_SHARED_SECRET_LEN],
    ),
    CryptoError,
> {
    let mut ephemeral_secret = [0u8; 32];
    let mut nonce = [0u8; 32];
    secure_random(&mut ephemeral_secret)?;
    secure_random(&mut nonce)?;

    let pk_seed: [u8; 32] = public_key[..32]
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength)?;

    let mut transcript_h = Sha3_256::new();
    transcript_h.update(&ephemeral_secret);
    transcript_h.update(&pk_seed);
    transcript_h.update(&nonce);
    let transcript = transcript_h.finalize();

    let mut ct = [0u8; ML_KEM_1024_CIPHERTEXT_LEN];
    ct[..32].copy_from_slice(&ephemeral_secret);
    ct[32..64].copy_from_slice(&nonce);
    fill_from_seed(&transcript[..], b"ML-KEM-1024-CT", &mut ct[64..]);

    let mut ss = [0u8; ML_KEM_1024_SHARED_SECRET_LEN];
    fill_from_seed(&transcript[..], b"ML-KEM-1024-SS", &mut ss);

    Ok((ct, ss))
}

#[cfg(feature = "oqs")]
pub fn ml_kem1024_encapsulate(
    public_key: &[u8; ML_KEM_1024_PUBLIC_KEY_LEN],
) -> Result<
    (
        [u8; ML_KEM_1024_CIPHERTEXT_LEN],
        [u8; ML_KEM_1024_SHARED_SECRET_LEN],
    ),
    CryptoError,
> {
    oqs_impl::ml_kem1024_encapsulate(public_key)
}

/// ML-KEM-1024 decapsulation.
///
/// Recomputes the same shared secret from (secret_key, ciphertext)
/// by recovering the embedded `(ephemeral_secret, nonce)` from ciphertext
/// and the public-key seed from secret_key.
#[cfg(not(feature = "oqs"))]
pub fn ml_kem1024_decapsulate(
    secret_key: &[u8; ML_KEM_1024_SECRET_KEY_LEN],
    ciphertext: &[u8; ML_KEM_1024_CIPHERTEXT_LEN],
) -> Result<[u8; ML_KEM_1024_SHARED_SECRET_LEN], CryptoError> {
    let pk_seed: [u8; 32] = secret_key[..32]
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength)?;

    let ephemeral_secret: [u8; 32] = ciphertext[..32]
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength)?;
    let nonce: [u8; 32] = ciphertext[32..64]
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength)?;

    let mut transcript_h = Sha3_256::new();
    transcript_h.update(&ephemeral_secret);
    transcript_h.update(&pk_seed);
    transcript_h.update(&nonce);
    let transcript = transcript_h.finalize();

    let mut expected_ct_tail = [0u8; ML_KEM_1024_CIPHERTEXT_LEN - 64];
    fill_from_seed(&transcript[..], b"ML-KEM-1024-CT", &mut expected_ct_tail);
    if ciphertext[64..] != expected_ct_tail {
        return Err(CryptoError::DecryptionFailed);
    }

    let mut ss = [0u8; ML_KEM_1024_SHARED_SECRET_LEN];
    fill_from_seed(&transcript[..], b"ML-KEM-1024-SS", &mut ss);
    Ok(ss)
}

#[cfg(feature = "oqs")]
pub fn ml_kem1024_decapsulate(
    secret_key: &[u8; ML_KEM_1024_SECRET_KEY_LEN],
    ciphertext: &[u8; ML_KEM_1024_CIPHERTEXT_LEN],
) -> Result<[u8; ML_KEM_1024_SHARED_SECRET_LEN], CryptoError> {
    oqs_impl::ml_kem1024_decapsulate(secret_key, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha3_lengths() {
        let data = b"intentkernel";
        assert_eq!(sha3_256(data).len(), 32);
        assert_eq!(sha3_384(data).len(), 48);
        assert_eq!(sha3_512(data).len(), 64);
    }

    #[test]
    fn test_ml_dsa87_sign_verify() {
        let kp = ml_dsa87_keygen().unwrap();
        let msg = b"test message";
        let sig = ml_dsa87_sign(&kp.secret_key, msg).unwrap();
        assert!(ml_dsa87_verify(&kp.public_key, msg, &sig).is_ok());
        assert!(ml_dsa87_verify(&kp.public_key, b"other", &sig).is_err());
        
        // Additionally test that a modified signature fails verification
        let mut bad_sig = sig;
        bad_sig[0] ^= 0xFF; // Flip bits in the signature
        assert!(ml_dsa87_verify(&kp.public_key, msg, &bad_sig).is_err());
    }

    #[cfg(feature = "oqs")]
    #[test]
    fn test_oqs_ml_dsa_roundtrip() {
        let kp = ml_dsa87_keygen().unwrap();
        let msg = b"oqs production path";
        let sig = ml_dsa87_sign(&kp.secret_key, msg).unwrap();
        assert!(ml_dsa87_verify(&kp.public_key, msg, &sig).is_ok());
    }

    #[test]
    fn test_ml_kem1024_roundtrip() {
        let kp = ml_kem1024_keygen().unwrap();
        let (ct, ss_encap) = ml_kem1024_encapsulate(&kp.public_key).unwrap();
        let ss_decap = ml_kem1024_decapsulate(&kp.secret_key, &ct).unwrap();
        assert_eq!(
            ss_encap, ss_decap,
            "KEM round-trip failed: encapsulate and decapsulate produced different shared secrets"
        );
    }

    #[test]
    fn test_ml_kem1024_modified_ciphertext_rejected() {
        let kp = ml_kem1024_keygen().unwrap();
        let (mut ct, ss_encap) = ml_kem1024_encapsulate(&kp.public_key).unwrap();

        ct[ML_KEM_1024_CIPHERTEXT_LEN - 1] ^= 0x01;

        match ml_kem1024_decapsulate(&kp.secret_key, &ct) {
            Ok(ss_decap) => assert_ne!(
                ss_encap, ss_decap,
                "modified ciphertext unexpectedly produced original shared secret"
            ),
            Err(CryptoError::DecryptionFailed) => {}
            Err(other) => panic!("unexpected error type for tampered ciphertext: {other:?}"),
        }
    }

    #[test]
    fn test_aes_gcm_roundtrip() {
        let key = [0x42u8; 32];
        let pt = b"secret capability payload";
        let aad = b"metadata";
        let (ct, tag, nonce) = aes_256_gcm_encrypt(&key, pt, aad).unwrap();
        let pt2 = aes_256_gcm_decrypt(&key, &ct, aad, &nonce, &tag).unwrap();
        assert_eq!(pt2, pt);
    }
}
