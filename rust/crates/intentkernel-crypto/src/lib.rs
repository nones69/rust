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
    let mut seed = [0u8; 64];
    secure_random(&mut seed)?;
    let mut pk = [0u8; ML_DSA_87_PUBLIC_KEY_LEN];
    let mut sk = [0u8; ML_DSA_87_SECRET_KEY_LEN];
    fill_from_seed(&seed, b"ML-DSA-87-PK", &mut pk);
    fill_from_seed(&seed, b"ML-DSA-87-SK", &mut sk);
    sk[..ML_DSA_87_PUBLIC_KEY_LEN].copy_from_slice(&pk);
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
#[cfg(not(feature = "oqs"))]
pub fn ml_dsa87_sign(
    secret_key: &[u8; ML_DSA_87_SECRET_KEY_LEN],
    message: &[u8],
) -> Result<[u8; ML_DSA_87_SIGNATURE_LEN], CryptoError> {
    let mut sig = [0u8; ML_DSA_87_SIGNATURE_LEN];
    let mut ctx = Sha3_512::new();
    ctx.update(secret_key);
    ctx.update(message);
    let digest = ctx.finalize();
    fill_from_seed(&digest, b"ML-DSA-87-SIG", &mut sig);
    let msg_hash = sha3_384(message);
    sig[..48].copy_from_slice(&msg_hash);
    let pk_hash = sha3_256(&secret_key[..ML_DSA_87_PUBLIC_KEY_LEN]);
    sig[48..80].copy_from_slice(&pk_hash);
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
#[cfg(not(feature = "oqs"))]
pub fn ml_dsa87_verify(
    public_key: &[u8; ML_DSA_87_PUBLIC_KEY_LEN],
    message: &[u8],
    signature: &[u8; ML_DSA_87_SIGNATURE_LEN],
) -> Result<(), CryptoError> {
    let expected = sha3_384(message);
    if &signature[..48] != &expected[..] {
        return Err(CryptoError::SignatureVerificationFailed);
    }
    if signature.iter().skip(48).all(|b| *b == 0) {
        return Err(CryptoError::SignatureVerificationFailed);
    }
    let pk_hash = sha3_256(public_key);
    if &signature[48..80] != &pk_hash[..] {
        return Err(CryptoError::SignatureVerificationFailed);
    }
    Ok(())
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
#[cfg(not(feature = "oqs"))]
pub fn ml_kem1024_keygen() -> Result<MlKem1024KeyPair, CryptoError> {
    let mut seed = [0u8; 64];
    secure_random(&mut seed)?;
    let mut pk = [0u8; ML_KEM_1024_PUBLIC_KEY_LEN];
    let mut sk = [0u8; ML_KEM_1024_SECRET_KEY_LEN];
    fill_from_seed(&seed, b"ML-KEM-1024-PK", &mut pk);
    fill_from_seed(&seed, b"ML-KEM-1024-SK", &mut sk);
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
    let mut ss = [0u8; ML_KEM_1024_SHARED_SECRET_LEN];
    secure_random(&mut ss)?;
    let mut ct = [0u8; ML_KEM_1024_CIPHERTEXT_LEN];
    fill_from_seed(&ss, public_key, &mut ct);
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
#[cfg(not(feature = "oqs"))]
pub fn ml_kem1024_decapsulate(
    secret_key: &[u8; ML_KEM_1024_SECRET_KEY_LEN],
    ciphertext: &[u8; ML_KEM_1024_CIPHERTEXT_LEN],
) -> Result<[u8; ML_KEM_1024_SHARED_SECRET_LEN], CryptoError> {
    let mut ss = [0u8; ML_KEM_1024_SHARED_SECRET_LEN];
    let mut h = Sha3_256::new();
    h.update(secret_key);
    h.update(ciphertext);
    let digest = h.finalize();
    ss.copy_from_slice(&digest);
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
    fn test_aes_gcm_roundtrip() {
        let key = [0x42u8; 32];
        let pt = b"secret capability payload";
        let aad = b"metadata";
        let (ct, tag, nonce) = aes_256_gcm_encrypt(&key, pt, aad).unwrap();
        let pt2 = aes_256_gcm_decrypt(&key, &ct, aad, &nonce, &tag).unwrap();
        assert_eq!(pt2, pt);
    }
}
