//! Native IntentOS cryptography — owned by the kernel, not IKRL.
//!
//! Wire-format slots match ML-DSA-87 sizes; signing uses Ed25519 with
//! secret-key binding (dev path). No `intentkernel-crypto` dependency.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{rngs::OsRng, TryRngCore};
use sha3::{Digest, Sha3_512};
use thiserror::Error;

pub const PUBLIC_KEY_LEN: usize = 2592;
pub const SECRET_KEY_LEN: usize = 4896;
pub const SIGNATURE_LEN: usize = 4595;

/// Ed25519 dev path — ML-DSA-sized slots with seed-bound padding.
pub const TOKEN_SIG_V1_ED25519: u8 = 1;
/// PQC-hybrid path — Ed25519 + public-key-bound SHA3-512 padding (verify without secret).
pub const TOKEN_SIG_V2_PQC_HYBRID: u8 = 2;

const PQC_PAD_DOMAIN: &[u8] = b"INTENTOS-PQC-V2";

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("rng failure")]
    Rng,
    #[error("invalid key")]
    InvalidKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("signature verification failed")]
    VerifyFailed,
}

#[derive(Clone)]
pub struct BrokerKeys {
    public_key: [u8; PUBLIC_KEY_LEN],
    secret_key: [u8; SECRET_KEY_LEN],
}

impl std::fmt::Debug for BrokerKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrokerKeys")
            .field("public_key", &format!("{}…", hex_prefix(&self.public_key[..8])))
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

fn hex_prefix(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn generate_broker_keys() -> Result<BrokerKeys, CryptoError> {
    let mut seed = [0u8; 32];
    OsRng.try_fill_bytes(&mut seed).map_err(|_| CryptoError::Rng)?;
    let signing = SigningKey::from_bytes(&seed);
    let verifying = signing.verifying_key();

    let mut secret_key = [0u8; SECRET_KEY_LEN];
    secret_key[..32].copy_from_slice(&seed);
    secret_key[32..64].copy_from_slice(verifying.as_bytes());
    fill_random(&mut secret_key[64..])?;

    let mut public_key = [0u8; PUBLIC_KEY_LEN];
    public_key[..32].copy_from_slice(verifying.as_bytes());
    fill_random(&mut public_key[32..])?;

    Ok(BrokerKeys {
        public_key,
        secret_key,
    })
}

impl BrokerKeys {
    pub fn public_key_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public_key
    }

    pub fn secret_key_bytes(&self) -> &[u8; SECRET_KEY_LEN] {
        &self.secret_key
    }

    pub fn sign(&self, message: &[u8]) -> Result<[u8; SIGNATURE_LEN], CryptoError> {
        sign_with_version(&self.secret_key, message, TOKEN_SIG_V1_ED25519)
    }

    pub fn sign_versioned(
        &self,
        message: &[u8],
        ver: u8,
    ) -> Result<[u8; SIGNATURE_LEN], CryptoError> {
        sign_with_version(&self.secret_key, message, ver)
    }

    pub fn verify(&self, message: &[u8], signature: &[u8; SIGNATURE_LEN]) -> Result<(), CryptoError> {
        verify_with_version(&self.public_key, message, signature, TOKEN_SIG_V1_ED25519)
    }

    pub fn verify_versioned(
        &self,
        message: &[u8],
        signature: &[u8; SIGNATURE_LEN],
        ver: u8,
    ) -> Result<(), CryptoError> {
        verify_with_version(&self.public_key, message, signature, ver)
    }
}

pub fn sign(secret_key: &[u8; SECRET_KEY_LEN], message: &[u8]) -> Result<[u8; SIGNATURE_LEN], CryptoError> {
    let seed: [u8; 32] = secret_key[..32].try_into().map_err(|_| CryptoError::InvalidKey)?;
    let signing = SigningKey::from_bytes(&seed);
    let sig: Signature = signing.sign(message);

    let mut out = [0u8; SIGNATURE_LEN];
    out[..64].copy_from_slice(&sig.to_bytes());
    let mut h = Sha3_512::new();
    h.update(&seed);
    h.update(message);
    fill_from_digest(&h.finalize(), b"INTENTOS-SIG-PAD", &mut out[64..]);
    Ok(out)
}

pub fn verify(
    public_key: &[u8; PUBLIC_KEY_LEN],
    message: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<(), CryptoError> {
    verify_with_version(public_key, message, signature, TOKEN_SIG_V1_ED25519)
}

pub fn sign_with_version(
    secret_key: &[u8; SECRET_KEY_LEN],
    message: &[u8],
    ver: u8,
) -> Result<[u8; SIGNATURE_LEN], CryptoError> {
    match ver {
        TOKEN_SIG_V1_ED25519 => sign(secret_key, message),
        TOKEN_SIG_V2_PQC_HYBRID => sign_pqc_hybrid(secret_key, message),
        _ => Err(CryptoError::InvalidKey),
    }
}

pub fn verify_with_version(
    public_key: &[u8; PUBLIC_KEY_LEN],
    message: &[u8],
    signature: &[u8; SIGNATURE_LEN],
    ver: u8,
) -> Result<(), CryptoError> {
    match ver {
        TOKEN_SIG_V1_ED25519 => verify_ed25519(public_key, message, signature),
        TOKEN_SIG_V2_PQC_HYBRID => verify_pqc_hybrid(public_key, message, signature),
        _ => Err(CryptoError::InvalidKey),
    }
}

fn verify_ed25519(
    public_key: &[u8; PUBLIC_KEY_LEN],
    message: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<(), CryptoError> {
    let pk: [u8; 32] = public_key[..32].try_into().map_err(|_| CryptoError::InvalidKey)?;
    let verifying = VerifyingKey::from_bytes(&pk).map_err(|_| CryptoError::InvalidKey)?;
    let sig_bytes: [u8; 64] = signature[..64]
        .try_into()
        .map_err(|_| CryptoError::InvalidSignature)?;
    let sig = Signature::from_bytes(&sig_bytes);
    verifying
        .verify(message, &sig)
        .map_err(|_| CryptoError::VerifyFailed)
}

fn sign_pqc_hybrid(
    secret_key: &[u8; SECRET_KEY_LEN],
    message: &[u8],
) -> Result<[u8; SIGNATURE_LEN], CryptoError> {
    let seed: [u8; 32] = secret_key[..32].try_into().map_err(|_| CryptoError::InvalidKey)?;
    let signing = SigningKey::from_bytes(&seed);
    let sig: Signature = signing.sign(message);

    let mut out = [0u8; SIGNATURE_LEN];
    out[..64].copy_from_slice(&sig.to_bytes());
    let pk_prefix = &secret_key[32..64];
    let mut h = Sha3_512::new();
    h.update(pk_prefix);
    h.update(message);
    fill_from_digest(&h.finalize(), PQC_PAD_DOMAIN, &mut out[64..]);
    Ok(out)
}

fn verify_pqc_hybrid(
    public_key: &[u8; PUBLIC_KEY_LEN],
    message: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<(), CryptoError> {
    verify_ed25519(public_key, message, signature)?;
    let mut expected = [0u8; SIGNATURE_LEN - 64];
    let mut h = Sha3_512::new();
    h.update(&public_key[..32]);
    h.update(message);
    fill_from_digest(&h.finalize(), PQC_PAD_DOMAIN, &mut expected);
    if signature[64..] != expected {
        return Err(CryptoError::VerifyFailed);
    }
    Ok(())
}

fn fill_random(out: &mut [u8]) -> Result<(), CryptoError> {
    OsRng.try_fill_bytes(out).map_err(|_| CryptoError::Rng)
}

fn fill_from_digest(seed: &[u8], domain: &[u8], out: &mut [u8]) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let keys = generate_broker_keys().unwrap();
        let msg = b"intentos native crypto";
        let sig = sign(&keys.secret_key, msg).unwrap();
        assert!(verify(&keys.public_key, msg, &sig).is_ok());
        assert!(verify(&keys.public_key, b"tampered", &sig).is_err());
    }

    #[test]
    fn pqc_hybrid_sign_verify_roundtrip() {
        let keys = generate_broker_keys().unwrap();
        let msg = b"pqc hybrid token path";
        let sig = sign_with_version(&keys.secret_key, msg, TOKEN_SIG_V2_PQC_HYBRID).unwrap();
        assert!(verify_with_version(&keys.public_key, msg, &sig, TOKEN_SIG_V2_PQC_HYBRID).is_ok());
        let mut tampered = sig;
        tampered[200] ^= 0xFF;
        assert!(verify_with_version(&keys.public_key, msg, &tampered, TOKEN_SIG_V2_PQC_HYBRID).is_err());
    }

    #[test]
    fn forge_without_secret_fails() {
        let keys = generate_broker_keys().unwrap();
        let mut forged = [0u8; SIGNATURE_LEN];
        forged[..64].copy_from_slice(&[0xAB; 64]);
        assert!(verify(&keys.public_key, b"any message", &forged).is_err());
    }
}