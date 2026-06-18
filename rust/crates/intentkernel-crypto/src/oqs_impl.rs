//! Production PQC backend using the `oqs` crate (liboqs).
//!
//! Enable with `cargo build --features oqs` on `intentkernel-crypto`.
//! The host must have liboqs installed and discoverable by the oqs crate.

use crate::{
    CryptoError, MlDsa87KeyPair, MlKem1024KeyPair, ML_DSA_87_PUBLIC_KEY_LEN,
    ML_DSA_87_SECRET_KEY_LEN, ML_DSA_87_SIGNATURE_LEN, ML_KEM_1024_CIPHERTEXT_LEN,
    ML_KEM_1024_PUBLIC_KEY_LEN, ML_KEM_1024_SECRET_KEY_LEN, ML_KEM_1024_SHARED_SECRET_LEN,
};
use oqs::kem::{Kem, Kyber1024};
use oqs::sig::{Dilithium5, Sig};

pub fn ml_dsa87_keygen() -> Result<MlDsa87KeyPair, CryptoError> {
    let scheme = Sig::new(Dilithium5).map_err(|e| CryptoError::RngFailure(e.to_string()))?;
    let (pk, sk) = scheme
        .keypair()
        .map_err(|e| CryptoError::RngFailure(e.to_string()))?;
    let mut public_key = [0u8; ML_DSA_87_PUBLIC_KEY_LEN];
    let mut secret_key = [0u8; ML_DSA_87_SECRET_KEY_LEN];
    public_key.copy_from_slice(pk.as_ref());
    secret_key.copy_from_slice(sk.as_ref());
    Ok(MlDsa87KeyPair {
        public_key,
        secret_key,
    })
}

pub fn ml_dsa87_sign(
    secret_key: &[u8; ML_DSA_87_SECRET_KEY_LEN],
    message: &[u8],
) -> Result<[u8; ML_DSA_87_SIGNATURE_LEN], CryptoError> {
    let scheme = Sig::new(Dilithium5).map_err(|e| CryptoError::RngFailure(e.to_string()))?;
    let sk = scheme
        .secret_key_from_bytes(secret_key)
        .ok_or(CryptoError::InvalidKeyLength)?;
    let sig = scheme
        .sign(message, &sk)
        .map_err(|_| CryptoError::RngFailure("sign failed".into()))?;
    let mut out = [0u8; ML_DSA_87_SIGNATURE_LEN];
    out.copy_from_slice(sig.as_ref());
    Ok(out)
}

pub fn ml_dsa87_verify(
    public_key: &[u8; ML_DSA_87_PUBLIC_KEY_LEN],
    message: &[u8],
    signature: &[u8; ML_DSA_87_SIGNATURE_LEN],
) -> Result<(), CryptoError> {
    let scheme = Sig::new(Dilithium5).map_err(|e| CryptoError::RngFailure(e.to_string()))?;
    let pk = scheme
        .public_key_from_bytes(public_key)
        .ok_or(CryptoError::InvalidKeyLength)?;
    let sig = scheme
        .signature_from_bytes(signature)
        .ok_or(CryptoError::InvalidSignatureLength)?;
    scheme
        .verify(message, &sig, &pk)
        .map_err(|_| CryptoError::SignatureVerificationFailed)
}

pub fn ml_kem1024_keygen() -> Result<MlKem1024KeyPair, CryptoError> {
    let scheme = Kem::new(Kyber1024).map_err(|e| CryptoError::RngFailure(e.to_string()))?;
    let (pk, sk) = scheme
        .keypair()
        .map_err(|e| CryptoError::RngFailure(e.to_string()))?;
    let mut public_key = [0u8; ML_KEM_1024_PUBLIC_KEY_LEN];
    let mut secret_key = [0u8; ML_KEM_1024_SECRET_KEY_LEN];
    public_key.copy_from_slice(pk.as_ref());
    secret_key.copy_from_slice(sk.as_ref());
    Ok(MlKem1024KeyPair {
        public_key,
        secret_key,
    })
}

pub fn ml_kem1024_encapsulate(
    public_key: &[u8; ML_KEM_1024_PUBLIC_KEY_LEN],
) -> Result<
    (
        [u8; ML_KEM_1024_CIPHERTEXT_LEN],
        [u8; ML_KEM_1024_SHARED_SECRET_LEN],
    ),
    CryptoError,
> {
    let scheme = Kem::new(Kyber1024).map_err(|e| CryptoError::RngFailure(e.to_string()))?;
    let pk = scheme
        .public_key_from_bytes(public_key)
        .ok_or(CryptoError::InvalidKeyLength)?;
    let (ct, ss) = scheme
        .encapsulate(&pk)
        .map_err(|e| CryptoError::RngFailure(e.to_string()))?;
    let mut ciphertext = [0u8; ML_KEM_1024_CIPHERTEXT_LEN];
    let mut shared_secret = [0u8; ML_KEM_1024_SHARED_SECRET_LEN];
    ciphertext.copy_from_slice(ct.as_ref());
    shared_secret.copy_from_slice(ss.as_ref());
    Ok((ciphertext, shared_secret))
}

pub fn ml_kem1024_decapsulate(
    secret_key: &[u8; ML_KEM_1024_SECRET_KEY_LEN],
    ciphertext: &[u8; ML_KEM_1024_CIPHERTEXT_LEN],
) -> Result<[u8; ML_KEM_1024_SHARED_SECRET_LEN], CryptoError> {
    let scheme = Kem::new(Kyber1024).map_err(|e| CryptoError::RngFailure(e.to_string()))?;
    let sk = scheme
        .secret_key_from_bytes(secret_key)
        .ok_or(CryptoError::InvalidKeyLength)?;
    let ct = scheme
        .ciphertext_from_bytes(ciphertext)
        .ok_or(CryptoError::InvalidSignatureLength)?;
    let ss = scheme
        .decapsulate(&ct, &sk)
        .map_err(|e| CryptoError::RngFailure(e.to_string()))?;
    let mut out = [0u8; ML_KEM_1024_SHARED_SECRET_LEN];
    out.copy_from_slice(ss.as_ref());
    Ok(out)
}
