use crate::crypto::CryptoError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KernelError {
    #[error("policy denied: {0}")]
    PolicyDenied(String),
    #[error("capability table full")]
    TableFull,
    #[error("token expired")]
    Expired,
    #[error("token not yet valid")]
    NotYetValid,
    #[error("capability exhausted")]
    Exhausted,
    #[error("bad signature")]
    BadSignature,
    #[error("token replay")]
    Replay,
    #[error("serialize: {0}")]
    Serialize(String),
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
}