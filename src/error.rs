//! Error types for LEASH

use thiserror::Error;

#[derive(Error, Debug)]
pub enum LeashError {
    #[error("Heartbeat expired: epoch {epoch} is older than max age {max_age}")]
    HeartbeatExpired { epoch: u64, max_age: u64 },

    #[error("Invalid heartbeat signature")]
    InvalidHeartbeatSignature,

    #[error("Invalid credential signature")]
    InvalidCredentialSignature,

    #[error("Heartbeat binding mismatch")]
    HeartbeatBindingMismatch,

    #[error("Key derivation failed: {0}")]
    KeyDerivationError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Clock synchronization error: local={local}, remote={remote}")]
    ClockSyncError { local: u64, remote: u64 },
}

pub type Result<T> = std::result::Result<T, LeashError>;
