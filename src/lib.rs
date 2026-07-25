//! Liveness-Enforced Authorization for Swarm Hierarchies (LEASH)
//!
//! A cryptographic credential architecture for AI agent swarms
//! that enables immediate revocation without network connectivity.

pub mod heartbeat;
pub mod credentials;
pub mod keys;
pub mod verification;
pub mod error;

pub use heartbeat::{Heartbeat, HeartbeatGenerator};
pub use credentials::{AgentCredential, CredentialProof};
pub use keys::{AgentKeyPair, KeyHierarchy};
pub use verification::Verifier;
pub use error::LeashError;

/// Configuration for LEASH system
#[derive(Debug, Clone)]
pub struct LeashConfig {
    /// Heartbeat interval in seconds
    pub heartbeat_interval_secs: u64,
    /// Maximum acceptable heartbeat age in seconds
    pub max_heartbeat_age_secs: u64,
    /// Key derivation path prefix
    pub derivation_prefix: String,
}

impl Default for LeashConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval_secs: 10,
            max_heartbeat_age_secs: 30,
            derivation_prefix: "m/44'/0'/0'".to_string(),
        }
    }
}

/// Calculate the current epoch based on timestamp and interval
pub fn current_epoch(timestamp_secs: u64, interval_secs: u64) -> u64 {
    timestamp_secs / interval_secs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_calculation() {
        assert_eq!(current_epoch(0, 10), 0);
        assert_eq!(current_epoch(9, 10), 0);
        assert_eq!(current_epoch(10, 10), 1);
        assert_eq!(current_epoch(25, 10), 2);
    }
}
