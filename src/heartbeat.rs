//! Heartbeat generation and management
//!
//! Implements the periodic heartbeat mechanism that binds child credential validity
//! to parent liveness.

use k256::ecdsa::{SigningKey, VerifyingKey, Signature, signature::{Signer, Verifier}};
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{LeashError, Result};
use crate::LeashConfig;

/// A heartbeat signature proving parent liveness at a specific epoch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    /// The epoch number (time / interval)
    pub epoch: u64,
    /// The commitment being signed: H(parent_hpk || epoch)
    pub commitment: [u8; 32],
    /// ECDSA signature over the commitment
    pub signature: Vec<u8>,
    /// Parent's heartbeat public key (for verification)
    pub parent_heartbeat_pubkey: Vec<u8>,
}

impl Heartbeat {
    /// Create a new heartbeat for the given epoch
    pub fn new(
        heartbeat_signing_key: &SigningKey,
        epoch: u64,
    ) -> Self {
        let heartbeat_pubkey = heartbeat_signing_key.verifying_key();
        let commitment = Self::compute_commitment(heartbeat_pubkey, epoch);
        
        let signature: Signature = heartbeat_signing_key.sign(&commitment);
        
        Self {
            epoch,
            commitment,
            signature: signature.to_bytes().to_vec(),
            parent_heartbeat_pubkey: heartbeat_pubkey.to_sec1_bytes().to_vec(),
        }
    }

    /// Compute the commitment for a given epoch
    pub fn compute_commitment(heartbeat_pubkey: &VerifyingKey, epoch: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(heartbeat_pubkey.to_sec1_bytes());
        hasher.update(epoch.to_le_bytes());
        hasher.finalize().into()
    }

    /// Verify this heartbeat's signature
    pub fn verify(&self) -> Result<()> {
        let pubkey = VerifyingKey::from_sec1_bytes(&self.parent_heartbeat_pubkey)
            .map_err(|e| LeashError::CryptoError(e.to_string()))?;
        
        let signature = Signature::from_slice(&self.signature)
            .map_err(|e| LeashError::CryptoError(e.to_string()))?;

        pubkey.verify(&self.commitment, &signature)
            .map_err(|_| LeashError::InvalidHeartbeatSignature)
    }

    /// Check if this heartbeat is fresh enough
    pub fn is_fresh(&self, current_epoch: u64, max_age_epochs: u64) -> bool {
        current_epoch.saturating_sub(self.epoch) <= max_age_epochs
    }
}

/// Generator for periodic heartbeats
pub struct HeartbeatGenerator {
    /// The signing key for heartbeats
    heartbeat_key: SigningKey,
    /// Configuration
    config: LeashConfig,
    /// Last generated epoch
    last_epoch: Option<u64>,
    /// Pre-generated heartbeats for future epochs (for planned disconnection)
    pregenerated: Vec<Heartbeat>,
}

impl HeartbeatGenerator {
    /// Create a new heartbeat generator
    pub fn new(heartbeat_key: SigningKey, config: LeashConfig) -> Self {
        Self {
            heartbeat_key,
            config,
            last_epoch: None,
            pregenerated: Vec::new(),
        }
    }

    /// Get the current epoch
    pub fn current_epoch(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now / self.config.heartbeat_interval_secs
    }

    /// Generate a heartbeat for the current epoch
    pub fn generate(&mut self) -> Heartbeat {
        let epoch = self.current_epoch();
        self.last_epoch = Some(epoch);
        Heartbeat::new(&self.heartbeat_key, epoch)
    }

    /// Generate a heartbeat for a specific epoch
    pub fn generate_for_epoch(&self, epoch: u64) -> Heartbeat {
        Heartbeat::new(&self.heartbeat_key, epoch)
    }

    /// Pre-generate heartbeats for future epochs
    /// Useful for planned disconnection scenarios
    pub fn pregenerate(&mut self, num_epochs: u64) -> &[Heartbeat] {
        let start_epoch = self.current_epoch();
        self.pregenerated.clear();
        
        for i in 0..num_epochs {
            let hb = self.generate_for_epoch(start_epoch + i);
            self.pregenerated.push(hb);
        }
        
        &self.pregenerated
    }

    /// Get a pre-generated heartbeat for a specific epoch
    pub fn get_pregenerated(&self, epoch: u64) -> Option<&Heartbeat> {
        self.pregenerated.iter().find(|hb| hb.epoch == epoch)
    }

    /// Check if a new heartbeat should be generated
    pub fn should_generate(&self) -> bool {
        match self.last_epoch {
            None => true,
            Some(last) => self.current_epoch() > last,
        }
    }

    /// Get the heartbeat public key
    pub fn public_key(&self) -> VerifyingKey {
        *self.heartbeat_key.verifying_key()
    }
}

/// Heartbeat cache for child agents
pub struct HeartbeatCache {
    /// Cached heartbeats indexed by epoch
    heartbeats: Vec<Heartbeat>,
    /// Maximum number of heartbeats to cache
    max_cache_size: usize,
    /// Configuration
    config: LeashConfig,
}

impl HeartbeatCache {
    /// Create a new heartbeat cache
    pub fn new(config: LeashConfig, max_cache_size: usize) -> Self {
        Self {
            heartbeats: Vec::new(),
            max_cache_size,
            config,
        }
    }

    /// Add a heartbeat to the cache
    pub fn add(&mut self, heartbeat: Heartbeat) {
        // Remove old heartbeats
        let current_epoch = self.current_epoch();
        let max_age = self.config.max_heartbeat_age_secs / self.config.heartbeat_interval_secs;
        
        self.heartbeats.retain(|hb| hb.is_fresh(current_epoch, max_age + 1));
        
        // Add new heartbeat if not duplicate
        if !self.heartbeats.iter().any(|hb| hb.epoch == heartbeat.epoch) {
            self.heartbeats.push(heartbeat);
        }
        
        // Trim to max size
        while self.heartbeats.len() > self.max_cache_size {
            self.heartbeats.remove(0);
        }
    }

    /// Get the most recent valid heartbeat
    pub fn get_latest(&self) -> Option<&Heartbeat> {
        let current_epoch = self.current_epoch();
        let max_age = self.config.max_heartbeat_age_secs / self.config.heartbeat_interval_secs;
        
        self.heartbeats
            .iter()
            .filter(|hb| hb.is_fresh(current_epoch, max_age))
            .max_by_key(|hb| hb.epoch)
    }

    /// Get heartbeat for a specific epoch
    pub fn get(&self, epoch: u64) -> Option<&Heartbeat> {
        self.heartbeats.iter().find(|hb| hb.epoch == epoch)
    }

    fn current_epoch(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now / self.config.heartbeat_interval_secs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::AgentKeyPair;

    #[test]
    fn test_heartbeat_generation() {
        let kp = AgentKeyPair::generate_root("test").unwrap();
        let hb = Heartbeat::new(&kp.heartbeat_key, 100);
        
        assert_eq!(hb.epoch, 100);
        assert!(hb.verify().is_ok());
    }

    #[test]
    fn test_heartbeat_freshness() {
        let kp = AgentKeyPair::generate_root("test").unwrap();
        let hb = Heartbeat::new(&kp.heartbeat_key, 100);
        
        assert!(hb.is_fresh(100, 3)); // Same epoch
        assert!(hb.is_fresh(103, 3)); // Within window
        assert!(!hb.is_fresh(104, 3)); // Outside window
    }

    #[test]
    fn test_heartbeat_generator() {
        let kp = AgentKeyPair::generate_root("test").unwrap();
        let config = LeashConfig::default();
        let mut gen = HeartbeatGenerator::new(kp.heartbeat_key.clone(), config);
        
        let hb = gen.generate();
        assert!(hb.verify().is_ok());
    }

    #[test]
    fn test_pregeneration() {
        let kp = AgentKeyPair::generate_root("test").unwrap();
        let config = LeashConfig::default();
        let mut gen = HeartbeatGenerator::new(kp.heartbeat_key.clone(), config);
        
        let pregenerated = gen.pregenerate(5);
        assert_eq!(pregenerated.len(), 5);
        
        for hb in pregenerated {
            assert!(hb.verify().is_ok());
        }
    }
}
