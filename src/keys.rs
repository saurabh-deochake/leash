//! Key management for LEASH
//!
//! Implements hierarchical deterministic key derivation for agent credentials.

use k256::{
    ecdsa::{SigningKey, VerifyingKey, signature::Signer},
    SecretKey,
};
use sha2::{Sha256, Digest};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use rand::rngs::OsRng;

use crate::error::{LeashError, Result};

/// Agent key pair containing identity and heartbeat keys
#[derive(Clone)]
pub struct AgentKeyPair {
    /// Long-term identity signing key
    pub identity_key: SigningKey,
    /// Heartbeat signing key (derived from identity)
    pub heartbeat_key: SigningKey,
    /// Child derivation key material
    pub child_derivation_key: [u8; 32],
    /// Agent identifier
    pub agent_id: String,
}

impl AgentKeyPair {
    /// Generate a new root agent key pair
    pub fn generate_root(agent_id: &str) -> Result<Self> {
        let identity_key = SigningKey::random(&mut OsRng);
        Self::from_identity_key(identity_key, agent_id)
    }

    /// Create key pair from existing identity key
    pub fn from_identity_key(identity_key: SigningKey, agent_id: &str) -> Result<Self> {
        let identity_bytes = identity_key.to_bytes();
        
        // Derive heartbeat key using HKDF
        let hk = Hkdf::<Sha256>::new(None, &identity_bytes);
        let mut heartbeat_bytes = [0u8; 32];
        hk.expand(b"heartbeat", &mut heartbeat_bytes)
            .map_err(|e| LeashError::KeyDerivationError(e.to_string()))?;
        
        let heartbeat_key = SigningKey::from_bytes(&heartbeat_bytes.into())
            .map_err(|e| LeashError::KeyDerivationError(e.to_string()))?;

        // Derive child derivation key
        let mut child_derivation_key = [0u8; 32];
        hk.expand(b"children", &mut child_derivation_key)
            .map_err(|e| LeashError::KeyDerivationError(e.to_string()))?;

        Ok(Self {
            identity_key,
            heartbeat_key,
            child_derivation_key,
            agent_id: agent_id.to_string(),
        })
    }

    /// Get the public identity key
    pub fn identity_public_key(&self) -> VerifyingKey {
        *self.identity_key.verifying_key()
    }

    /// Get the public heartbeat key
    pub fn heartbeat_public_key(&self) -> VerifyingKey {
        *self.heartbeat_key.verifying_key()
    }

    /// Derive a child agent's key pair
    pub fn derive_child(&self, child_id: &str) -> Result<AgentKeyPair> {
        let hk = Hkdf::<Sha256>::new(None, &self.child_derivation_key);
        let mut child_identity_bytes = [0u8; 32];
        hk.expand(child_id.as_bytes(), &mut child_identity_bytes)
            .map_err(|e| LeashError::KeyDerivationError(e.to_string()))?;

        let child_identity_key = SigningKey::from_bytes(&child_identity_bytes.into())
            .map_err(|e| LeashError::KeyDerivationError(e.to_string()))?;

        AgentKeyPair::from_identity_key(child_identity_key, child_id)
    }
}

/// Serializable public key information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyInfo {
    /// Compressed public key bytes (33 bytes for secp256k1)
    pub identity_public_key: Vec<u8>,
    pub heartbeat_public_key: Vec<u8>,
    pub agent_id: String,
}

impl From<&AgentKeyPair> for PublicKeyInfo {
    fn from(kp: &AgentKeyPair) -> Self {
        Self {
            identity_public_key: kp.identity_public_key().to_sec1_bytes().to_vec(),
            heartbeat_public_key: kp.heartbeat_public_key().to_sec1_bytes().to_vec(),
            agent_id: kp.agent_id.clone(),
        }
    }
}

/// Key hierarchy for managing parent-child relationships
pub struct KeyHierarchy {
    /// Root key pair
    pub root: AgentKeyPair,
    /// Derived child key pairs
    children: Vec<AgentKeyPair>,
}

impl KeyHierarchy {
    /// Create a new key hierarchy with a root agent
    pub fn new(root_id: &str) -> Result<Self> {
        Ok(Self {
            root: AgentKeyPair::generate_root(root_id)?,
            children: Vec::new(),
        })
    }

    /// Add a child agent to the hierarchy
    pub fn add_child(&mut self, child_id: &str) -> Result<&AgentKeyPair> {
        let child = self.root.derive_child(child_id)?;
        self.children.push(child);
        Ok(self.children.last().unwrap())
    }

    /// Get a child by ID
    pub fn get_child(&self, child_id: &str) -> Option<&AgentKeyPair> {
        self.children.iter().find(|c| c.agent_id == child_id)
    }

    /// Get all children
    pub fn children(&self) -> &[AgentKeyPair] {
        &self.children
    }
}

/// Compute heartbeat binding for a child agent
pub fn compute_heartbeat_binding(parent_heartbeat_pubkey: &VerifyingKey, child_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(parent_heartbeat_pubkey.to_sec1_bytes());
    hasher.update(child_id.as_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let kp = AgentKeyPair::generate_root("test-agent").unwrap();
        assert_eq!(kp.agent_id, "test-agent");
    }

    #[test]
    fn test_child_derivation() {
        let parent = AgentKeyPair::generate_root("parent").unwrap();
        let child1 = parent.derive_child("child-1").unwrap();
        let child2 = parent.derive_child("child-2").unwrap();

        // Children should have different keys
        assert_ne!(
            child1.identity_public_key().to_sec1_bytes(),
            child2.identity_public_key().to_sec1_bytes()
        );

        // Derivation should be deterministic
        let child1_again = parent.derive_child("child-1").unwrap();
        assert_eq!(
            child1.identity_public_key().to_sec1_bytes(),
            child1_again.identity_public_key().to_sec1_bytes()
        );
    }

    #[test]
    fn test_heartbeat_binding() {
        let parent = AgentKeyPair::generate_root("parent").unwrap();
        let binding1 = compute_heartbeat_binding(&parent.heartbeat_public_key(), "child-1");
        let binding2 = compute_heartbeat_binding(&parent.heartbeat_public_key(), "child-2");

        assert_ne!(binding1, binding2);
    }
}
