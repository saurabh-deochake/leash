//! Agent credentials with heartbeat binding
//!
//! Implements the credential structure that binds child agent authentication
//! to parent heartbeat validity.

use k256::ecdsa::{SigningKey, VerifyingKey, Signature, signature::{Signer, Verifier}};
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{LeashError, Result};
use crate::heartbeat::Heartbeat;
use crate::keys::{AgentKeyPair, compute_heartbeat_binding};

/// Agent credential containing identity and heartbeat binding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCredential {
    /// Agent identifier
    pub agent_id: String,
    /// Agent's public identity key
    pub identity_public_key: Vec<u8>,
    /// Heartbeat binding: H(parent_hpk || agent_id)
    pub heartbeat_binding: [u8; 32],
    /// Parent's heartbeat public key (needed for verification)
    pub parent_heartbeat_pubkey: Vec<u8>,
    /// Credential issuance timestamp
    pub issued_at: u64,
    /// Optional expiration timestamp (in addition to heartbeat requirement)
    pub expires_at: Option<u64>,
    /// Credential metadata (permissions, scopes, etc.)
    pub metadata: CredentialMetadata,
}

/// Metadata associated with a credential
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CredentialMetadata {
    /// Allowed scopes/permissions
    pub scopes: Vec<String>,
    /// Maximum delegation depth
    pub max_delegation_depth: u32,
    /// Current delegation depth
    pub delegation_depth: u32,
    /// Custom attributes
    pub attributes: std::collections::HashMap<String, String>,
}

impl AgentCredential {
    /// Create a new credential for a child agent
    pub fn new(
        child_keypair: &AgentKeyPair,
        parent_heartbeat_pubkey: &VerifyingKey,
        metadata: CredentialMetadata,
        expires_at: Option<u64>,
    ) -> Self {
        let heartbeat_binding = compute_heartbeat_binding(
            parent_heartbeat_pubkey,
            &child_keypair.agent_id,
        );

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            agent_id: child_keypair.agent_id.clone(),
            identity_public_key: child_keypair.identity_public_key().to_sec1_bytes().to_vec(),
            heartbeat_binding,
            parent_heartbeat_pubkey: parent_heartbeat_pubkey.to_sec1_bytes().to_vec(),
            issued_at: now,
            expires_at,
            metadata,
        }
    }

    /// Verify that the heartbeat binding matches
    pub fn verify_binding(&self, parent_heartbeat_pubkey: &VerifyingKey) -> Result<()> {
        let expected_binding = compute_heartbeat_binding(parent_heartbeat_pubkey, &self.agent_id);
        
        if self.heartbeat_binding != expected_binding {
            return Err(LeashError::HeartbeatBindingMismatch);
        }
        
        Ok(())
    }

    /// Check if the credential has expired (ignoring heartbeat)
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            now > expires_at
        } else {
            false
        }
    }
}

/// Authentication proof combining credential, heartbeat, and challenge response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialProof {
    /// The agent's credential
    pub credential: AgentCredential,
    /// The heartbeat proving parent liveness
    pub heartbeat: Heartbeat,
    /// Challenge from the verifier
    pub challenge: Vec<u8>,
    /// Signature over (challenge || epoch || heartbeat_signature)
    pub signature: Vec<u8>,
    /// Timestamp of proof generation
    pub timestamp: u64,
}

impl CredentialProof {
    /// Create a new authentication proof
    pub fn new(
        credential: AgentCredential,
        heartbeat: Heartbeat,
        challenge: &[u8],
        signing_key: &SigningKey,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Construct proof data: challenge || epoch || heartbeat_signature
        let mut proof_data = Vec::new();
        proof_data.extend_from_slice(challenge);
        proof_data.extend_from_slice(&heartbeat.epoch.to_le_bytes());
        proof_data.extend_from_slice(&heartbeat.signature);

        let signature: Signature = signing_key.sign(&proof_data);

        Self {
            credential,
            heartbeat,
            challenge: challenge.to_vec(),
            signature: signature.to_bytes().to_vec(),
            timestamp,
        }
    }

    /// Verify the proof signature
    pub fn verify_signature(&self) -> Result<()> {
        let pubkey = VerifyingKey::from_sec1_bytes(&self.credential.identity_public_key)
            .map_err(|e| LeashError::CryptoError(e.to_string()))?;

        // Reconstruct proof data
        let mut proof_data = Vec::new();
        proof_data.extend_from_slice(&self.challenge);
        proof_data.extend_from_slice(&self.heartbeat.epoch.to_le_bytes());
        proof_data.extend_from_slice(&self.heartbeat.signature);

        let signature = Signature::from_slice(&self.signature)
            .map_err(|e| LeashError::CryptoError(e.to_string()))?;

        pubkey.verify(&proof_data, &signature)
            .map_err(|_| LeashError::InvalidCredentialSignature)
    }

    /// Get the epoch from the embedded heartbeat
    pub fn heartbeat_epoch(&self) -> u64 {
        self.heartbeat.epoch
    }
}

/// Builder for creating credentials with various options
pub struct CredentialBuilder {
    scopes: Vec<String>,
    max_delegation_depth: u32,
    delegation_depth: u32,
    attributes: std::collections::HashMap<String, String>,
    expires_in_secs: Option<u64>,
}

impl CredentialBuilder {
    pub fn new() -> Self {
        Self {
            scopes: Vec::new(),
            max_delegation_depth: 3,
            delegation_depth: 0,
            attributes: std::collections::HashMap::new(),
            expires_in_secs: None,
        }
    }

    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    pub fn with_scope(mut self, scope: &str) -> Self {
        self.scopes.push(scope.to_string());
        self
    }

    pub fn with_max_delegation_depth(mut self, depth: u32) -> Self {
        self.max_delegation_depth = depth;
        self
    }

    pub fn with_delegation_depth(mut self, depth: u32) -> Self {
        self.delegation_depth = depth;
        self
    }

    pub fn with_attribute(mut self, key: &str, value: &str) -> Self {
        self.attributes.insert(key.to_string(), value.to_string());
        self
    }

    pub fn expires_in(mut self, secs: u64) -> Self {
        self.expires_in_secs = Some(secs);
        self
    }

    pub fn build(
        self,
        child_keypair: &AgentKeyPair,
        parent_heartbeat_pubkey: &VerifyingKey,
    ) -> AgentCredential {
        let metadata = CredentialMetadata {
            scopes: self.scopes,
            max_delegation_depth: self.max_delegation_depth,
            delegation_depth: self.delegation_depth,
            attributes: self.attributes,
        };

        let expires_at = self.expires_in_secs.map(|secs| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() + secs
        });

        AgentCredential::new(child_keypair, parent_heartbeat_pubkey, metadata, expires_at)
    }
}

impl Default for CredentialBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::AgentKeyPair;

    #[test]
    fn test_credential_creation() {
        let parent = AgentKeyPair::generate_root("parent").unwrap();
        let child = parent.derive_child("child-1").unwrap();

        let cred = CredentialBuilder::new()
            .with_scope("read")
            .with_scope("write")
            .build(&child, &parent.heartbeat_public_key());

        assert_eq!(cred.agent_id, "child-1");
        assert_eq!(cred.metadata.scopes, vec!["read", "write"]);
    }

    #[test]
    fn test_credential_proof() {
        let parent = AgentKeyPair::generate_root("parent").unwrap();
        let child = parent.derive_child("child-1").unwrap();

        let cred = CredentialBuilder::new()
            .build(&child, &parent.heartbeat_public_key());

        let heartbeat = Heartbeat::new(&parent.heartbeat_key, 100);
        let challenge = b"test-challenge";

        let proof = CredentialProof::new(
            cred,
            heartbeat,
            challenge,
            &child.identity_key,
        );

        assert!(proof.verify_signature().is_ok());
    }

    #[test]
    fn test_heartbeat_binding_verification() {
        let parent = AgentKeyPair::generate_root("parent").unwrap();
        let child = parent.derive_child("child-1").unwrap();

        let cred = CredentialBuilder::new()
            .build(&child, &parent.heartbeat_public_key());

        // Should verify with correct parent key
        assert!(cred.verify_binding(&parent.heartbeat_public_key()).is_ok());

        // Should fail with different parent key
        let other_parent = AgentKeyPair::generate_root("other").unwrap();
        assert!(cred.verify_binding(&other_parent.heartbeat_public_key()).is_err());
    }
}
