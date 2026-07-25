//! Verification logic for LEASH credentials
//!
//! Implements the verifier component that validates authentication proofs
//! including heartbeat freshness checks.

use k256::ecdsa::VerifyingKey;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{LeashError, Result};
use crate::credentials::CredentialProof;
use crate::heartbeat::Heartbeat;
use crate::LeashConfig;

/// Result of credential verification
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Whether the verification succeeded
    pub valid: bool,
    /// Agent ID from the credential
    pub agent_id: String,
    /// Heartbeat epoch used
    pub heartbeat_epoch: u64,
    /// Current epoch at verification time
    pub current_epoch: u64,
    /// Scopes/permissions from the credential
    pub scopes: Vec<String>,
    /// Any warnings (e.g., heartbeat nearing expiration)
    pub warnings: Vec<String>,
}

/// Verifier for LEASH credentials
pub struct Verifier {
    /// Configuration
    config: LeashConfig,
    /// Trusted parent heartbeat public keys
    trusted_parents: Vec<TrustedParent>,
}

/// A trusted parent agent
#[derive(Clone)]
pub struct TrustedParent {
    /// Parent agent ID
    pub agent_id: String,
    /// Parent's heartbeat public key
    pub heartbeat_pubkey: VerifyingKey,
    /// Optional: specific scopes this parent can grant
    pub allowed_scopes: Option<Vec<String>>,
}

impl Verifier {
    /// Create a new verifier with the given configuration
    pub fn new(config: LeashConfig) -> Self {
        Self {
            config,
            trusted_parents: Vec::new(),
        }
    }

    /// Add a trusted parent
    pub fn add_trusted_parent(&mut self, parent: TrustedParent) {
        self.trusted_parents.push(parent);
    }

    /// Add a trusted parent by public key
    pub fn trust_parent(&mut self, agent_id: &str, heartbeat_pubkey: VerifyingKey) {
        self.trusted_parents.push(TrustedParent {
            agent_id: agent_id.to_string(),
            heartbeat_pubkey,
            allowed_scopes: None,
        });
    }

    /// Get the current epoch
    pub fn current_epoch(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now / self.config.heartbeat_interval_secs
    }

    /// Verify a credential proof
    pub fn verify(&self, proof: &CredentialProof, challenge: &[u8]) -> Result<VerificationResult> {
        let current_epoch = self.current_epoch();
        let mut warnings = Vec::new();

        // 1. Verify the challenge matches
        if proof.challenge != challenge {
            return Err(LeashError::CryptoError("Challenge mismatch".to_string()));
        }

        // 2. Check credential expiration (if set)
        if proof.credential.is_expired() {
            return Err(LeashError::HeartbeatExpired {
                epoch: proof.heartbeat_epoch(),
                max_age: 0,
            });
        }

        // 3. Find the trusted parent
        let parent_pubkey = VerifyingKey::from_sec1_bytes(&proof.credential.parent_heartbeat_pubkey)
            .map_err(|e| LeashError::CryptoError(e.to_string()))?;

        let trusted_parent = self.trusted_parents
            .iter()
            .find(|p| p.heartbeat_pubkey == parent_pubkey);

        if trusted_parent.is_none() {
            return Err(LeashError::CryptoError("Parent not trusted".to_string()));
        }

        // 4. Verify heartbeat binding
        proof.credential.verify_binding(&parent_pubkey)?;

        // 5. Check heartbeat freshness
        let max_age_epochs = self.config.max_heartbeat_age_secs / self.config.heartbeat_interval_secs;
        
        if !proof.heartbeat.is_fresh(current_epoch, max_age_epochs) {
            return Err(LeashError::HeartbeatExpired {
                epoch: proof.heartbeat_epoch(),
                max_age: max_age_epochs,
            });
        }

        // Add warning if heartbeat is nearing expiration
        let age = current_epoch.saturating_sub(proof.heartbeat_epoch());
        if age >= max_age_epochs.saturating_sub(1) {
            warnings.push(format!(
                "Heartbeat nearing expiration: age {} of max {}",
                age, max_age_epochs
            ));
        }

        // 6. Verify heartbeat signature
        proof.heartbeat.verify()?;

        // 7. Verify the credential proof signature
        proof.verify_signature()?;

        // 8. Check scope restrictions (if parent has restrictions)
        let scopes = if let Some(parent) = trusted_parent {
            if let Some(ref allowed) = parent.allowed_scopes {
                proof.credential.metadata.scopes
                    .iter()
                    .filter(|s| allowed.contains(s))
                    .cloned()
                    .collect()
            } else {
                proof.credential.metadata.scopes.clone()
            }
        } else {
            proof.credential.metadata.scopes.clone()
        };

        Ok(VerificationResult {
            valid: true,
            agent_id: proof.credential.agent_id.clone(),
            heartbeat_epoch: proof.heartbeat_epoch(),
            current_epoch,
            scopes,
            warnings,
        })
    }

    /// Quick check if a heartbeat is valid and fresh
    pub fn verify_heartbeat(&self, heartbeat: &Heartbeat) -> Result<bool> {
        // Verify signature
        heartbeat.verify()?;

        // Check freshness
        let current_epoch = self.current_epoch();
        let max_age_epochs = self.config.max_heartbeat_age_secs / self.config.heartbeat_interval_secs;

        Ok(heartbeat.is_fresh(current_epoch, max_age_epochs))
    }
}

/// Builder for verification challenges
pub struct ChallengeBuilder {
    /// Random nonce
    nonce: [u8; 32],
    /// Timestamp
    timestamp: u64,
    /// Resource being accessed
    resource: Option<String>,
    /// Action being performed
    action: Option<String>,
}

impl ChallengeBuilder {
    /// Create a new challenge builder with random nonce
    pub fn new() -> Self {
        use rand::RngCore;
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            nonce,
            timestamp,
            resource: None,
            action: None,
        }
    }

    /// Set the resource being accessed
    pub fn for_resource(mut self, resource: &str) -> Self {
        self.resource = Some(resource.to_string());
        self
    }

    /// Set the action being performed
    pub fn for_action(mut self, action: &str) -> Self {
        self.action = Some(action.to_string());
        self
    }

    /// Build the challenge bytes
    pub fn build(self) -> Vec<u8> {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(&self.nonce);
        hasher.update(self.timestamp.to_le_bytes());
        
        if let Some(ref resource) = self.resource {
            hasher.update(resource.as_bytes());
        }
        if let Some(ref action) = self.action {
            hasher.update(action.as_bytes());
        }

        hasher.finalize().to_vec()
    }
}

impl Default for ChallengeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::AgentKeyPair;
    use crate::credentials::{CredentialBuilder, CredentialProof};
    use crate::heartbeat::Heartbeat;

    fn setup_test_scenario() -> (AgentKeyPair, AgentKeyPair, Verifier) {
        let parent = AgentKeyPair::generate_root("parent").unwrap();
        let child = parent.derive_child("child-1").unwrap();
        
        let config = LeashConfig {
            heartbeat_interval_secs: 10,
            max_heartbeat_age_secs: 30,
            ..Default::default()
        };
        
        let mut verifier = Verifier::new(config);
        verifier.trust_parent("parent", parent.heartbeat_public_key());
        
        (parent, child, verifier)
    }

    #[test]
    fn test_successful_verification() {
        let (parent, child, verifier) = setup_test_scenario();

        let cred = CredentialBuilder::new()
            .with_scope("read")
            .build(&child, &parent.heartbeat_public_key());

        // Use current epoch for fresh heartbeat
        let current_epoch = verifier.current_epoch();
        let heartbeat = Heartbeat::new(&parent.heartbeat_key, current_epoch);

        let challenge = ChallengeBuilder::new()
            .for_resource("/api/data")
            .for_action("read")
            .build();

        let proof = CredentialProof::new(
            cred,
            heartbeat,
            &challenge,
            &child.identity_key,
        );

        let result = verifier.verify(&proof, &challenge);
        assert!(result.is_ok());
        
        let result = result.unwrap();
        assert!(result.valid);
        assert_eq!(result.agent_id, "child-1");
    }

    #[test]
    fn test_expired_heartbeat() {
        let (parent, child, verifier) = setup_test_scenario();

        let cred = CredentialBuilder::new()
            .build(&child, &parent.heartbeat_public_key());

        // Use very old epoch
        let old_epoch = verifier.current_epoch().saturating_sub(100);
        let heartbeat = Heartbeat::new(&parent.heartbeat_key, old_epoch);

        let challenge = ChallengeBuilder::new().build();

        let proof = CredentialProof::new(
            cred,
            heartbeat,
            &challenge,
            &child.identity_key,
        );

        let result = verifier.verify(&proof, &challenge);
        assert!(result.is_err());
        
        match result {
            Err(LeashError::HeartbeatExpired { .. }) => (),
            _ => panic!("Expected HeartbeatExpired error"),
        }
    }

    #[test]
    fn test_untrusted_parent() {
        let (parent, child, mut verifier) = setup_test_scenario();
        
        // Clear trusted parents
        verifier.trusted_parents.clear();

        let cred = CredentialBuilder::new()
            .build(&child, &parent.heartbeat_public_key());

        let current_epoch = verifier.current_epoch();
        let heartbeat = Heartbeat::new(&parent.heartbeat_key, current_epoch);

        let challenge = ChallengeBuilder::new().build();

        let proof = CredentialProof::new(
            cred,
            heartbeat,
            &challenge,
            &child.identity_key,
        );

        let result = verifier.verify(&proof, &challenge);
        assert!(result.is_err());
    }
}
