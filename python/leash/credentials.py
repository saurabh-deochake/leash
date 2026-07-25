"""
Agent credentials with heartbeat binding.

Implements the credential structure that binds child agent authentication
to parent heartbeat validity.
"""

import hashlib
import time
from dataclasses import dataclass, field
from typing import Optional

from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError

from .keys import AgentKeyPair, compute_heartbeat_binding
from .heartbeat import Heartbeat


@dataclass
class CredentialMetadata:
    """Metadata associated with a credential."""
    scopes: list[str] = field(default_factory=list)
    max_delegation_depth: int = 3
    delegation_depth: int = 0
    attributes: dict[str, str] = field(default_factory=dict)


@dataclass
class AgentCredential:
    """
    Agent credential containing identity and heartbeat binding.
    
    The credential binds the child agent's identity to the parent's
    heartbeat key, ensuring the child can only authenticate when
    the parent is generating heartbeats.
    """
    agent_id: str
    identity_public_key: bytes
    heartbeat_binding: bytes  # H(parent_hpk || agent_id)
    parent_heartbeat_pubkey: bytes
    issued_at: int
    expires_at: Optional[int]
    metadata: CredentialMetadata
    
    @classmethod
    def create(
        cls,
        child_keypair: AgentKeyPair,
        parent_heartbeat_pubkey: VerifyingKey,
        metadata: CredentialMetadata,
        expires_at: Optional[int] = None
    ) -> "AgentCredential":
        """
        Create a new credential for a child agent.
        
        Args:
            child_keypair: The child agent's key pair
            parent_heartbeat_pubkey: Parent's heartbeat public key
            metadata: Credential metadata (scopes, etc.)
            expires_at: Optional expiration timestamp
            
        Returns:
            New AgentCredential
        """
        heartbeat_binding = compute_heartbeat_binding(
            parent_heartbeat_pubkey,
            child_keypair.agent_id
        )
        
        return cls(
            agent_id=child_keypair.agent_id,
            identity_public_key=child_keypair.public_key_bytes(),
            heartbeat_binding=heartbeat_binding,
            parent_heartbeat_pubkey=parent_heartbeat_pubkey.to_string(),
            issued_at=int(time.time()),
            expires_at=expires_at,
            metadata=metadata
        )
    
    def verify_binding(self, parent_heartbeat_pubkey: VerifyingKey) -> bool:
        """
        Verify that the heartbeat binding matches the parent key.
        
        Args:
            parent_heartbeat_pubkey: The parent's heartbeat public key
            
        Returns:
            True if binding is valid
        """
        expected = compute_heartbeat_binding(parent_heartbeat_pubkey, self.agent_id)
        return self.heartbeat_binding == expected
    
    def is_expired(self) -> bool:
        """Check if the credential has expired (ignoring heartbeat)."""
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at
    
    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "agent_id": self.agent_id,
            "identity_public_key": self.identity_public_key.hex(),
            "heartbeat_binding": self.heartbeat_binding.hex(),
            "parent_heartbeat_pubkey": self.parent_heartbeat_pubkey.hex(),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "metadata": {
                "scopes": self.metadata.scopes,
                "max_delegation_depth": self.metadata.max_delegation_depth,
                "delegation_depth": self.metadata.delegation_depth,
                "attributes": self.metadata.attributes
            }
        }


@dataclass
class CredentialProof:
    """
    Authentication proof combining credential, heartbeat, and challenge response.
    
    This is what the child agent sends to a verifier to prove its identity
    and that its parent is still alive (generating heartbeats).
    """
    credential: AgentCredential
    heartbeat: Heartbeat
    challenge: bytes
    signature: bytes  # Signature over (challenge || epoch || heartbeat_signature)
    timestamp: int
    
    @classmethod
    def create(
        cls,
        credential: AgentCredential,
        heartbeat: Heartbeat,
        challenge: bytes,
        signing_key: SigningKey
    ) -> "CredentialProof":
        """
        Create a new authentication proof.
        
        Args:
            credential: The agent's credential
            heartbeat: A recent heartbeat from the parent
            challenge: Challenge bytes from the verifier
            signing_key: The agent's identity signing key
            
        Returns:
            New CredentialProof
        """
        timestamp = int(time.time())
        
        # Construct proof data: challenge || epoch || heartbeat_signature
        proof_data = (
            challenge +
            heartbeat.epoch.to_bytes(8, 'little') +
            heartbeat.signature
        )
        
        signature = signing_key.sign(proof_data)
        
        return cls(
            credential=credential,
            heartbeat=heartbeat,
            challenge=challenge,
            signature=signature,
            timestamp=timestamp
        )
    
    def verify_signature(self) -> bool:
        """
        Verify the proof signature.
        
        Returns:
            True if signature is valid
        """
        try:
            pubkey = VerifyingKey.from_string(
                self.credential.identity_public_key,
                curve=SECP256k1
            )
            
            # Reconstruct proof data
            proof_data = (
                self.challenge +
                self.heartbeat.epoch.to_bytes(8, 'little') +
                self.heartbeat.signature
            )
            
            pubkey.verify(self.signature, proof_data)
            return True
        except BadSignatureError:
            return False
    
    def heartbeat_epoch(self) -> int:
        """Get the epoch from the embedded heartbeat."""
        return self.heartbeat.epoch


class CredentialBuilder:
    """
    Builder for creating credentials with various options.
    
    Example:
        credential = (CredentialBuilder()
            .with_scope("read")
            .with_scope("write")
            .with_attribute("mission", "survey")
            .expires_in(3600)
            .build(child_keypair, parent_heartbeat_pubkey))
    """
    
    def __init__(self):
        self.scopes: list[str] = []
        self.max_delegation_depth: int = 3
        self.delegation_depth: int = 0
        self.attributes: dict[str, str] = {}
        self.expires_in_secs: Optional[int] = None
    
    def with_scopes(self, scopes: list[str]) -> "CredentialBuilder":
        """Set multiple scopes at once."""
        self.scopes = scopes
        return self
    
    def with_scope(self, scope: str) -> "CredentialBuilder":
        """Add a single scope."""
        self.scopes.append(scope)
        return self
    
    def with_max_delegation_depth(self, depth: int) -> "CredentialBuilder":
        """Set maximum delegation depth."""
        self.max_delegation_depth = depth
        return self
    
    def with_delegation_depth(self, depth: int) -> "CredentialBuilder":
        """Set current delegation depth."""
        self.delegation_depth = depth
        return self
    
    def with_attribute(self, key: str, value: str) -> "CredentialBuilder":
        """Add a custom attribute."""
        self.attributes[key] = value
        return self
    
    def expires_in(self, secs: int) -> "CredentialBuilder":
        """Set expiration time (seconds from now)."""
        self.expires_in_secs = secs
        return self
    
    def build(
        self,
        child_keypair: AgentKeyPair,
        parent_heartbeat_pubkey: VerifyingKey
    ) -> AgentCredential:
        """
        Build the credential.
        
        Args:
            child_keypair: The child agent's key pair
            parent_heartbeat_pubkey: Parent's heartbeat public key
            
        Returns:
            New AgentCredential
        """
        metadata = CredentialMetadata(
            scopes=self.scopes,
            max_delegation_depth=self.max_delegation_depth,
            delegation_depth=self.delegation_depth,
            attributes=self.attributes
        )
        
        expires_at = None
        if self.expires_in_secs is not None:
            expires_at = int(time.time()) + self.expires_in_secs
        
        return AgentCredential.create(
            child_keypair,
            parent_heartbeat_pubkey,
            metadata,
            expires_at
        )


# === TESTS ===

if __name__ == "__main__":
    from .keys import AgentKeyPair
    from .heartbeat import Heartbeat
    
    print("Testing credentials...")
    
    # Create parent and child
    parent = AgentKeyPair.generate_root("parent")
    child = parent.derive_child("child-1")
    
    # Build credential
    credential = (CredentialBuilder()
        .with_scope("read")
        .with_scope("write")
        .with_attribute("mission", "survey")
        .build(child, parent.heartbeat_public_key()))
    
    assert credential.agent_id == "child-1"
    assert credential.metadata.scopes == ["read", "write"]
    print(f"✓ Created credential for {credential.agent_id}")
    print(f"  Scopes: {credential.metadata.scopes}")
    
    # Verify binding
    assert credential.verify_binding(parent.heartbeat_public_key()) == True
    print("✓ Heartbeat binding verified")
    
    # Wrong parent should fail
    other_parent = AgentKeyPair.generate_root("other")
    assert credential.verify_binding(other_parent.heartbeat_public_key()) == False
    print("✓ Wrong parent binding rejected")
    
    # Create proof
    heartbeat = Heartbeat.create(parent.heartbeat_key, 100)
    challenge = b"test-challenge-12345"
    
    proof = CredentialProof.create(
        credential,
        heartbeat,
        challenge,
        child.identity_key
    )
    
    assert proof.verify_signature() == True
    print("✓ Credential proof signature verified")
    
    print("\nAll credential tests passed! ✓")
