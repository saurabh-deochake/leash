"""
Key management for LEASH.

Implements hierarchical deterministic key derivation for agent credentials.
Uses ECDSA with secp256k1 curve (same as Bitcoin/Ethereum).
"""

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Optional

from ecdsa import SigningKey, VerifyingKey, SECP256k1


@dataclass
class AgentKeyPair:
    """
    Agent key pair containing identity and heartbeat keys.
    
    Each agent has:
    - identity_key: Long-term signing key for authentication
    - heartbeat_key: Key for generating heartbeat signatures (derived from identity)
    - child_derivation_key: Key material for deriving child agent keys
    - agent_id: Unique identifier for this agent
    """
    identity_key: SigningKey
    heartbeat_key: SigningKey
    child_derivation_key: bytes  # 32 bytes
    agent_id: str
    
    @classmethod
    def generate_root(cls, agent_id: str) -> "AgentKeyPair":
        """
        Generate a new root agent key pair with random keys.
        
        Args:
            agent_id: Unique identifier for this agent
            
        Returns:
            New AgentKeyPair instance
        """
        # Generate random 32-byte seed
        seed = secrets.token_bytes(32)
        identity_key = SigningKey.from_string(seed, curve=SECP256k1)
        return cls._from_identity_key(identity_key, agent_id)
    
    @classmethod
    def _from_identity_key(cls, identity_key: SigningKey, agent_id: str) -> "AgentKeyPair":
        """Create key pair from existing identity key."""
        identity_bytes = identity_key.to_string()
        
        # Derive heartbeat key using HKDF-like construction
        heartbeat_bytes = hmac.new(
            identity_bytes,
            b"heartbeat",
            hashlib.sha256
        ).digest()
        heartbeat_key = SigningKey.from_string(heartbeat_bytes, curve=SECP256k1)
        
        # Derive child derivation key
        child_derivation_key = hmac.new(
            identity_bytes,
            b"children",
            hashlib.sha256
        ).digest()
        
        return cls(
            identity_key=identity_key,
            heartbeat_key=heartbeat_key,
            child_derivation_key=child_derivation_key,
            agent_id=agent_id
        )
    
    def identity_public_key(self) -> VerifyingKey:
        """Get the public identity key."""
        return self.identity_key.get_verifying_key()
    
    def heartbeat_public_key(self) -> VerifyingKey:
        """Get the public heartbeat key."""
        return self.heartbeat_key.get_verifying_key()
    
    def derive_child(self, child_id: str) -> "AgentKeyPair":
        """
        Derive a child agent's key pair.
        
        This is deterministic - same child_id always produces same keys.
        
        Args:
            child_id: Unique identifier for the child agent
            
        Returns:
            New AgentKeyPair for the child
        """
        # Derive child identity key from parent's child_derivation_key
        child_identity_bytes = hmac.new(
            self.child_derivation_key,
            child_id.encode('utf-8'),
            hashlib.sha256
        ).digest()
        
        child_identity_key = SigningKey.from_string(child_identity_bytes, curve=SECP256k1)
        return AgentKeyPair._from_identity_key(child_identity_key, child_id)
    
    def public_key_bytes(self) -> bytes:
        """Get identity public key as bytes."""
        return self.identity_public_key().to_string()
    
    def heartbeat_public_key_bytes(self) -> bytes:
        """Get heartbeat public key as bytes."""
        return self.heartbeat_public_key().to_string()


class KeyHierarchy:
    """
    Key hierarchy for managing parent-child agent relationships.
    
    Example:
        hierarchy = KeyHierarchy("command-center")
        drone1 = hierarchy.add_child("drone-1")
        drone2 = hierarchy.add_child("drone-2")
    """
    
    def __init__(self, root_id: str):
        """
        Create a new key hierarchy with a root agent.
        
        Args:
            root_id: Identifier for the root agent
        """
        self.root = AgentKeyPair.generate_root(root_id)
        self._children: dict[str, AgentKeyPair] = {}
    
    def add_child(self, child_id: str) -> AgentKeyPair:
        """
        Add a child agent to the hierarchy.
        
        Args:
            child_id: Unique identifier for the child
            
        Returns:
            The child's AgentKeyPair
        """
        child = self.root.derive_child(child_id)
        self._children[child_id] = child
        return child
    
    def get_child(self, child_id: str) -> Optional[AgentKeyPair]:
        """Get a child by ID."""
        return self._children.get(child_id)
    
    def children(self) -> list[AgentKeyPair]:
        """Get all children."""
        return list(self._children.values())


def compute_heartbeat_binding(parent_heartbeat_pubkey: VerifyingKey, child_id: str) -> bytes:
    """
    Compute the heartbeat binding for a child agent.
    
    This binds the child's credential to the parent's heartbeat key.
    
    Args:
        parent_heartbeat_pubkey: Parent's heartbeat public key
        child_id: Child agent's identifier
        
    Returns:
        32-byte binding hash
    """
    hasher = hashlib.sha256()
    hasher.update(parent_heartbeat_pubkey.to_string())
    hasher.update(child_id.encode('utf-8'))
    return hasher.digest()


# === TESTS ===

if __name__ == "__main__":
    print("Testing key generation...")
    
    # Test root key generation
    parent = AgentKeyPair.generate_root("parent-agent")
    print(f"✓ Created parent agent: {parent.agent_id}")
    
    # Test child derivation
    child1 = parent.derive_child("child-1")
    child2 = parent.derive_child("child-2")
    print(f"✓ Derived child: {child1.agent_id}")
    print(f"✓ Derived child: {child2.agent_id}")
    
    # Verify children have different keys
    assert child1.public_key_bytes() != child2.public_key_bytes()
    print("✓ Children have different keys")
    
    # Verify derivation is deterministic
    child1_again = parent.derive_child("child-1")
    assert child1.public_key_bytes() == child1_again.public_key_bytes()
    print("✓ Derivation is deterministic")
    
    # Test heartbeat binding
    binding1 = compute_heartbeat_binding(parent.heartbeat_public_key(), "child-1")
    binding2 = compute_heartbeat_binding(parent.heartbeat_public_key(), "child-2")
    assert binding1 != binding2
    print("✓ Heartbeat bindings are unique per child")
    
    # Test hierarchy
    hierarchy = KeyHierarchy("command-center")
    hierarchy.add_child("drone-alpha")
    hierarchy.add_child("drone-beta")
    assert len(hierarchy.children()) == 2
    print("✓ Key hierarchy works")
    
    print("\nAll key tests passed! ✓")
