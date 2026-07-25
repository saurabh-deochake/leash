"""
Verification logic for LEASH credentials.

Implements the verifier component that validates authentication proofs
including heartbeat freshness checks.
"""

import hashlib
import secrets
import time
from dataclasses import dataclass, field
from typing import Optional

from ecdsa import VerifyingKey, SECP256k1

from .config import LeashConfig
from .credentials import CredentialProof
from .heartbeat import Heartbeat


@dataclass
class VerificationResult:
    """Result of credential verification."""
    valid: bool
    agent_id: str
    heartbeat_epoch: int
    current_epoch: int
    scopes: list[str]
    warnings: list[str] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class TrustedParent:
    """A trusted parent agent."""
    agent_id: str
    heartbeat_pubkey: VerifyingKey
    allowed_scopes: Optional[list[str]] = None


class Verifier:
    """
    Verifier for LEASH credentials.
    
    Resource servers use this to validate authentication proofs from agents.
    
    Example:
        verifier = Verifier(config)
        verifier.trust_parent("command-center", parent_pubkey)
        
        result = verifier.verify(proof, challenge)
        if result.valid:
            print(f"Agent {result.agent_id} authenticated with scopes {result.scopes}")
    """
    
    def __init__(self, config: LeashConfig):
        """
        Create a new verifier.
        
        Args:
            config: LEASH configuration
        """
        self.config = config
        self.trusted_parents: list[TrustedParent] = []
        # Monotonic sequence tracking: agent_id -> last accepted sequence number.
        # Only populated when config.use_sequence_numbers is True.
        self._sequence_cache: dict[str, int] = {}
    
    def trust_parent(
        self,
        agent_id: str,
        heartbeat_pubkey: VerifyingKey,
        allowed_scopes: Optional[list[str]] = None
    ) -> None:
        """
        Add a trusted parent.
        
        Args:
            agent_id: Parent agent's identifier
            heartbeat_pubkey: Parent's heartbeat public key
            allowed_scopes: Optional list of scopes this parent can grant
        """
        self.trusted_parents.append(TrustedParent(
            agent_id=agent_id,
            heartbeat_pubkey=heartbeat_pubkey,
            allowed_scopes=allowed_scopes
        ))
    
    def current_epoch(self) -> int:
        """Get the current epoch."""
        return int(time.time()) // self.config.heartbeat_interval_secs
    
    def verify(self, proof: CredentialProof, challenge: bytes) -> VerificationResult:
        """
        Verify a credential proof.
        
        This performs all verification steps:
        1. Challenge matches
        2. Credential not expired
        3. Parent is trusted
        4. Heartbeat binding is valid
        5. Heartbeat is fresh
        6. Heartbeat signature is valid
        7. Proof signature is valid
        
        Args:
            proof: The credential proof to verify
            challenge: The challenge that was issued
            
        Returns:
            VerificationResult with success/failure and details
        """
        current_epoch = self.current_epoch()
        warnings = []
        
        # 1. Verify challenge matches
        if proof.challenge != challenge:
            return VerificationResult(
                valid=False,
                agent_id=proof.credential.agent_id,
                heartbeat_epoch=proof.heartbeat_epoch(),
                current_epoch=current_epoch,
                scopes=[],
                error="Challenge mismatch"
            )
        
        # 2. Check credential expiration
        if proof.credential.is_expired():
            return VerificationResult(
                valid=False,
                agent_id=proof.credential.agent_id,
                heartbeat_epoch=proof.heartbeat_epoch(),
                current_epoch=current_epoch,
                scopes=[],
                error="Credential expired"
            )
        
        # 3. Find trusted parent
        parent_pubkey = VerifyingKey.from_string(
            proof.credential.parent_heartbeat_pubkey,
            curve=SECP256k1
        )
        
        trusted_parent = None
        for tp in self.trusted_parents:
            if tp.heartbeat_pubkey.to_string() == parent_pubkey.to_string():
                trusted_parent = tp
                break
        
        if trusted_parent is None:
            return VerificationResult(
                valid=False,
                agent_id=proof.credential.agent_id,
                heartbeat_epoch=proof.heartbeat_epoch(),
                current_epoch=current_epoch,
                scopes=[],
                error="Parent not trusted"
            )
        
        # 4. Verify heartbeat binding
        if not proof.credential.verify_binding(parent_pubkey):
            return VerificationResult(
                valid=False,
                agent_id=proof.credential.agent_id,
                heartbeat_epoch=proof.heartbeat_epoch(),
                current_epoch=current_epoch,
                scopes=[],
                error="Heartbeat binding mismatch"
            )
        
        # 5. Check heartbeat freshness
        max_age_epochs = self.config.max_age_epochs()
        if not proof.heartbeat.is_fresh(current_epoch, max_age_epochs):
            return VerificationResult(
                valid=False,
                agent_id=proof.credential.agent_id,
                heartbeat_epoch=proof.heartbeat_epoch(),
                current_epoch=current_epoch,
                scopes=[],
                error=f"Heartbeat expired: epoch {proof.heartbeat_epoch()} is too old (current: {current_epoch}, max age: {max_age_epochs})"
            )
        
        # Add warning if heartbeat is nearing expiration
        age = current_epoch - proof.heartbeat_epoch()
        if age >= max_age_epochs - 1:
            warnings.append(f"Heartbeat nearing expiration: age {age} of max {max_age_epochs}")

        # 5b. Monotonic sequence number check (additive — only when enabled)
        if self.config.use_sequence_numbers and proof.heartbeat.sequence_number > 0:
            agent_id = proof.credential.agent_id
            seq = proof.heartbeat.sequence_number
            last_seen = self._sequence_cache.get(agent_id)

            if last_seen is not None:
                if seq <= last_seen:
                    return VerificationResult(
                        valid=False,
                        agent_id=agent_id,
                        heartbeat_epoch=proof.heartbeat_epoch(),
                        current_epoch=current_epoch,
                        scopes=[],
                        error=f"Sequence regression: {seq} <= last seen {last_seen}",
                    )
                if seq - last_seen > self.config.max_sequence_gap:
                    return VerificationResult(
                        valid=False,
                        agent_id=agent_id,
                        heartbeat_epoch=proof.heartbeat_epoch(),
                        current_epoch=current_epoch,
                        scopes=[],
                        error=f"Sequence gap too large: {seq} - {last_seen} = {seq - last_seen} > {self.config.max_sequence_gap}",
                    )

            # Accept — cache the new sequence number
            self._sequence_cache[agent_id] = seq

        # 6. Verify heartbeat signature
        if not proof.heartbeat.verify():
            return VerificationResult(
                valid=False,
                agent_id=proof.credential.agent_id,
                heartbeat_epoch=proof.heartbeat_epoch(),
                current_epoch=current_epoch,
                scopes=[],
                error="Invalid heartbeat signature"
            )
        
        # 7. Verify proof signature
        if not proof.verify_signature():
            return VerificationResult(
                valid=False,
                agent_id=proof.credential.agent_id,
                heartbeat_epoch=proof.heartbeat_epoch(),
                current_epoch=current_epoch,
                scopes=[],
                error="Invalid proof signature"
            )
        
        # 8. Filter scopes based on parent restrictions
        scopes = proof.credential.metadata.scopes
        if trusted_parent.allowed_scopes is not None:
            scopes = [s for s in scopes if s in trusted_parent.allowed_scopes]
        
        return VerificationResult(
            valid=True,
            agent_id=proof.credential.agent_id,
            heartbeat_epoch=proof.heartbeat_epoch(),
            current_epoch=current_epoch,
            scopes=scopes,
            warnings=warnings
        )
    
    def verify_heartbeat(self, heartbeat: Heartbeat) -> bool:
        """
        Quick check if a heartbeat is valid and fresh.
        
        Args:
            heartbeat: The heartbeat to verify
            
        Returns:
            True if heartbeat is valid and fresh
        """
        if not heartbeat.verify():
            return False
        
        current_epoch = self.current_epoch()
        max_age_epochs = self.config.max_age_epochs()
        
        return heartbeat.is_fresh(current_epoch, max_age_epochs)


def generate_challenge(
    resource: Optional[str] = None,
    action: Optional[str] = None
) -> bytes:
    """
    Generate a verification challenge.
    
    Args:
        resource: Optional resource being accessed
        action: Optional action being performed
        
    Returns:
        32-byte challenge
    """
    nonce = secrets.token_bytes(32)
    timestamp = int(time.time()).to_bytes(8, 'little')
    
    hasher = hashlib.sha256()
    hasher.update(nonce)
    hasher.update(timestamp)
    
    if resource:
        hasher.update(resource.encode('utf-8'))
    if action:
        hasher.update(action.encode('utf-8'))
    
    return hasher.digest()


# === TESTS ===

if __name__ == "__main__":
    from .keys import AgentKeyPair
    from .heartbeat import Heartbeat
    from .credentials import CredentialBuilder, CredentialProof
    
    print("Testing verification...")
    
    # Setup
    config = LeashConfig(heartbeat_interval_secs=10, max_heartbeat_age_secs=30)
    parent = AgentKeyPair.generate_root("parent")
    child = parent.derive_child("child-1")
    
    verifier = Verifier(config)
    verifier.trust_parent("parent", parent.heartbeat_public_key())
    
    # Create credential and proof
    credential = (CredentialBuilder()
        .with_scope("read")
        .build(child, parent.heartbeat_public_key()))
    
    current_epoch = verifier.current_epoch()
    heartbeat = Heartbeat.create(parent.heartbeat_key, current_epoch)
    challenge = generate_challenge("/api/data", "read")
    
    proof = CredentialProof.create(
        credential,
        heartbeat,
        challenge,
        child.identity_key
    )
    
    # Test successful verification
    result = verifier.verify(proof, challenge)
    assert result.valid == True
    assert result.agent_id == "child-1"
    print(f"✓ Verification successful for {result.agent_id}")
    print(f"  Scopes: {result.scopes}")
    
    # Test expired heartbeat
    old_heartbeat = Heartbeat.create(parent.heartbeat_key, current_epoch - 100)
    old_proof = CredentialProof.create(
        credential,
        old_heartbeat,
        challenge,
        child.identity_key
    )
    
    result = verifier.verify(old_proof, challenge)
    assert result.valid == False
    assert "expired" in result.error.lower()
    print(f"✓ Expired heartbeat rejected: {result.error}")
    
    # Test untrusted parent
    other_parent = AgentKeyPair.generate_root("other")
    other_child = other_parent.derive_child("other-child")
    other_cred = (CredentialBuilder()
        .build(other_child, other_parent.heartbeat_public_key()))
    other_hb = Heartbeat.create(other_parent.heartbeat_key, current_epoch)
    other_proof = CredentialProof.create(
        other_cred,
        other_hb,
        challenge,
        other_child.identity_key
    )
    
    result = verifier.verify(other_proof, challenge)
    assert result.valid == False
    assert "not trusted" in result.error.lower()
    print(f"✓ Untrusted parent rejected: {result.error}")
    
    print("\nAll verification tests passed! ✓")
