"""
Unit tests for LEASH library.

Run with: pytest tests/test_leash.py -v
"""

import pytest
import time
from leash import (
    LeashConfig,
    AgentKeyPair,
    KeyHierarchy,
    Heartbeat,
    HeartbeatGenerator,
    HeartbeatCache,
    CredentialBuilder,
    CredentialProof,
    Verifier,
)
from leash.verification import generate_challenge


class TestKeys:
    """Tests for key generation and derivation."""
    
    def test_root_key_generation(self):
        """Test that root keys can be generated."""
        parent = AgentKeyPair.generate_root("test-parent")
        assert parent.agent_id == "test-parent"
        assert parent.identity_key is not None
        assert parent.heartbeat_key is not None
    
    def test_child_derivation(self):
        """Test that child keys are derived correctly."""
        parent = AgentKeyPair.generate_root("parent")
        child1 = parent.derive_child("child-1")
        child2 = parent.derive_child("child-2")
        
        # Children should have different keys
        assert child1.public_key_bytes() != child2.public_key_bytes()
    
    def test_derivation_is_deterministic(self):
        """Test that same child_id produces same keys."""
        parent = AgentKeyPair.generate_root("parent")
        child1 = parent.derive_child("child-1")
        child1_again = parent.derive_child("child-1")
        
        assert child1.public_key_bytes() == child1_again.public_key_bytes()
    
    def test_key_hierarchy(self):
        """Test KeyHierarchy helper class."""
        hierarchy = KeyHierarchy("root")
        hierarchy.add_child("child-a")
        hierarchy.add_child("child-b")
        
        assert len(hierarchy.children()) == 2
        assert hierarchy.get_child("child-a") is not None
        assert hierarchy.get_child("nonexistent") is None


class TestHeartbeat:
    """Tests for heartbeat generation and verification."""
    
    def test_heartbeat_creation(self):
        """Test heartbeat creation."""
        parent = AgentKeyPair.generate_root("parent")
        hb = Heartbeat.create(parent.heartbeat_key, 100)
        
        assert hb.epoch == 100
        assert len(hb.commitment) == 32
        assert len(hb.signature) > 0
    
    def test_heartbeat_verification(self):
        """Test heartbeat signature verification."""
        parent = AgentKeyPair.generate_root("parent")
        hb = Heartbeat.create(parent.heartbeat_key, 100)
        
        assert hb.verify() == True
    
    def test_heartbeat_freshness(self):
        """Test heartbeat freshness checking."""
        parent = AgentKeyPair.generate_root("parent")
        hb = Heartbeat.create(parent.heartbeat_key, 100)
        
        # Same epoch - fresh
        assert hb.is_fresh(100, 3) == True
        
        # Within window - fresh
        assert hb.is_fresh(103, 3) == True
        
        # Outside window - stale
        assert hb.is_fresh(104, 3) == False
    
    def test_heartbeat_generator(self):
        """Test HeartbeatGenerator."""
        parent = AgentKeyPair.generate_root("parent")
        config = LeashConfig()
        gen = HeartbeatGenerator(parent.heartbeat_key, config)
        
        hb = gen.generate()
        assert hb.verify() == True
    
    def test_heartbeat_pregeneration(self):
        """Test pre-generating heartbeats for future epochs."""
        parent = AgentKeyPair.generate_root("parent")
        config = LeashConfig()
        gen = HeartbeatGenerator(parent.heartbeat_key, config)
        
        pregenerated = gen.pregenerate(5)
        assert len(pregenerated) == 5
        
        for hb in pregenerated:
            assert hb.verify() == True
    
    def test_heartbeat_cache(self):
        """Test HeartbeatCache."""
        config = LeashConfig(heartbeat_interval_secs=10, max_heartbeat_age_secs=30)
        cache = HeartbeatCache(config)
        
        parent = AgentKeyPair.generate_root("parent")
        current_epoch = int(time.time()) // 10
        
        hb = Heartbeat.create(parent.heartbeat_key, current_epoch)
        cache.add(hb)
        
        latest = cache.get_latest()
        assert latest is not None
        assert latest.epoch == current_epoch


class TestCredentials:
    """Tests for credentials and proofs."""
    
    def test_credential_creation(self):
        """Test credential creation with builder."""
        parent = AgentKeyPair.generate_root("parent")
        child = parent.derive_child("child-1")
        
        cred = (CredentialBuilder()
            .with_scope("read")
            .with_scope("write")
            .with_attribute("key", "value")
            .build(child, parent.heartbeat_public_key()))
        
        assert cred.agent_id == "child-1"
        assert cred.metadata.scopes == ["read", "write"]
        assert cred.metadata.attributes["key"] == "value"
    
    def test_heartbeat_binding(self):
        """Test that heartbeat binding is verified correctly."""
        parent = AgentKeyPair.generate_root("parent")
        child = parent.derive_child("child-1")
        
        cred = CredentialBuilder().build(child, parent.heartbeat_public_key())
        
        # Correct parent - should pass
        assert cred.verify_binding(parent.heartbeat_public_key()) == True
        
        # Wrong parent - should fail
        other = AgentKeyPair.generate_root("other")
        assert cred.verify_binding(other.heartbeat_public_key()) == False
    
    def test_credential_proof(self):
        """Test credential proof creation and verification."""
        parent = AgentKeyPair.generate_root("parent")
        child = parent.derive_child("child-1")
        
        cred = CredentialBuilder().build(child, parent.heartbeat_public_key())
        hb = Heartbeat.create(parent.heartbeat_key, 100)
        challenge = b"test-challenge"
        
        proof = CredentialProof.create(cred, hb, challenge, child.identity_key)
        
        assert proof.verify_signature() == True
        assert proof.heartbeat_epoch() == 100


class TestVerification:
    """Tests for the verification process."""
    
    @pytest.fixture
    def setup(self):
        """Setup test fixtures."""
        config = LeashConfig(heartbeat_interval_secs=10, max_heartbeat_age_secs=30)
        parent = AgentKeyPair.generate_root("parent")
        child = parent.derive_child("child-1")
        
        verifier = Verifier(config)
        verifier.trust_parent("parent", parent.heartbeat_public_key())
        
        return {
            "config": config,
            "parent": parent,
            "child": child,
            "verifier": verifier
        }
    
    def test_successful_verification(self, setup):
        """Test successful verification with fresh heartbeat."""
        parent = setup["parent"]
        child = setup["child"]
        verifier = setup["verifier"]
        
        cred = CredentialBuilder().with_scope("read").build(
            child, parent.heartbeat_public_key()
        )
        
        current_epoch = verifier.current_epoch()
        hb = Heartbeat.create(parent.heartbeat_key, current_epoch)
        challenge = generate_challenge()
        
        proof = CredentialProof.create(cred, hb, challenge, child.identity_key)
        result = verifier.verify(proof, challenge)
        
        assert result.valid == True
        assert result.agent_id == "child-1"
    
    def test_expired_heartbeat_rejected(self, setup):
        """Test that expired heartbeats are rejected."""
        parent = setup["parent"]
        child = setup["child"]
        verifier = setup["verifier"]
        
        cred = CredentialBuilder().build(child, parent.heartbeat_public_key())
        
        # Create heartbeat from 100 epochs ago (way too old)
        old_epoch = verifier.current_epoch() - 100
        hb = Heartbeat.create(parent.heartbeat_key, old_epoch)
        challenge = generate_challenge()
        
        proof = CredentialProof.create(cred, hb, challenge, child.identity_key)
        result = verifier.verify(proof, challenge)
        
        assert result.valid == False
        assert "expired" in result.error.lower()
    
    def test_untrusted_parent_rejected(self, setup):
        """Test that credentials from untrusted parents are rejected."""
        verifier = setup["verifier"]
        
        # Create a different parent (not trusted)
        other_parent = AgentKeyPair.generate_root("other")
        other_child = other_parent.derive_child("other-child")
        
        cred = CredentialBuilder().build(
            other_child, other_parent.heartbeat_public_key()
        )
        
        current_epoch = verifier.current_epoch()
        hb = Heartbeat.create(other_parent.heartbeat_key, current_epoch)
        challenge = generate_challenge()
        
        proof = CredentialProof.create(cred, hb, challenge, other_child.identity_key)
        result = verifier.verify(proof, challenge)
        
        assert result.valid == False
        assert "not trusted" in result.error.lower()
    
    def test_wrong_challenge_rejected(self, setup):
        """Test that wrong challenge is rejected."""
        parent = setup["parent"]
        child = setup["child"]
        verifier = setup["verifier"]
        
        cred = CredentialBuilder().build(child, parent.heartbeat_public_key())
        
        current_epoch = verifier.current_epoch()
        hb = Heartbeat.create(parent.heartbeat_key, current_epoch)
        
        challenge1 = generate_challenge()
        challenge2 = generate_challenge()  # Different challenge
        
        proof = CredentialProof.create(cred, hb, challenge1, child.identity_key)
        result = verifier.verify(proof, challenge2)  # Verify with wrong challenge
        
        assert result.valid == False


class TestZombieWindow:
    """Tests specifically for zombie window behavior."""
    
    def test_zombie_window_bounded(self):
        """Test that zombie window is bounded by max_heartbeat_age."""
        config = LeashConfig(heartbeat_interval_secs=10, max_heartbeat_age_secs=30)
        parent = AgentKeyPair.generate_root("parent")
        child = parent.derive_child("child")
        
        verifier = Verifier(config)
        verifier.trust_parent("parent", parent.heartbeat_public_key())
        
        cred = CredentialBuilder().build(child, parent.heartbeat_public_key())
        challenge = generate_challenge()
        
        # Create heartbeat at current epoch
        base_epoch = verifier.current_epoch()
        hb = Heartbeat.create(parent.heartbeat_key, base_epoch)
        
        # Test at various ages
        max_age_epochs = config.max_age_epochs()  # 3 epochs
        
        for age in range(max_age_epochs + 2):
            # Simulate time passing by checking against future epoch
            simulated_current = base_epoch + age
            
            proof = CredentialProof.create(cred, hb, challenge, child.identity_key)
            
            # Manually check freshness (since we can't actually advance time)
            is_fresh = hb.is_fresh(simulated_current, max_age_epochs)
            
            if age <= max_age_epochs:
                assert is_fresh == True, f"Should be fresh at age {age}"
            else:
                assert is_fresh == False, f"Should be stale at age {age}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
