"""
Heartbeat generation and management.

Implements the periodic heartbeat mechanism that binds child credential validity
to parent liveness. This is the core of LEASH's partition-tolerant revocation.
"""

import hashlib
import time
from dataclasses import dataclass, field
from typing import Optional

from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError

from .config import LeashConfig


@dataclass
class Heartbeat:
    """
    A heartbeat signature proving parent liveness at a specific epoch.
    
    The heartbeat contains:
    - epoch: Time period number (current_time / interval)
    - commitment: Hash of (parent_pubkey || epoch)
    - signature: ECDSA signature over the commitment
    - parent_heartbeat_pubkey: For verification
    """
    epoch: int
    commitment: bytes  # 32 bytes
    signature: bytes   # ECDSA signature
    parent_heartbeat_pubkey: bytes  # Public key bytes
    sequence_number: int = 0  # Monotonic counter (0 = sequence mode disabled)
    
    @classmethod
    def create(cls, heartbeat_signing_key: SigningKey, epoch: int) -> "Heartbeat":
        """
        Create a new heartbeat for the given epoch.
        
        Args:
            heartbeat_signing_key: Parent's heartbeat signing key
            epoch: The epoch number
            
        Returns:
            New Heartbeat instance
        """
        heartbeat_pubkey = heartbeat_signing_key.get_verifying_key()
        commitment = cls.compute_commitment(heartbeat_pubkey, epoch)
        signature = heartbeat_signing_key.sign(commitment)
        
        return cls(
            epoch=epoch,
            commitment=commitment,
            signature=signature,
            parent_heartbeat_pubkey=heartbeat_pubkey.to_string()
        )
    
    @classmethod
    def create_with_seq(
        cls,
        heartbeat_signing_key: SigningKey,
        epoch: int,
        sequence_number: int,
    ) -> "Heartbeat":
        """
        Create a heartbeat that includes a monotonic sequence number.

        The sequence number is mixed into the commitment hash so that
        replaying an old heartbeat with a different sequence fails
        signature verification.

        Args:
            heartbeat_signing_key: Parent's heartbeat signing key
            epoch: The epoch number
            sequence_number: Monotonically increasing counter

        Returns:
            New Heartbeat instance with sequence_number set
        """
        heartbeat_pubkey = heartbeat_signing_key.get_verifying_key()
        commitment = cls.compute_commitment_with_seq(
            heartbeat_pubkey, epoch, sequence_number
        )
        signature = heartbeat_signing_key.sign(commitment)

        return cls(
            epoch=epoch,
            commitment=commitment,
            signature=signature,
            parent_heartbeat_pubkey=heartbeat_pubkey.to_string(),
            sequence_number=sequence_number,
        )

    @staticmethod
    def compute_commitment(heartbeat_pubkey: VerifyingKey, epoch: int) -> bytes:
        """Compute the commitment hash for a given epoch."""
        hasher = hashlib.sha256()
        hasher.update(heartbeat_pubkey.to_string())
        hasher.update(epoch.to_bytes(8, 'little'))
        return hasher.digest()

    @staticmethod
    def compute_commitment_with_seq(
        heartbeat_pubkey: VerifyingKey, epoch: int, sequence_number: int
    ) -> bytes:
        """Compute the commitment hash including a sequence number."""
        hasher = hashlib.sha256()
        hasher.update(heartbeat_pubkey.to_string())
        hasher.update(epoch.to_bytes(8, 'little'))
        hasher.update(sequence_number.to_bytes(8, 'little'))
        return hasher.digest()
    
    def verify(self) -> bool:
        """
        Verify this heartbeat's signature.
        
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            pubkey = VerifyingKey.from_string(self.parent_heartbeat_pubkey, curve=SECP256k1)
            pubkey.verify(self.signature, self.commitment)
            return True
        except BadSignatureError:
            return False
    
    def is_fresh(self, current_epoch: int, max_age_epochs: int) -> bool:
        """
        Check if this heartbeat is fresh enough.
        
        Args:
            current_epoch: The current epoch number
            max_age_epochs: Maximum allowed age in epochs
            
        Returns:
            True if heartbeat is within acceptable age
        """
        age = current_epoch - self.epoch
        return 0 <= age <= max_age_epochs
    
    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        d = {
            "epoch": self.epoch,
            "commitment": self.commitment.hex(),
            "signature": self.signature.hex(),
            "parent_heartbeat_pubkey": self.parent_heartbeat_pubkey.hex(),
        }
        if self.sequence_number != 0:
            d["sequence_number"] = self.sequence_number
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "Heartbeat":
        """Deserialize from dictionary."""
        return cls(
            epoch=data["epoch"],
            commitment=bytes.fromhex(data["commitment"]),
            signature=bytes.fromhex(data["signature"]),
            parent_heartbeat_pubkey=bytes.fromhex(data["parent_heartbeat_pubkey"]),
            sequence_number=data.get("sequence_number", 0),
        )


class HeartbeatGenerator:
    """
    Generator for periodic heartbeats.
    
    Used by parent agents to generate heartbeats at regular intervals.
    
    Example:
        generator = HeartbeatGenerator(parent.heartbeat_key, config)
        heartbeat = generator.generate()  # Generate for current epoch
    """
    
    def __init__(self, heartbeat_key: SigningKey, config: LeashConfig):
        """
        Create a new heartbeat generator.
        
        Args:
            heartbeat_key: The signing key for heartbeats
            config: LEASH configuration
        """
        self.heartbeat_key = heartbeat_key
        self.config = config
        self.last_epoch: Optional[int] = None
        self.pregenerated: list[Heartbeat] = []
        self._sequence_counter: int = 0
    
    def current_epoch(self) -> int:
        """Get the current epoch based on system time."""
        return int(time.time()) // self.config.heartbeat_interval_secs
    
    def generate(self) -> Heartbeat:
        """Generate a heartbeat for the current epoch."""
        epoch = self.current_epoch()
        self.last_epoch = epoch
        if self.config.use_sequence_numbers:
            self._sequence_counter += 1
            return Heartbeat.create_with_seq(
                self.heartbeat_key, epoch, self._sequence_counter
            )
        return Heartbeat.create(self.heartbeat_key, epoch)

    def generate_for_epoch(self, epoch: int) -> Heartbeat:
        """Generate a heartbeat for a specific epoch."""
        if self.config.use_sequence_numbers:
            self._sequence_counter += 1
            return Heartbeat.create_with_seq(
                self.heartbeat_key, epoch, self._sequence_counter
            )
        return Heartbeat.create(self.heartbeat_key, epoch)
    
    def pregenerate(self, num_epochs: int) -> list[Heartbeat]:
        """
        Pre-generate heartbeats for future epochs.
        
        Useful for planned disconnection scenarios where the parent
        knows it will be offline but wants children to remain valid.
        
        Args:
            num_epochs: Number of future epochs to pre-generate
            
        Returns:
            List of pre-generated heartbeats
        """
        start_epoch = self.current_epoch()
        self.pregenerated = [
            self.generate_for_epoch(start_epoch + i)  # increments _sequence_counter when enabled
            for i in range(num_epochs)
        ]
        return self.pregenerated
    
    def should_generate(self) -> bool:
        """Check if a new heartbeat should be generated."""
        if self.last_epoch is None:
            return True
        return self.current_epoch() > self.last_epoch
    
    def public_key(self) -> VerifyingKey:
        """Get the heartbeat public key."""
        return self.heartbeat_key.get_verifying_key()


class HeartbeatCache:
    """
    Heartbeat cache for child agents.
    
    Child agents use this to store received heartbeats and retrieve
    the most recent valid one for authentication.
    
    Example:
        cache = HeartbeatCache(config)
        cache.add(heartbeat_from_parent)
        latest = cache.get_latest()  # Get freshest heartbeat
    """
    
    def __init__(self, config: LeashConfig, max_cache_size: int = 10):
        """
        Create a new heartbeat cache.
        
        Args:
            config: LEASH configuration
            max_cache_size: Maximum heartbeats to store
        """
        self.config = config
        self.max_cache_size = max_cache_size
        self.heartbeats: list[Heartbeat] = []
    
    def current_epoch(self) -> int:
        """Get the current epoch."""
        return int(time.time()) // self.config.heartbeat_interval_secs
    
    def add(self, heartbeat: Heartbeat) -> None:
        """
        Add a heartbeat to the cache.
        
        Automatically removes stale heartbeats and duplicates.
        """
        current_epoch = self.current_epoch()
        max_age = self.config.max_age_epochs() + 1
        
        # Remove stale heartbeats
        self.heartbeats = [
            hb for hb in self.heartbeats
            if hb.is_fresh(current_epoch, max_age)
        ]
        
        # Don't add duplicates
        if not any(hb.epoch == heartbeat.epoch for hb in self.heartbeats):
            self.heartbeats.append(heartbeat)
        
        # Trim to max size (keep newest)
        if len(self.heartbeats) > self.max_cache_size:
            self.heartbeats.sort(key=lambda hb: hb.epoch)
            self.heartbeats = self.heartbeats[-self.max_cache_size:]
    
    def get_latest(self) -> Optional[Heartbeat]:
        """
        Get the most recent valid heartbeat.
        
        Returns:
            The freshest heartbeat, or None if no valid heartbeats
        """
        current_epoch = self.current_epoch()
        max_age = self.config.max_age_epochs()
        
        valid = [
            hb for hb in self.heartbeats
            if hb.is_fresh(current_epoch, max_age)
        ]
        
        if not valid:
            return None
        
        return max(valid, key=lambda hb: hb.epoch)
    
    def get(self, epoch: int) -> Optional[Heartbeat]:
        """Get heartbeat for a specific epoch."""
        for hb in self.heartbeats:
            if hb.epoch == epoch:
                return hb
        return None
    
    def is_empty(self) -> bool:
        """Check if cache has no valid heartbeats."""
        return self.get_latest() is None


# === TESTS ===

if __name__ == "__main__":
    from .keys import AgentKeyPair
    
    print("Testing heartbeat generation...")
    
    # Create parent agent
    parent = AgentKeyPair.generate_root("parent")
    config = LeashConfig(heartbeat_interval_secs=10, max_heartbeat_age_secs=30)
    
    # Test heartbeat creation
    hb = Heartbeat.create(parent.heartbeat_key, 100)
    assert hb.epoch == 100
    print(f"✓ Created heartbeat for epoch {hb.epoch}")
    
    # Test signature verification
    assert hb.verify() == True
    print("✓ Heartbeat signature verified")
    
    # Test freshness
    assert hb.is_fresh(100, 3) == True   # Same epoch
    assert hb.is_fresh(103, 3) == True   # Within window
    assert hb.is_fresh(104, 3) == False  # Outside window
    print("✓ Freshness check works")
    
    # Test generator
    generator = HeartbeatGenerator(parent.heartbeat_key, config)
    hb = generator.generate()
    assert hb.verify() == True
    print(f"✓ Generator created heartbeat for epoch {hb.epoch}")
    
    # Test pre-generation
    pregenerated = generator.pregenerate(5)
    assert len(pregenerated) == 5
    for hb in pregenerated:
        assert hb.verify() == True
    print(f"✓ Pre-generated {len(pregenerated)} heartbeats")
    
    # Test cache
    cache = HeartbeatCache(config)
    cache.add(hb)
    latest = cache.get_latest()
    assert latest is not None
    print("✓ Cache stores and retrieves heartbeats")
    
    print("\nAll heartbeat tests passed! ✓")
