"""
Configuration for LEASH system.
"""

from dataclasses import dataclass


@dataclass
class LeashConfig:
    """Configuration parameters for LEASH system."""
    
    # Heartbeat interval in seconds (how often parent generates heartbeats)
    heartbeat_interval_secs: int = 10
    
    # Maximum acceptable heartbeat age in seconds (zombie window)
    max_heartbeat_age_secs: int = 30
    
    # Key derivation path prefix (BIP-32 style)
    derivation_prefix: str = "m/44'/0'/0'"

    # Monotonic sequence number mode (additive — does not affect clock-based freshness)
    use_sequence_numbers: bool = False

    # Maximum allowed gap between consecutive sequence numbers (staleness bound k).
    # Verification rejects if seq - last_seen_seq > max_sequence_gap.
    # Only used when use_sequence_numbers is True.
    max_sequence_gap: int = 3

    def max_age_epochs(self) -> int:
        """Calculate maximum age in epochs."""
        return self.max_heartbeat_age_secs // self.heartbeat_interval_secs
