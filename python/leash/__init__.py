"""
Liveness-Enforced Authorization for Swarm Hierarchies (LEASH)

A cryptographic credential architecture for AI agent swarms
that enables immediate revocation without network connectivity.
"""

from .keys import AgentKeyPair, KeyHierarchy
from .heartbeat import Heartbeat, HeartbeatGenerator, HeartbeatCache
from .credentials import AgentCredential, CredentialProof, CredentialBuilder
from .verification import Verifier, VerificationResult
from .config import LeashConfig

__version__ = "0.1.0"
__all__ = [
    "AgentKeyPair",
    "KeyHierarchy", 
    "Heartbeat",
    "HeartbeatGenerator",
    "HeartbeatCache",
    "AgentCredential",
    "CredentialProof",
    "CredentialBuilder",
    "Verifier",
    "VerificationResult",
    "LeashConfig",
]
