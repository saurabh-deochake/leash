#!/usr/bin/env python3
"""
AI Agent Example with LEASH Integration

This example shows how to integrate LEASH with AI agents where:
1. A parent "Coordinator" agent spawns child "Worker" agents
2. Each worker gets credentials derived from the parent
3. Workers call an IAM service to access resources
4. When parent is revoked, all workers lose access

This is a realistic simulation of how you'd use LEASH in production.

Run with: python examples/ai_agent_example.py
"""

import time
import threading
import random
from dataclasses import dataclass, field
from typing import Optional, Callable
from enum import Enum

# Add parent directory to path for imports
import sys
sys.path.insert(0, '..')

from leash import (
    LeashConfig,
    AgentKeyPair,
    Heartbeat,
    HeartbeatGenerator,
    HeartbeatCache,
    CredentialBuilder,
    CredentialProof,
    Verifier,
)
from leash.verification import generate_challenge


# =============================================================================
# SIMULATED IAM SERVICE
# =============================================================================

class IAMService:
    """
    Simulated IAM (Identity and Access Management) Service.
    
    In a real system, this would be something like:
    - AWS IAM
    - Azure Active Directory
    - Google Cloud IAM
    - Okta
    - Your own OAuth server
    
    This IAM service uses LEASH for credential verification.
    """
    
    def __init__(self, config: LeashConfig):
        self.config = config
        self.verifier = Verifier(config)
        self.access_log: list[dict] = []
    
    def register_trusted_coordinator(self, coordinator_id: str, heartbeat_pubkey):
        """Register a coordinator (parent agent) as trusted."""
        self.verifier.trust_parent(coordinator_id, heartbeat_pubkey)
        print(f"[IAM] Registered trusted coordinator: {coordinator_id}")
    
    def authenticate(self, proof: CredentialProof, challenge: bytes) -> dict:
        """
        Authenticate an agent using LEASH credentials.
        
        Returns:
            dict with 'success', 'agent_id', 'scopes', 'error'
        """
        result = self.verifier.verify(proof, challenge)
        
        log_entry = {
            "timestamp": time.time(),
            "agent_id": result.agent_id,
            "success": result.valid,
            "error": result.error,
            "heartbeat_epoch": result.heartbeat_epoch,
        }
        self.access_log.append(log_entry)
        
        if result.valid:
            return {
                "success": True,
                "agent_id": result.agent_id,
                "scopes": result.scopes,
                "token": f"access_token_{result.agent_id}_{int(time.time())}",
            }
        else:
            return {
                "success": False,
                "agent_id": result.agent_id,
                "error": result.error,
            }
    
    def get_access_log(self) -> list[dict]:
        """Get the access log for auditing."""
        return self.access_log


# =============================================================================
# SIMULATED RESOURCE SERVICE
# =============================================================================

class ResourceService:
    """
    Simulated resource service that agents want to access.
    
    Could represent:
    - A database
    - An API endpoint
    - A file storage system
    - Any protected resource
    """
    
    def __init__(self, name: str):
        self.name = name
        self.data = {
            "sensor_data": [23.5, 24.1, 22.8, 25.0],
            "status": "operational",
            "last_update": time.time(),
        }
    
    def read(self, token: str, resource: str) -> dict:
        """Read a resource (requires valid token)."""
        if not token.startswith("access_token_"):
            return {"error": "Invalid token"}
        
        if resource in self.data:
            return {"success": True, "data": self.data[resource]}
        return {"error": f"Resource '{resource}' not found"}
    
    def write(self, token: str, resource: str, value) -> dict:
        """Write to a resource (requires valid token)."""
        if not token.startswith("access_token_"):
            return {"error": "Invalid token"}
        
        self.data[resource] = value
        self.data["last_update"] = time.time()
        return {"success": True, "message": f"Updated {resource}"}


# =============================================================================
# AI AGENTS
# =============================================================================

class AgentStatus(Enum):
    INITIALIZING = "initializing"
    RUNNING = "running"
    STOPPED = "stopped"
    REVOKED = "revoked"


@dataclass
class WorkerAgent:
    """
    A child AI agent that performs tasks.
    
    In a real system, this could be:
    - A drone performing surveillance
    - A data processing agent
    - A customer service bot
    - Any autonomous AI worker
    """
    agent_id: str
    keypair: AgentKeyPair
    credential: object  # AgentCredential
    heartbeat_cache: HeartbeatCache
    task: str
    status: AgentStatus = AgentStatus.INITIALIZING
    results: list = field(default_factory=list)
    
    def receive_heartbeat(self, heartbeat: Heartbeat) -> None:
        """Receive a heartbeat from the parent coordinator."""
        self.heartbeat_cache.add(heartbeat)
    
    def can_authenticate(self) -> bool:
        """Check if we have a valid heartbeat to authenticate."""
        return self.heartbeat_cache.get_latest() is not None
    
    def create_auth_proof(self, challenge: bytes) -> Optional[CredentialProof]:
        """Create an authentication proof for IAM."""
        heartbeat = self.heartbeat_cache.get_latest()
        if heartbeat is None:
            return None
        
        return CredentialProof.create(
            self.credential,
            heartbeat,
            challenge,
            self.keypair.identity_key
        )
    
    def perform_task(self, iam: IAMService, resource: ResourceService) -> dict:
        """
        Perform the agent's task by:
        1. Getting a challenge from IAM
        2. Creating an auth proof with current heartbeat
        3. Authenticating with IAM
        4. Accessing the resource
        """
        # Step 1: Get challenge (in real system, IAM would provide this)
        challenge = generate_challenge(resource.name, self.task)
        
        # Step 2: Create auth proof
        proof = self.create_auth_proof(challenge)
        if proof is None:
            return {
                "success": False,
                "error": "No valid heartbeat - cannot authenticate",
                "agent_id": self.agent_id,
            }
        
        # Step 3: Authenticate with IAM
        auth_result = iam.authenticate(proof, challenge)
        if not auth_result["success"]:
            self.status = AgentStatus.REVOKED
            return {
                "success": False,
                "error": f"Authentication failed: {auth_result.get('error')}",
                "agent_id": self.agent_id,
            }
        
        # Step 4: Access resource
        token = auth_result["token"]
        
        if self.task == "read_sensors":
            data = resource.read(token, "sensor_data")
        elif self.task == "check_status":
            data = resource.read(token, "status")
        elif self.task == "update_status":
            data = resource.write(token, "status", "updated_by_" + self.agent_id)
        else:
            data = {"error": f"Unknown task: {self.task}"}
        
        result = {
            "success": True,
            "agent_id": self.agent_id,
            "task": self.task,
            "data": data,
            "heartbeat_epoch": proof.heartbeat_epoch(),
        }
        self.results.append(result)
        return result


class CoordinatorAgent:
    """
    A parent AI agent that coordinates child workers.
    
    In a real system, this could be:
    - A mission control system
    - A task orchestrator
    - A swarm coordinator
    - Any parent agent that delegates to children
    """
    
    def __init__(self, agent_id: str, config: LeashConfig):
        self.agent_id = agent_id
        self.config = config
        self.keypair = AgentKeyPair.generate_root(agent_id)
        self.heartbeat_gen = HeartbeatGenerator(self.keypair.heartbeat_key, config)
        self.workers: dict[str, WorkerAgent] = {}
        self.is_alive = True
        self._heartbeat_thread: Optional[threading.Thread] = None
    
    def spawn_worker(self, worker_id: str, task: str, scopes: list[str]) -> WorkerAgent:
        """
        Spawn a new worker agent with derived credentials.
        
        This is the key LEASH operation:
        - Child key is derived from parent
        - Credential is bound to parent's heartbeat key
        - Child can only authenticate with fresh parent heartbeats
        """
        # Derive child keypair
        child_keypair = self.keypair.derive_child(worker_id)
        
        # Create credential with heartbeat binding
        credential = (CredentialBuilder()
            .with_scopes(scopes)
            .with_attribute("spawned_by", self.agent_id)
            .with_attribute("task", task)
            .build(child_keypair, self.keypair.heartbeat_public_key()))
        
        # Create worker
        worker = WorkerAgent(
            agent_id=worker_id,
            keypair=child_keypair,
            credential=credential,
            heartbeat_cache=HeartbeatCache(self.config),
            task=task,
            status=AgentStatus.RUNNING,
        )
        
        # Give initial heartbeat
        heartbeat = self.heartbeat_gen.generate()
        worker.receive_heartbeat(heartbeat)
        
        self.workers[worker_id] = worker
        print(f"[Coordinator] Spawned worker: {worker_id} with task: {task}")
        
        return worker
    
    def broadcast_heartbeat(self) -> None:
        """Broadcast heartbeat to all workers."""
        if not self.is_alive:
            return
        
        heartbeat = self.heartbeat_gen.generate()
        for worker in self.workers.values():
            worker.receive_heartbeat(heartbeat)
    
    def start_heartbeat_loop(self) -> None:
        """Start background heartbeat generation."""
        def loop():
            while self.is_alive:
                self.broadcast_heartbeat()
                time.sleep(self.config.heartbeat_interval_secs)
        
        self._heartbeat_thread = threading.Thread(target=loop, daemon=True)
        self._heartbeat_thread.start()
        print(f"[Coordinator] Started heartbeat loop (interval: {self.config.heartbeat_interval_secs}s)")
    
    def terminate(self) -> None:
        """
        Terminate the coordinator.
        
        This simulates:
        - Coordinator being compromised
        - Coordinator being intentionally shut down
        - Coordinator crashing
        
        After termination, NO MORE HEARTBEATS are generated.
        Workers will lose authentication ability after max_heartbeat_age.
        """
        self.is_alive = False
        print(f"[Coordinator] ⚠️  TERMINATED - No more heartbeats will be generated")


# =============================================================================
# MAIN SIMULATION
# =============================================================================

def run_simulation():
    """
    Run a complete simulation showing:
    1. Coordinator spawns workers
    2. Workers authenticate and access resources
    3. Coordinator is terminated (revoked)
    4. Workers can no longer authenticate
    """
    
    print("=" * 70)
    print("AI AGENT SIMULATION WITH LEASH")
    print("=" * 70)
    
    # Configuration - short intervals for demo
    config = LeashConfig(
        heartbeat_interval_secs=2,  # Heartbeat every 2 seconds
        max_heartbeat_age_secs=6,   # Heartbeats valid for 6 seconds
    )
    
    print(f"\nConfiguration:")
    print(f"  Heartbeat interval: {config.heartbeat_interval_secs}s")
    print(f"  Max heartbeat age: {config.max_heartbeat_age_secs}s")
    print(f"  (In production, use 10s interval, 30s max age)")
    
    # Create services
    iam = IAMService(config)
    resource = ResourceService("sensor-hub")
    
    # Create coordinator
    print("\n" + "-" * 50)
    print("PHASE 1: Setup")
    print("-" * 50)
    
    coordinator = CoordinatorAgent("mission-control", config)
    iam.register_trusted_coordinator(
        coordinator.agent_id,
        coordinator.keypair.heartbeat_public_key()
    )
    
    # Spawn workers
    worker1 = coordinator.spawn_worker(
        "drone-alpha",
        task="read_sensors",
        scopes=["read", "sensors"]
    )
    
    worker2 = coordinator.spawn_worker(
        "drone-beta",
        task="check_status",
        scopes=["read", "status"]
    )
    
    worker3 = coordinator.spawn_worker(
        "drone-gamma",
        task="update_status",
        scopes=["read", "write", "status"]
    )
    
    # Start heartbeat loop
    coordinator.start_heartbeat_loop()
    time.sleep(0.5)  # Let first heartbeat propagate
    
    # Phase 2: Normal operation
    print("\n" + "-" * 50)
    print("PHASE 2: Normal Operation (workers can authenticate)")
    print("-" * 50)
    
    for i in range(3):
        print(f"\n--- Round {i+1} ---")
        for worker in [worker1, worker2, worker3]:
            result = worker.perform_task(iam, resource)
            if result["success"]:
                print(f"✓ {worker.agent_id}: {result['task']} succeeded")
            else:
                print(f"✗ {worker.agent_id}: {result['error']}")
        time.sleep(1)
    
    # Phase 3: Terminate coordinator (simulate compromise/revocation)
    print("\n" + "-" * 50)
    print("PHASE 3: Coordinator Terminated (simulating revocation)")
    print("-" * 50)
    
    coordinator.terminate()
    
    # Phase 4: Watch workers lose access
    print("\n" + "-" * 50)
    print("PHASE 4: Zombie Window (workers still have stale heartbeats)")
    print("-" * 50)
    
    zombie_count = 0
    revoked_count = 0
    
    for i in range(8):
        print(f"\n--- {i+1} seconds after termination ---")
        
        for worker in [worker1, worker2, worker3]:
            result = worker.perform_task(iam, resource)
            if result["success"]:
                print(f"⚠️  {worker.agent_id}: Still authenticated (ZOMBIE)")
                zombie_count += 1
            else:
                print(f"✓ {worker.agent_id}: Access DENIED - {result['error'][:50]}...")
                revoked_count += 1
        
        time.sleep(1)
    
    # Summary
    print("\n" + "=" * 70)
    print("SIMULATION COMPLETE")
    print("=" * 70)
    
    print(f"""
Results:
  - Zombie authentications: {zombie_count}
  - Denied after revocation: {revoked_count}
  - Zombie window: ~{config.max_heartbeat_age_secs} seconds

Compare to traditional OAuth:
  - OAuth zombie window: 3600 seconds (1 hour)
  - LEASH zombie window: {config.max_heartbeat_age_secs} seconds
  - Improvement: {3600 // config.max_heartbeat_age_secs}x faster revocation

Key Insight:
  After the coordinator was terminated, workers could NOT get new heartbeats.
  Once their cached heartbeats expired, they could no longer authenticate.
  This happened WITHOUT any network call to revoke them!
""")
    
    # Show access log
    print("\nIAM Access Log (last 10 entries):")
    print("-" * 50)
    for entry in iam.get_access_log()[-10:]:
        status = "✓" if entry["success"] else "✗"
        error = f" ({entry['error'][:30]}...)" if entry.get("error") else ""
        print(f"  {status} {entry['agent_id']}: epoch={entry['heartbeat_epoch']}{error}")


if __name__ == "__main__":
    run_simulation()
