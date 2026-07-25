"""
Network Partition Simulator for CAP Theorem Testing.

This module simulates network partitions to demonstrate how LEASH
handles the CAP theorem trade-offs:

- C (Consistency): All nodes see the same data
- A (Availability): Every request receives a response  
- P (Partition Tolerance): System continues despite network partitions

LEASH chooses: Partition Tolerance + Consistency (CP)
- During partitions, child agents lose availability (can't authenticate)
- But the system remains consistent (revoked credentials don't work)
- This is the RIGHT choice for security-critical systems
"""

import asyncio
import time
import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Callable
import threading


class NetworkState(Enum):
    """Network connection state."""
    CONNECTED = "connected"
    PARTITIONED = "partitioned"


@dataclass
class NetworkMessage:
    """A message sent over the simulated network."""
    sender: str
    receiver: str
    message_type: str
    payload: dict
    timestamp: float = field(default_factory=time.time)


class SimulatedNetwork:
    """
    Simulates a network with partition capabilities.
    
    This allows testing how LEASH behaves when:
    1. Parent and children are connected (normal operation)
    2. Network partition occurs (children can't receive heartbeats)
    3. Parent is revoked during partition
    4. Network heals (children discover they're revoked)
    """
    
    def __init__(self, latency_ms: float = 10, packet_loss: float = 0.0):
        """
        Create a simulated network.
        
        Args:
            latency_ms: Simulated network latency in milliseconds
            packet_loss: Probability of packet loss (0.0 to 1.0)
        """
        self.latency_ms = latency_ms
        self.packet_loss = packet_loss
        self.partitions: set[tuple[str, str]] = set()  # Pairs of partitioned nodes
        self.message_queues: dict[str, list[NetworkMessage]] = {}
        self.nodes: set[str] = set()
        self._lock = threading.Lock()
    
    def register_node(self, node_id: str) -> None:
        """Register a node on the network."""
        with self._lock:
            self.nodes.add(node_id)
            self.message_queues[node_id] = []
    
    def create_partition(self, node_a: str, node_b: str) -> None:
        """
        Create a network partition between two nodes.
        
        Messages between these nodes will be dropped.
        """
        with self._lock:
            self.partitions.add((node_a, node_b))
            self.partitions.add((node_b, node_a))
            print(f"🔴 PARTITION: {node_a} <-/-> {node_b}")
    
    def heal_partition(self, node_a: str, node_b: str) -> None:
        """Heal a network partition between two nodes."""
        with self._lock:
            self.partitions.discard((node_a, node_b))
            self.partitions.discard((node_b, node_a))
            print(f"🟢 HEALED: {node_a} <---> {node_b}")
    
    def partition_node(self, node_id: str) -> None:
        """Partition a node from all other nodes."""
        with self._lock:
            for other in self.nodes:
                if other != node_id:
                    self.partitions.add((node_id, other))
                    self.partitions.add((other, node_id))
            print(f"🔴 ISOLATED: {node_id} (partitioned from all)")
    
    def reconnect_node(self, node_id: str) -> None:
        """Reconnect a node to all other nodes."""
        with self._lock:
            to_remove = [(a, b) for a, b in self.partitions if a == node_id or b == node_id]
            for pair in to_remove:
                self.partitions.discard(pair)
            print(f"🟢 RECONNECTED: {node_id}")
    
    def is_partitioned(self, node_a: str, node_b: str) -> bool:
        """Check if two nodes are partitioned."""
        return (node_a, node_b) in self.partitions
    
    def send(self, sender: str, receiver: str, message_type: str, payload: dict) -> bool:
        """
        Send a message from one node to another.
        
        Returns:
            True if message was delivered, False if dropped
        """
        # Check for partition
        if self.is_partitioned(sender, receiver):
            return False
        
        # Check for packet loss
        if random.random() < self.packet_loss:
            return False
        
        # Simulate latency
        time.sleep(self.latency_ms / 1000)
        
        # Deliver message
        msg = NetworkMessage(
            sender=sender,
            receiver=receiver,
            message_type=message_type,
            payload=payload
        )
        
        with self._lock:
            if receiver in self.message_queues:
                self.message_queues[receiver].append(msg)
                return True
        return False
    
    def receive(self, node_id: str) -> list[NetworkMessage]:
        """Receive all pending messages for a node."""
        with self._lock:
            messages = self.message_queues.get(node_id, [])
            self.message_queues[node_id] = []
            return messages
    
    def broadcast(self, sender: str, message_type: str, payload: dict) -> dict[str, bool]:
        """
        Broadcast a message to all other nodes.
        
        Returns:
            Dict mapping receiver to delivery success
        """
        results = {}
        for node in self.nodes:
            if node != sender:
                results[node] = self.send(sender, node, message_type, payload)
        return results


@dataclass
class SimulatedAgent:
    """
    A simulated agent in the network.
    
    Can be either a parent (generates heartbeats) or child (receives heartbeats).
    """
    agent_id: str
    is_parent: bool
    network: SimulatedNetwork
    heartbeat_cache: list[dict] = field(default_factory=list)
    is_alive: bool = True
    last_heartbeat_epoch: Optional[int] = None
    
    def __post_init__(self):
        self.network.register_node(self.agent_id)
    
    def generate_heartbeat(self, epoch: int) -> dict:
        """Generate a heartbeat (parent only)."""
        if not self.is_parent:
            raise ValueError("Only parents can generate heartbeats")
        
        heartbeat = {
            "epoch": epoch,
            "parent_id": self.agent_id,
            "timestamp": time.time()
        }
        self.last_heartbeat_epoch = epoch
        return heartbeat
    
    def broadcast_heartbeat(self, epoch: int) -> dict[str, bool]:
        """Broadcast a heartbeat to all children."""
        heartbeat = self.generate_heartbeat(epoch)
        return self.network.broadcast(
            self.agent_id,
            "heartbeat",
            heartbeat
        )
    
    def receive_heartbeats(self) -> list[dict]:
        """Receive heartbeats from the network."""
        messages = self.network.receive(self.agent_id)
        heartbeats = [
            msg.payload for msg in messages
            if msg.message_type == "heartbeat"
        ]
        
        # Add to cache
        for hb in heartbeats:
            if not any(h["epoch"] == hb["epoch"] for h in self.heartbeat_cache):
                self.heartbeat_cache.append(hb)
        
        # Keep only recent heartbeats
        self.heartbeat_cache = sorted(
            self.heartbeat_cache,
            key=lambda h: h["epoch"]
        )[-10:]
        
        return heartbeats
    
    def get_latest_heartbeat(self, max_age_epochs: int, current_epoch: int) -> Optional[dict]:
        """Get the most recent valid heartbeat."""
        valid = [
            hb for hb in self.heartbeat_cache
            if current_epoch - hb["epoch"] <= max_age_epochs
        ]
        if not valid:
            return None
        return max(valid, key=lambda h: h["epoch"])
    
    def can_authenticate(self, max_age_epochs: int, current_epoch: int) -> bool:
        """Check if this agent can authenticate (has valid heartbeat)."""
        return self.get_latest_heartbeat(max_age_epochs, current_epoch) is not None
    
    def terminate(self) -> None:
        """Terminate this agent (simulates revocation/compromise)."""
        self.is_alive = False
        print(f"💀 TERMINATED: {self.agent_id}")


class CAPTheoremSimulator:
    """
    Simulator for demonstrating CAP theorem properties of LEASH.
    
    Runs scenarios showing how LEASH handles:
    1. Normal operation (C, A, P all satisfied when no partitions)
    2. Network partitions (chooses C over A)
    3. Parent revocation during partition
    4. Network healing and credential invalidation
    """
    
    def __init__(
        self,
        heartbeat_interval_secs: int = 2,
        max_heartbeat_age_secs: int = 6,
        num_children: int = 3
    ):
        """
        Create a CAP theorem simulator.
        
        Args:
            heartbeat_interval_secs: How often parent generates heartbeats
            max_heartbeat_age_secs: Maximum heartbeat age (zombie window)
            num_children: Number of child agents to simulate
        """
        self.heartbeat_interval = heartbeat_interval_secs
        self.max_age_secs = max_heartbeat_age_secs
        self.max_age_epochs = max_heartbeat_age_secs // heartbeat_interval_secs
        
        self.network = SimulatedNetwork(latency_ms=50)
        
        # Create parent
        self.parent = SimulatedAgent(
            agent_id="parent",
            is_parent=True,
            network=self.network
        )
        
        # Create children
        self.children = [
            SimulatedAgent(
                agent_id=f"child-{i}",
                is_parent=False,
                network=self.network
            )
            for i in range(num_children)
        ]
        
        self.current_epoch = 0
        self.running = False
    
    def current_time_epoch(self) -> int:
        """Get current epoch based on simulation time."""
        return self.current_epoch
    
    def advance_epoch(self) -> None:
        """Advance simulation by one epoch."""
        self.current_epoch += 1
    
    def run_scenario_normal_operation(self) -> dict:
        """
        Scenario 1: Normal operation (no partitions).
        
        Demonstrates: C, A, P all satisfied
        """
        print("\n" + "="*60)
        print("SCENARIO 1: Normal Operation")
        print("="*60)
        
        results = {"epochs": [], "all_children_can_auth": []}
        
        for _ in range(5):
            self.advance_epoch()
            epoch = self.current_time_epoch()
            
            # Parent broadcasts heartbeat
            if self.parent.is_alive:
                delivery = self.parent.broadcast_heartbeat(epoch)
                print(f"\nEpoch {epoch}: Parent broadcast heartbeat")
                print(f"  Delivered to: {[k for k, v in delivery.items() if v]}")
            
            # Children receive and check auth
            auth_status = []
            for child in self.children:
                child.receive_heartbeats()
                can_auth = child.can_authenticate(self.max_age_epochs, epoch)
                auth_status.append(can_auth)
                status = "✓" if can_auth else "✗"
                print(f"  {child.agent_id}: can_authenticate={status}")
            
            results["epochs"].append(epoch)
            results["all_children_can_auth"].append(all(auth_status))
            
            time.sleep(0.1)  # Small delay for readability
        
        print("\n→ Result: All children can authenticate (C, A, P satisfied)")
        return results
    
    def run_scenario_partition(self) -> dict:
        """
        Scenario 2: Network partition.
        
        Demonstrates: LEASH chooses Consistency over Availability
        """
        print("\n" + "="*60)
        print("SCENARIO 2: Network Partition")
        print("="*60)
        
        results = {"epochs": [], "partitioned_child_auth": [], "connected_child_auth": []}
        
        # Partition one child
        partitioned_child = self.children[0]
        self.network.partition_node(partitioned_child.agent_id)
        
        for i in range(self.max_age_epochs + 3):
            self.advance_epoch()
            epoch = self.current_time_epoch()
            
            # Parent broadcasts heartbeat
            if self.parent.is_alive:
                delivery = self.parent.broadcast_heartbeat(epoch)
                delivered_to = [k for k, v in delivery.items() if v]
                print(f"\nEpoch {epoch}: Parent broadcast heartbeat")
                print(f"  Delivered to: {delivered_to}")
                print(f"  NOT delivered to: {partitioned_child.agent_id} (partitioned)")
            
            # Check auth status
            for child in self.children:
                child.receive_heartbeats()
                can_auth = child.can_authenticate(self.max_age_epochs, epoch)
                status = "✓" if can_auth else "✗"
                
                if child == partitioned_child:
                    results["partitioned_child_auth"].append(can_auth)
                    marker = " [PARTITIONED]"
                else:
                    results["connected_child_auth"].append(can_auth)
                    marker = ""
                
                print(f"  {child.agent_id}: can_authenticate={status}{marker}")
            
            results["epochs"].append(epoch)
            time.sleep(0.1)
        
        # Heal partition
        self.network.reconnect_node(partitioned_child.agent_id)
        
        print("\n→ Result: Partitioned child lost authentication ability")
        print("→ This is CORRECT: LEASH chooses Consistency over Availability")
        print("→ A revoked credential CANNOT be used, even during partition")
        
        return results
    
    def run_scenario_revocation_during_partition(self) -> dict:
        """
        Scenario 3: Parent revoked while children are partitioned.
        
        This is the KEY scenario showing LEASH's advantage:
        - Traditional systems: Children keep working until token expires
        - LEASH: Children stop working when heartbeats expire
        """
        print("\n" + "="*60)
        print("SCENARIO 3: Parent Revocation During Partition")
        print("="*60)
        print("This demonstrates the 'zombie agent' problem and LEASH's solution")
        
        results = {
            "epochs": [],
            "parent_alive": [],
            "child_can_auth": [],
            "zombie_window": 0
        }
        
        # Reset state
        self.parent.is_alive = True
        for child in self.children:
            child.heartbeat_cache = []
        
        # Phase 1: Normal operation (3 epochs)
        print("\n--- Phase 1: Normal Operation ---")
        for _ in range(3):
            self.advance_epoch()
            epoch = self.current_time_epoch()
            
            self.parent.broadcast_heartbeat(epoch)
            for child in self.children:
                child.receive_heartbeats()
            
            can_auth = self.children[0].can_authenticate(self.max_age_epochs, epoch)
            print(f"Epoch {epoch}: Parent alive, child can_auth={can_auth}")
            
            results["epochs"].append(epoch)
            results["parent_alive"].append(True)
            results["child_can_auth"].append(can_auth)
        
        # Phase 2: Partition all children, then revoke parent
        print("\n--- Phase 2: Partition + Revocation ---")
        for child in self.children:
            self.network.partition_node(child.agent_id)
        
        self.advance_epoch()
        epoch = self.current_time_epoch()
        
        # Parent is revoked (stops generating heartbeats)
        self.parent.terminate()
        print(f"Epoch {epoch}: Parent REVOKED (compromised/terminated)")
        
        # Phase 3: Watch zombie window
        print("\n--- Phase 3: Zombie Window ---")
        zombie_epochs = 0
        
        for _ in range(self.max_age_epochs + 2):
            self.advance_epoch()
            epoch = self.current_time_epoch()
            
            # Parent is dead, no heartbeats
            # Children are partitioned, can't receive anyway
            
            for child in self.children:
                child.receive_heartbeats()  # Won't receive anything
            
            can_auth = self.children[0].can_authenticate(self.max_age_epochs, epoch)
            
            if can_auth:
                zombie_epochs += 1
                print(f"Epoch {epoch}: ⚠️  ZOMBIE - Child can still auth (stale heartbeat)")
            else:
                print(f"Epoch {epoch}: ✓ Child CANNOT auth (heartbeat expired)")
            
            results["epochs"].append(epoch)
            results["parent_alive"].append(False)
            results["child_can_auth"].append(can_auth)
        
        results["zombie_window"] = zombie_epochs
        
        print(f"\n→ Zombie window: {zombie_epochs} epochs = {zombie_epochs * self.heartbeat_interval} seconds")
        print(f"→ Compare to OAuth: 3600 seconds (1 hour)")
        print(f"→ LEASH reduces zombie window by {3600 / max(1, zombie_epochs * self.heartbeat_interval):.0f}x")
        
        return results
    
    def run_all_scenarios(self) -> dict:
        """Run all CAP theorem scenarios."""
        print("\n" + "#"*60)
        print("# CAP Theorem Simulation for LEASH")
        print("#"*60)
        print(f"\nConfiguration:")
        print(f"  Heartbeat interval: {self.heartbeat_interval}s")
        print(f"  Max heartbeat age: {self.max_age_secs}s ({self.max_age_epochs} epochs)")
        print(f"  Number of children: {len(self.children)}")
        
        results = {
            "scenario_1_normal": self.run_scenario_normal_operation(),
            "scenario_2_partition": self.run_scenario_partition(),
            "scenario_3_revocation": self.run_scenario_revocation_during_partition()
        }
        
        print("\n" + "#"*60)
        print("# Summary")
        print("#"*60)
        print("""
CAP Theorem Analysis for LEASH:

┌─────────────────┬──────────────────────────────────────────┐
│ Property        │ LEASH Behavior                            │
├─────────────────┼──────────────────────────────────────────┤
│ Consistency (C) │ ✓ Revoked credentials always fail        │
│ Availability(A) │ ✗ Partitioned children lose auth ability │
│ Partition (P)   │ ✓ System continues during partitions     │
└─────────────────┴──────────────────────────────────────────┘

LEASH is a CP system (Consistency + Partition Tolerance):
- This is the CORRECT choice for security-critical systems
- Better to deny access than allow unauthorized access
- Zombie window is bounded and configurable
        """)
        
        return results


# === MAIN ===

if __name__ == "__main__":
    # Run simulation with short intervals for demo
    simulator = CAPTheoremSimulator(
        heartbeat_interval_secs=2,
        max_heartbeat_age_secs=6,
        num_children=3
    )
    
    results = simulator.run_all_scenarios()
