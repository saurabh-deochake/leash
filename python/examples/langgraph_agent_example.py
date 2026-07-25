#!/usr/bin/env python3
"""
LangGraph + LEASH Integration Example

This example shows how to integrate LEASH with LangGraph for building
AI agent swarms where:
1. A supervisor agent spawns worker agents
2. Each worker gets LEASH credentials
3. Workers must authenticate before calling tools/APIs
4. Revoking the supervisor revokes all workers

Requirements:
    pip install langchain langgraph langchain-openai

Run with: python examples/langgraph_agent_example.py
"""

import os
import time
import asyncio
from typing import Annotated, TypedDict, Literal, Optional
from dataclasses import dataclass, field

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

# Check if LangGraph is available
try:
    from langgraph.graph import StateGraph, END
    from langgraph.prebuilt import ToolNode
    from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
    from langchain_core.tools import tool
    LANGGRAPH_AVAILABLE = True
except ImportError:
    LANGGRAPH_AVAILABLE = False
    print("⚠️  LangGraph not installed. Install with: pip install langchain langgraph")
    print("   Running in simulation mode instead.\n")


# =============================================================================
# LEASH CREDENTIAL MANAGER
# =============================================================================

class LEASHCredentialManager:
    """
    Manages LEASH credentials for LangGraph agents.
    
    This is the bridge between LEASH and your AI agent framework.
    """
    
    def __init__(self, config: Optional[LeashConfig] = None):
        self.config = config or LeashConfig(
            heartbeat_interval_secs=10,
            max_heartbeat_age_secs=30
        )
        self.supervisors: dict[str, dict] = {}  # supervisor_id -> {keypair, heartbeat_gen}
        self.workers: dict[str, dict] = {}      # worker_id -> {keypair, credential, cache, supervisor_id}
        self.verifier = Verifier(self.config)
        self._heartbeat_tasks: dict[str, bool] = {}  # supervisor_id -> is_running
    
    def register_supervisor(self, supervisor_id: str) -> dict:
        """
        Register a supervisor (parent) agent.
        
        Returns the supervisor's public key info for verification setup.
        """
        keypair = AgentKeyPair.generate_root(supervisor_id)
        heartbeat_gen = HeartbeatGenerator(keypair.heartbeat_key, self.config)
        
        self.supervisors[supervisor_id] = {
            "keypair": keypair,
            "heartbeat_gen": heartbeat_gen,
            "workers": [],
            "is_alive": True,
        }
        
        # Register as trusted for verification
        self.verifier.trust_parent(supervisor_id, keypair.heartbeat_public_key())
        
        print(f"[LEASH] Registered supervisor: {supervisor_id}")
        return {
            "supervisor_id": supervisor_id,
            "heartbeat_pubkey": keypair.heartbeat_public_key_bytes().hex()
        }
    
    def create_worker_credential(
        self,
        supervisor_id: str,
        worker_id: str,
        scopes: list[str]
    ) -> dict:
        """
        Create credentials for a worker agent.
        
        The worker's keys are derived from the supervisor's keys.
        """
        if supervisor_id not in self.supervisors:
            raise ValueError(f"Unknown supervisor: {supervisor_id}")
        
        supervisor = self.supervisors[supervisor_id]
        
        # Derive worker keypair from supervisor
        worker_keypair = supervisor["keypair"].derive_child(worker_id)
        
        # Create credential bound to supervisor's heartbeat
        credential = (CredentialBuilder()
            .with_scopes(scopes)
            .with_attribute("supervisor", supervisor_id)
            .build(worker_keypair, supervisor["keypair"].heartbeat_public_key()))
        
        # Create heartbeat cache for worker
        cache = HeartbeatCache(self.config)
        
        # Give initial heartbeat
        heartbeat = supervisor["heartbeat_gen"].generate()
        cache.add(heartbeat)
        
        self.workers[worker_id] = {
            "keypair": worker_keypair,
            "credential": credential,
            "cache": cache,
            "supervisor_id": supervisor_id,
        }
        
        supervisor["workers"].append(worker_id)
        
        print(f"[LEASH] Created worker: {worker_id} under supervisor: {supervisor_id}")
        print(f"       Scopes: {scopes}")
        
        return {
            "worker_id": worker_id,
            "supervisor_id": supervisor_id,
            "scopes": scopes,
        }
    
    def broadcast_heartbeats(self, supervisor_id: str) -> int:
        """
        Broadcast heartbeat from supervisor to all workers.
        
        Returns number of workers that received the heartbeat.
        """
        if supervisor_id not in self.supervisors:
            return 0
        
        supervisor = self.supervisors[supervisor_id]
        if not supervisor["is_alive"]:
            return 0
        
        heartbeat = supervisor["heartbeat_gen"].generate()
        count = 0
        
        for worker_id in supervisor["workers"]:
            if worker_id in self.workers:
                self.workers[worker_id]["cache"].add(heartbeat)
                count += 1
        
        return count
    
    def start_heartbeat_loop(self, supervisor_id: str):
        """Start automatic heartbeat broadcasting for a supervisor."""
        self._heartbeat_tasks[supervisor_id] = True
        
        def loop():
            while self._heartbeat_tasks.get(supervisor_id, False):
                if supervisor_id in self.supervisors and self.supervisors[supervisor_id]["is_alive"]:
                    self.broadcast_heartbeats(supervisor_id)
                time.sleep(self.config.heartbeat_interval_secs)
        
        import threading
        thread = threading.Thread(target=loop, daemon=True)
        thread.start()
        print(f"[LEASH] Started heartbeat loop for {supervisor_id}")
    
    def authenticate_worker(self, worker_id: str, resource: str = "") -> dict:
        """
        Authenticate a worker agent.
        
        Returns auth result with token if successful.
        """
        if worker_id not in self.workers:
            return {"success": False, "error": f"Unknown worker: {worker_id}"}
        
        worker = self.workers[worker_id]
        
        # Get latest heartbeat
        heartbeat = worker["cache"].get_latest()
        if heartbeat is None:
            return {
                "success": False,
                "error": "No valid heartbeat - supervisor may be revoked",
                "worker_id": worker_id,
            }
        
        # Create challenge and proof
        challenge = generate_challenge(resource, "access")
        proof = CredentialProof.create(
            worker["credential"],
            heartbeat,
            challenge,
            worker["keypair"].identity_key
        )
        
        # Verify
        result = self.verifier.verify(proof, challenge)
        
        if result.valid:
            return {
                "success": True,
                "worker_id": worker_id,
                "scopes": result.scopes,
                "token": f"leash_token_{worker_id}_{int(time.time())}",
                "heartbeat_epoch": result.heartbeat_epoch,
            }
        else:
            return {
                "success": False,
                "error": result.error,
                "worker_id": worker_id,
            }
    
    def revoke_supervisor(self, supervisor_id: str):
        """
        Revoke a supervisor and all its workers.
        
        This simply stops heartbeat generation - workers will lose
        authentication ability after max_heartbeat_age.
        """
        if supervisor_id in self.supervisors:
            self.supervisors[supervisor_id]["is_alive"] = False
            self._heartbeat_tasks[supervisor_id] = False
            print(f"[LEASH] ⚠️  REVOKED supervisor: {supervisor_id}")
            print(f"       Workers will lose access in {self.config.max_heartbeat_age_secs}s")


# =============================================================================
# LANGGRAPH INTEGRATION
# =============================================================================

if LANGGRAPH_AVAILABLE:
    
    # Global credential manager (in production, use dependency injection)
    credential_manager = LEASHCredentialManager()
    
    # State for our agent graph
    class AgentState(TypedDict):
        messages: list
        current_worker: str
        auth_status: dict
        task_result: Optional[str]
    
    # Define tools that require authentication
    @tool
    def read_sensor_data(sensor_id: str) -> str:
        """Read data from a sensor. Requires authentication."""
        # This would be called by a worker agent
        return f"Sensor {sensor_id} reading: 23.5°C, humidity: 45%"
    
    @tool
    def update_database(record_id: str, value: str) -> str:
        """Update a database record. Requires authentication."""
        return f"Updated record {record_id} with value: {value}"
    
    @tool
    def send_alert(message: str) -> str:
        """Send an alert notification. Requires authentication."""
        return f"Alert sent: {message}"
    
    def create_authenticated_tool_wrapper(tool_func, worker_id: str):
        """
        Wrap a tool to require LEASH authentication before execution.
        
        This is the key integration point - every tool call checks credentials.
        """
        original_func = tool_func.func
        
        def authenticated_wrapper(*args, **kwargs):
            # Authenticate before tool execution
            auth_result = credential_manager.authenticate_worker(worker_id)
            
            if not auth_result["success"]:
                return f"❌ Authentication failed: {auth_result.get('error', 'Unknown error')}"
            
            # Execute the actual tool
            result = original_func(*args, **kwargs)
            return f"✓ [Authenticated as {worker_id}] {result}"
        
        # Create new tool with same metadata but authenticated function
        from langchain_core.tools import StructuredTool
        return StructuredTool(
            name=tool_func.name,
            description=tool_func.description,
            func=authenticated_wrapper,
            args_schema=tool_func.args_schema,
        )
    
    def create_worker_agent(
        supervisor_id: str,
        worker_id: str,
        tools: list,
        scopes: list[str]
    ):
        """
        Create a LangGraph worker agent with LEASH credentials.
        
        Args:
            supervisor_id: The parent supervisor's ID
            worker_id: Unique ID for this worker
            tools: List of tools this worker can use
            scopes: Permission scopes for this worker
        
        Returns:
            A configured StateGraph for the worker
        """
        # Create LEASH credentials
        credential_manager.create_worker_credential(
            supervisor_id,
            worker_id,
            scopes
        )
        
        # Wrap tools with authentication
        authenticated_tools = [
            create_authenticated_tool_wrapper(t, worker_id)
            for t in tools
        ]
        
        # Create the agent graph
        graph = StateGraph(AgentState)
        
        def authenticate_node(state: AgentState) -> AgentState:
            """Node that authenticates the worker."""
            auth_result = credential_manager.authenticate_worker(worker_id)
            return {
                **state,
                "current_worker": worker_id,
                "auth_status": auth_result,
            }
        
        def execute_task_node(state: AgentState) -> AgentState:
            """Node that executes the task if authenticated."""
            if not state["auth_status"].get("success"):
                return {
                    **state,
                    "task_result": f"Cannot execute: {state['auth_status'].get('error')}",
                }
            
            # In a real implementation, this would use an LLM to decide
            # which tool to call based on the messages
            return {
                **state,
                "task_result": "Task executed successfully",
            }
        
        # Add nodes
        graph.add_node("authenticate", authenticate_node)
        graph.add_node("execute", execute_task_node)
        
        # Add edges
        graph.set_entry_point("authenticate")
        graph.add_edge("authenticate", "execute")
        graph.add_edge("execute", END)
        
        return graph.compile()


# =============================================================================
# SIMULATION (works without LangGraph installed)
# =============================================================================

def run_simulation_without_langgraph():
    """
    Simulation that demonstrates the concepts without requiring LangGraph.
    """
    print("=" * 70)
    print("LEASH + AI AGENT SIMULATION")
    print("(Simulating LangGraph-style agent workflow)")
    print("=" * 70)
    
    # Create credential manager
    cred_manager = LEASHCredentialManager(LeashConfig(
        heartbeat_interval_secs=2,
        max_heartbeat_age_secs=6
    ))
    
    # Phase 1: Setup supervisor
    print("\n" + "-" * 50)
    print("PHASE 1: Register Supervisor Agent")
    print("-" * 50)
    
    supervisor_info = cred_manager.register_supervisor("supervisor-agent")
    cred_manager.start_heartbeat_loop("supervisor-agent")
    
    # Phase 2: Create worker agents
    print("\n" + "-" * 50)
    print("PHASE 2: Spawn Worker Agents")
    print("-" * 50)
    
    workers = [
        cred_manager.create_worker_credential(
            "supervisor-agent",
            "sensor-reader",
            ["read", "sensors"]
        ),
        cred_manager.create_worker_credential(
            "supervisor-agent",
            "data-writer",
            ["read", "write", "database"]
        ),
        cred_manager.create_worker_credential(
            "supervisor-agent",
            "alert-sender",
            ["send", "alerts"]
        ),
    ]
    
    time.sleep(0.5)  # Let heartbeat propagate
    
    # Phase 3: Workers perform tasks
    print("\n" + "-" * 50)
    print("PHASE 3: Workers Perform Tasks (Authenticated)")
    print("-" * 50)
    
    for _ in range(3):
        print("\n--- Task Round ---")
        for worker in workers:
            worker_id = worker["worker_id"]
            auth = cred_manager.authenticate_worker(worker_id, "api/resource")
            
            if auth["success"]:
                print(f"✓ {worker_id}: Authenticated, executing task...")
                print(f"  Token: {auth['token'][:30]}...")
            else:
                print(f"✗ {worker_id}: {auth['error']}")
        
        time.sleep(1)
    
    # Phase 4: Revoke supervisor
    print("\n" + "-" * 50)
    print("PHASE 4: Revoke Supervisor")
    print("-" * 50)
    
    cred_manager.revoke_supervisor("supervisor-agent")
    
    # Phase 5: Watch workers lose access
    print("\n" + "-" * 50)
    print("PHASE 5: Workers Lose Access (Zombie Window)")
    print("-" * 50)
    
    for i in range(8):
        print(f"\n--- {i+1}s after revocation ---")
        
        for worker in workers:
            worker_id = worker["worker_id"]
            auth = cred_manager.authenticate_worker(worker_id)
            
            if auth["success"]:
                print(f"⚠️  {worker_id}: Still authenticated (zombie)")
            else:
                print(f"✓ {worker_id}: Access DENIED")
        
        time.sleep(1)
    
    print("\n" + "=" * 70)
    print("SIMULATION COMPLETE")
    print("=" * 70)
    print("""
Key Points for LangGraph Integration:

1. Create an LEASHCredentialManager instance
2. Register your supervisor/orchestrator agent
3. When spawning worker agents, create credentials for them
4. Start the heartbeat loop for the supervisor
5. Wrap your tools with authentication checks
6. To revoke all workers, just revoke the supervisor

Example LangGraph integration:

    from langgraph.graph import StateGraph
    
    # Setup
    cred_manager = LEASHCredentialManager()
    cred_manager.register_supervisor("orchestrator")
    cred_manager.start_heartbeat_loop("orchestrator")
    
    # Create worker with credentials
    cred_manager.create_worker_credential(
        "orchestrator",
        "worker-1",
        ["read", "write"]
    )
    
    # In your tool/node, authenticate first
    def my_tool_node(state):
        auth = cred_manager.authenticate_worker("worker-1")
        if not auth["success"]:
            return {"error": auth["error"]}
        # ... execute tool ...
""")


def run_with_langgraph():
    """
    Full LangGraph integration example.
    """
    print("=" * 70)
    print("LANGGRAPH + LEASH INTEGRATION")
    print("=" * 70)
    
    # Register supervisor
    credential_manager.register_supervisor("orchestrator")
    credential_manager.start_heartbeat_loop("orchestrator")
    
    # Create worker agents
    tools = [read_sensor_data, update_database, send_alert]
    
    worker1_graph = create_worker_agent(
        "orchestrator",
        "sensor-worker",
        [read_sensor_data],
        ["read", "sensors"]
    )
    
    worker2_graph = create_worker_agent(
        "orchestrator",
        "database-worker",
        [update_database],
        ["read", "write", "database"]
    )
    
    time.sleep(0.5)
    
    # Run workers
    print("\n" + "-" * 50)
    print("Running Worker Agents")
    print("-" * 50)
    
    initial_state = {
        "messages": [HumanMessage(content="Read sensor data")],
        "current_worker": "",
        "auth_status": {},
        "task_result": None,
    }
    
    for i in range(3):
        print(f"\n--- Round {i+1} ---")
        
        result1 = worker1_graph.invoke(initial_state)
        print(f"Sensor Worker: {result1['auth_status']}")
        
        result2 = worker2_graph.invoke(initial_state)
        print(f"Database Worker: {result2['auth_status']}")
        
        time.sleep(1)
    
    # Revoke and test
    print("\n" + "-" * 50)
    print("Revoking Orchestrator")
    print("-" * 50)
    
    credential_manager.revoke_supervisor("orchestrator")
    
    for i in range(5):
        print(f"\n--- {i+1}s after revocation ---")
        result1 = worker1_graph.invoke(initial_state)
        status = "✓ Authenticated" if result1['auth_status'].get('success') else "✗ Denied"
        print(f"Sensor Worker: {status}")
        time.sleep(1)


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    if LANGGRAPH_AVAILABLE:
        print("LangGraph detected! Running full integration example.\n")
        run_with_langgraph()
    else:
        print("Running simulation (install langgraph for full example).\n")
        run_simulation_without_langgraph()
