"""
LEASH authentication wrapper for agent tools.

Provides ``LEASHAuthContext`` — a helper that sets up parent/child keys,
heartbeat generation, and exposes an ``auth_fn(agent_id, tool_name) -> bool``
callback suitable for ``AgentToolkit``.

Usage::

    ctx = LEASHAuthContext(config)
    ctx.register_parent("orchestrator")
    child_info = ctx.register_child("orchestrator", "worker-1", ["read_file", "review_code"])

    toolkit = AgentToolkit(
        ...,
        agent_id="worker-1",
        auth_fn=ctx.make_auth_fn("worker-1"),
    )

    # Revoking the parent silently stops heartbeats:
    ctx.revoke_parent("orchestrator")
    # After max_heartbeat_age, all children are denied.
"""

import sys
import os
import time
import threading
from dataclasses import dataclass, field
from typing import Optional

# Ensure leash package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from leash import (
    LeashConfig,
    AgentKeyPair,
    HeartbeatGenerator,
    HeartbeatCache,
    CredentialBuilder,
    CredentialProof,
    Verifier,
)
from leash.verification import generate_challenge


@dataclass
class _ParentState:
    keypair: AgentKeyPair
    heartbeat_gen: HeartbeatGenerator
    is_alive: bool = True
    children: list[str] = field(default_factory=list)


@dataclass
class _ChildState:
    keypair: AgentKeyPair
    credential: object  # AgentCredential
    cache: HeartbeatCache
    parent_id: str
    scopes: list[str]


class LEASHAuthContext:
    """
    Manages LEASH state for one experiment run.

    Owns parents, children, heartbeat loops, and a ``Verifier``.
    """

    def __init__(self, config: Optional[LeashConfig] = None):
        self.config = config or LeashConfig(
            heartbeat_interval_secs=5,
            max_heartbeat_age_secs=15,
        )
        self.verifier = Verifier(self.config)
        self._parents: dict[str, _ParentState] = {}
        self._children: dict[str, _ChildState] = {}
        self._hb_threads: dict[str, threading.Event] = {}

    # -- parent management --------------------------------------------------

    def register_parent(self, parent_id: str) -> AgentKeyPair:
        """Create a root agent and start its heartbeat loop."""
        kp = AgentKeyPair.generate_root(parent_id)
        hb_gen = HeartbeatGenerator(kp.heartbeat_key, self.config)
        self._parents[parent_id] = _ParentState(
            keypair=kp, heartbeat_gen=hb_gen,
        )
        self.verifier.trust_parent(parent_id, kp.heartbeat_public_key())
        self._start_heartbeat_loop(parent_id)
        return kp

    def revoke_parent(self, parent_id: str) -> None:
        """Stop heartbeat generation — children will time out."""
        if parent_id in self._parents:
            self._parents[parent_id].is_alive = False
        if parent_id in self._hb_threads:
            self._hb_threads[parent_id].set()  # signal thread to stop

    def is_parent_alive(self, parent_id: str) -> bool:
        p = self._parents.get(parent_id)
        return p.is_alive if p else False

    # -- child management ---------------------------------------------------

    def register_child(
        self, parent_id: str, child_id: str, scopes: list[str],
    ) -> dict:
        """Derive a child agent from *parent_id*."""
        parent = self._parents[parent_id]
        child_kp = parent.keypair.derive_child(child_id)
        cred = (
            CredentialBuilder()
            .with_scopes(scopes)
            .with_attribute("parent", parent_id)
            .build(child_kp, parent.keypair.heartbeat_public_key())
        )
        cache = HeartbeatCache(self.config)
        # Seed with a fresh heartbeat
        cache.add(parent.heartbeat_gen.generate())

        self._children[child_id] = _ChildState(
            keypair=child_kp,
            credential=cred,
            cache=cache,
            parent_id=parent_id,
            scopes=scopes,
        )
        parent.children.append(child_id)
        return {"child_id": child_id, "scopes": scopes}

    # -- authentication -----------------------------------------------------

    def authenticate(self, child_id: str) -> bool:
        """
        Full LEASH authentication flow for *child_id*.

        Returns ``True`` iff the child holds a fresh parent heartbeat and
        the proof passes verification.
        """
        child = self._children.get(child_id)
        if child is None:
            return False

        heartbeat = child.cache.get_latest()
        if heartbeat is None:
            return False

        challenge = generate_challenge("tool_call", child_id)
        proof = CredentialProof.create(
            child.credential, heartbeat, challenge, child.keypair.identity_key,
        )
        result = self.verifier.verify(proof, challenge)
        return result.valid

    def make_auth_fn(self, child_id: str):
        """
        Return a callback ``(agent_id, tool_name) -> bool`` for AgentToolkit.
        """
        def _auth_fn(agent_id: str, tool_name: str) -> bool:
            return self.authenticate(child_id)
        return _auth_fn

    # -- heartbeat loop -----------------------------------------------------

    def _start_heartbeat_loop(self, parent_id: str) -> None:
        stop_event = threading.Event()
        self._hb_threads[parent_id] = stop_event

        def _loop():
            parent = self._parents[parent_id]
            while not stop_event.is_set():
                if parent.is_alive:
                    hb = parent.heartbeat_gen.generate()
                    for cid in parent.children:
                        c = self._children.get(cid)
                        if c is not None:
                            c.cache.add(hb)
                stop_event.wait(self.config.heartbeat_interval_secs)

        t = threading.Thread(target=_loop, daemon=True, name=f"hb-{parent_id}")
        t.start()

    # -- teardown -----------------------------------------------------------

    def shutdown(self) -> None:
        """Stop all heartbeat threads."""
        for ev in self._hb_threads.values():
            ev.set()
