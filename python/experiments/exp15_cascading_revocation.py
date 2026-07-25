#!/usr/bin/env python3
"""
Experiment 15 — Cascading Revocation Under Real Hierarchy

Hypothesis
----------
Revoking the root orchestrator in a 4-level deep hierarchy (root →
coordinators → workers → sub-workers) causes ALL descendants at every
level to lose authentication within the theoretical bound, and the
denial time scales linearly with depth (O(d) signature checks per
verification).

Method
------
1.  Build a 4-level hierarchy:
        Level 0: Root orchestrator             (1 agent)
        Level 1: Team coordinators             (3 agents)
        Level 2: Workers per coordinator       (5 × 3 = 15 agents)
        Level 3: Sub-workers per worker        (2 × 15 = 30 agents)
        Total: 49 agents
2.  All agents perform real LLM-backed tool calls continuously.
3.  Kill the root orchestrator at T_kill.
4.  Measure the denial timestamp at each level to produce:
        - Per-level denial latency
        - Whether all 49 agents are denied within the bound
        - Verification latency vs. hierarchy depth

Requirements
------------
    export OPENAI_API_KEY="sk-..."
    pip install openai

Run
---
    python experiments/exp15_cascading_revocation.py [--model gpt-4o-mini-2024-07-18]
"""

import argparse
import json
import os
import sys
import time
import threading
import statistics

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PYTHON_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, PYTHON_DIR)

from leash import LeashConfig, AgentKeyPair, HeartbeatGenerator, HeartbeatCache
from leash.credentials import CredentialBuilder, CredentialProof
from leash.verification import Verifier, generate_challenge

from tools.sandbox import Sandbox
from tools.agent_tools import AgentToolkit, AuditLog

RESULTS_DIR = os.path.join(PYTHON_DIR, "results")
os.makedirs(RESULTS_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# LLM helper
# ---------------------------------------------------------------------------

def make_llm_fn(model, base_url, api_key):
    from openai import OpenAI
    client = OpenAI(api_key=api_key, base_url=base_url)

    def _call(prompt):
        resp = client.chat.completions.create(
            model=model, temperature=0.0, max_tokens=128,
            messages=[
                {"role": "system", "content": "Be concise. One sentence max."},
                {"role": "user", "content": prompt},
            ],
        )
        return resp.choices[0].message.content or ""
    return _call


# ---------------------------------------------------------------------------
# Hierarchical agent tree
# ---------------------------------------------------------------------------

class AgentNode:
    """A node in the agent hierarchy."""

    def __init__(
        self, agent_id: str, level: int, keypair: AgentKeyPair,
        parent_hpk, config: LeashConfig,
    ):
        self.agent_id = agent_id
        self.level = level
        self.keypair = keypair
        self.config = config
        self.heartbeat_gen = HeartbeatGenerator(keypair.heartbeat_key, config)
        self.heartbeat_cache = HeartbeatCache(config)
        self.credential = (
            CredentialBuilder()
            .with_scopes(["read_file", "write_file", "review_code"])
            .with_attribute("level", str(level))
            .build(keypair, parent_hpk)
        ) if parent_hpk else None
        self.parent_hpk = parent_hpk
        self.children: list["AgentNode"] = []
        self.is_alive = True

        # Measurement: when was this agent first denied?
        self.first_denial_time: float | None = None
        self.last_success_time: float | None = None
        self.call_count = 0
        self.success_count = 0
        self.denial_count = 0


def build_hierarchy(config: LeashConfig) -> tuple[AgentNode, list[AgentNode]]:
    """Build the 4-level hierarchy (49 agents)."""
    all_nodes: list[AgentNode] = []

    # Level 0: Root
    root_kp = AgentKeyPair.generate_root("root")
    root = AgentNode("root", 0, root_kp, None, config)
    all_nodes.append(root)

    # Level 1: 3 coordinators
    for ci in range(3):
        coord_id = f"coord-{ci}"
        coord_kp = root_kp.derive_child(coord_id)
        coord = AgentNode(coord_id, 1, coord_kp, root_kp.heartbeat_public_key(), config)
        root.children.append(coord)
        all_nodes.append(coord)

        # Level 2: 5 workers per coordinator
        for wi in range(5):
            worker_id = f"worker-{ci}-{wi}"
            worker_kp = coord_kp.derive_child(worker_id)
            worker = AgentNode(worker_id, 2, worker_kp, coord_kp.heartbeat_public_key(), config)
            coord.children.append(worker)
            all_nodes.append(worker)

            # Level 3: 2 sub-workers per worker
            for si in range(2):
                sub_id = f"sub-{ci}-{wi}-{si}"
                sub_kp = worker_kp.derive_child(sub_id)
                sub = AgentNode(sub_id, 3, sub_kp, worker_kp.heartbeat_public_key(), config)
                worker.children.append(sub)
                all_nodes.append(sub)

    return root, all_nodes


# ---------------------------------------------------------------------------
# Heartbeat distribution (tree-structured)
# ---------------------------------------------------------------------------

def distribute_heartbeats(root: AgentNode):
    """Recursively generate heartbeats and distribute down the tree."""
    if not root.is_alive:
        return
    hb = root.heartbeat_gen.generate()
    for child in root.children:
        child.heartbeat_cache.add(hb)
        distribute_heartbeats(child)


def start_heartbeat_tree(root: AgentNode, config: LeashConfig) -> threading.Event:
    """Run heartbeat distribution in a background thread."""
    stop = threading.Event()

    def _loop():
        while not stop.is_set():
            distribute_heartbeats(root)
            stop.wait(config.heartbeat_interval_secs)

    t = threading.Thread(target=_loop, daemon=True, name="hb-tree")
    t.start()
    return stop


# ---------------------------------------------------------------------------
# Authentication test
# ---------------------------------------------------------------------------

def try_authenticate(node: AgentNode, verifier: Verifier) -> bool:
    """Attempt LEASH authentication for a non-root node."""
    if node.credential is None:
        return True  # root doesn't auth
    hb = node.heartbeat_cache.get_latest()
    if hb is None:
        return False
    challenge = generate_challenge("cascade_test", node.agent_id)
    proof = CredentialProof.create(
        node.credential, hb, challenge, node.keypair.identity_key,
    )
    result = verifier.verify(proof, challenge)
    return result.valid


# ---------------------------------------------------------------------------
# Worker loop: each agent continuously tries to authenticate + call a tool
# ---------------------------------------------------------------------------

def agent_loop(
    node: AgentNode, verifier: Verifier, sandbox: Sandbox, llm_fn,
    stop: threading.Event, interval: float = 1.0,
):
    """Continuously authenticate and do a tool call. Record timing."""
    tk = AgentToolkit(
        sandbox_root=sandbox.root, db_path=sandbox.db_path,
        llm_fn=llm_fn, agent_id=node.agent_id,
    )
    while not stop.is_set():
        node.call_count += 1
        now = time.time()
        ok = try_authenticate(node, verifier)
        if ok:
            node.success_count += 1
            node.last_success_time = now
            # Do a lightweight tool call
            try:
                tk.read_file("utils.py")
            except Exception:
                pass
        else:
            node.denial_count += 1
            if node.first_denial_time is None:
                node.first_denial_time = now
        stop.wait(interval)


# ---------------------------------------------------------------------------
# Main experiment
# ---------------------------------------------------------------------------

def run_experiment(model: str = "gpt-4o-mini-2024-07-18"):
    api_key = os.environ.get("OPENAI_API_KEY", "")
    base_url = os.environ.get(
        "OPENAI_BASE_URL",
        "https://api.openai.com/v1/",
    )
    if not api_key:
        print("ERROR: Set OPENAI_API_KEY in your environment.")
        sys.exit(1)

    config = LeashConfig(heartbeat_interval_secs=5, max_heartbeat_age_secs=15)
    expected_zombie = config.max_heartbeat_age_secs + config.heartbeat_interval_secs

    print("=" * 70)
    print("  Experiment 15 — Cascading Revocation")
    print("=" * 70)
    print(f"  Hierarchy  : 4 levels, 49 agents")
    print(f"  Config     : Δh={config.heartbeat_interval_secs}s, W_max={config.max_heartbeat_age_secs}s")
    print(f"  Bound      : ≤ {expected_zombie}s per level")
    print("=" * 70)

    llm_fn = make_llm_fn(model, base_url, api_key)

    # Quick LLM check
    print("\n  LLM check ... ", end="", flush=True)
    try:
        llm_fn("Reply OK.")
        print("OK")
    except Exception as exc:
        print(f"FAILED: {exc}")
        sys.exit(1)

    # Build hierarchy
    root, all_nodes = build_hierarchy(config)
    non_root = [n for n in all_nodes if n.level > 0]
    print(f"  Agents: {len(all_nodes)} total ({sum(1 for n in all_nodes if n.level==1)} L1, "
          f"{sum(1 for n in all_nodes if n.level==2)} L2, {sum(1 for n in all_nodes if n.level==3)} L3)")

    # Setup verifier with trust for each parent
    verifier = Verifier(config)
    for node in all_nodes:
        if node.children:  # it's a parent
            verifier.trust_parent(node.agent_id, node.keypair.heartbeat_public_key())

    with Sandbox() as sb:
        # Start heartbeat distribution
        hb_stop = start_heartbeat_tree(root, config)

        # Let heartbeats flow for a few cycles
        print(f"\n  Letting heartbeats stabilize ({config.heartbeat_interval_secs * 3}s) ...", flush=True)
        time.sleep(config.heartbeat_interval_secs * 3)

        # Start agent loops
        agent_stop = threading.Event()
        threads = []
        for node in non_root:
            t = threading.Thread(
                target=agent_loop,
                args=(node, verifier, sb, llm_fn, agent_stop, 0.5),
                daemon=True,
            )
            threads.append(t)
            t.start()

        # Let agents run for a bit
        print(f"  Agents running for 10s pre-revocation ...", flush=True)
        time.sleep(10)

        # Verify all agents are currently authenticated
        pre_kill_ok = sum(1 for n in non_root if n.success_count > 0)
        print(f"  Pre-kill: {pre_kill_ok}/{len(non_root)} agents authenticated successfully")

        # KILL THE ROOT
        t_kill = time.time()
        root.is_alive = False
        hb_stop.set()  # stop heartbeat distribution entirely
        print(f"\n  ROOT ORCHESTRATOR KILLED at T={t_kill:.3f}")
        print(f"  Observing cascade for {expected_zombie + 10}s ...", flush=True)

        # Observe for zombie window + margin
        time.sleep(expected_zombie + 10)
        agent_stop.set()
        for t in threads:
            t.join(timeout=3)

    # ---------------------------------------------------------------------------
    # Analyse results per level
    # ---------------------------------------------------------------------------
    print(f"\n{'=' * 70}")
    print("  CASCADE RESULTS")
    print(f"{'=' * 70}")
    print(f"  {'Level':<10} {'Agents':>8} {'Denied':>8} {'Zombie(s)':>10} {'Max(s)':>8} {'Within?':>8}")
    print(f"  {'─'*10} {'─'*8} {'─'*8} {'─'*10} {'─'*8} {'─'*8}")

    level_results = {}
    for level in range(1, 4):
        nodes_at_level = [n for n in non_root if n.level == level]
        denied = [n for n in nodes_at_level if n.first_denial_time is not None]
        zombie_windows = []
        for n in denied:
            if n.last_success_time and n.last_success_time >= t_kill:
                zw = n.last_success_time - t_kill
            elif n.first_denial_time:
                zw = n.first_denial_time - t_kill
            else:
                zw = 0.0
            zombie_windows.append(zw)

        mean_zw = statistics.mean(zombie_windows) if zombie_windows else 0.0
        max_zw = max(zombie_windows) if zombie_windows else 0.0
        within = max_zw <= expected_zombie + 2  # +2s margin for thread scheduling

        print(
            f"  Level {level:<5} {len(nodes_at_level):>8} {len(denied):>8} "
            f"{mean_zw:>10.2f} {max_zw:>8.2f} {'YES' if within else 'NO':>8}"
        )
        level_results[f"level_{level}"] = {
            "agents": len(nodes_at_level),
            "denied": len(denied),
            "zombie_window_mean_s": round(mean_zw, 3),
            "zombie_window_max_s": round(max_zw, 3),
            "within_bound": within,
        }

    total_denied = sum(1 for n in non_root if n.denial_count > 0)
    total_still_ok = sum(1 for n in non_root if n.denial_count == 0)
    all_denied = total_denied == len(non_root)

    print(f"\n  Total denied: {total_denied}/{len(non_root)}  {'ALL DENIED' if all_denied else 'INCOMPLETE!'}")
    if total_still_ok > 0:
        still_ok_ids = [n.agent_id for n in non_root if n.denial_count == 0]
        print(f"  Still authenticated: {still_ok_ids[:5]}...")
    print(f"{'=' * 70}")

    # Save
    per_agent = []
    for n in non_root:
        zw = 0.0
        if n.last_success_time and n.last_success_time >= t_kill:
            zw = n.last_success_time - t_kill
        per_agent.append({
            "agent_id": n.agent_id,
            "level": n.level,
            "calls": n.call_count,
            "successes": n.success_count,
            "denials": n.denial_count,
            "zombie_window_s": round(zw, 3),
            "first_denial_offset_s": round(n.first_denial_time - t_kill, 3) if n.first_denial_time else None,
        })

    output = {
        "experiment": "exp15_cascading_revocation",
        "model": model,
        "timestamp": time.time(),
        "config": {
            "heartbeat_interval_secs": config.heartbeat_interval_secs,
            "max_heartbeat_age_secs": config.max_heartbeat_age_secs,
            "expected_zombie_bound_s": expected_zombie,
        },
        "hierarchy": {"levels": 4, "total_agents": len(all_nodes)},
        "t_kill": t_kill,
        "level_results": level_results,
        "all_denied": all_denied,
        "per_agent": per_agent,
    }
    output_path = os.path.join(RESULTS_DIR, "exp15_cascading_revocation.json")
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\n  Results saved to {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Exp 15: Cascading Revocation")
    parser.add_argument("--model", "-m", type=str, default="gpt-4o-mini-2024-07-18")
    args = parser.parse_args()
    run_experiment(model=args.model)
