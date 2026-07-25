#!/usr/bin/env python3
"""
Experiment 12 — Real Zombie Agent Demonstration

Hypothesis
----------
Under standard OAuth-style bearer tokens, worker agents continue executing
privileged tool calls for the full token lifetime after the orchestrator is
killed.  Under LEASH, all worker tool calls fail within W_max + Delta_h
seconds (~20 s with the experiment config).

Method
------
1.  Spawn an orchestrator and five worker agents, each performing a
    continuous loop of real LLM-backed tool calls (code review, file writes,
    DB queries) against a sandboxed codebase.
2.  After the workers have successfully completed several tool calls,
    **kill the orchestrator** at a known timestamp T_kill.
3.  Workers continue attempting tool calls.  Every attempt is audit-logged
    with a millisecond timestamp.
4.  Measure:
    a.  **OAuth baseline** — how many successful tool calls occur after T_kill
        (simulated: bearer token valid for 3600 s).
    b.  **LEASH** — how many successful tool calls occur after T_kill, and at
        what timestamp the last success occurs (the *measured zombie window*).

The audit-log diff between (a) and (b) is the headline result.

Requirements
------------
    export OPENAI_API_KEY="sk-..."
    export OPENAI_BASE_URL="https://api.openai.com/v1/"
    pip install openai

Run
---
    python experiments/exp12_zombie_demo.py [--model gpt-4o-mini-2024-07-18]
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

from leash import LeashConfig

from tools.sandbox import Sandbox
from tools.agent_tools import AgentToolkit, AuditLog
from tools.leash_auth import LEASHAuthContext

RESULTS_DIR = os.path.join(PYTHON_DIR, "results")
os.makedirs(RESULTS_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# LLM helper (same as exp11)
# ---------------------------------------------------------------------------

def make_llm_fn(model: str, base_url: str, api_key: str):
    from openai import OpenAI
    client = OpenAI(api_key=api_key, base_url=base_url)

    def _call(prompt: str) -> str:
        resp = client.chat.completions.create(
            model=model,
            temperature=0.0,
            max_tokens=256,
            messages=[
                {"role": "system", "content": "You are a security engineer. Be concise."},
                {"role": "user", "content": prompt},
            ],
        )
        return resp.choices[0].message.content or ""
    return _call


# ---------------------------------------------------------------------------
# Worker loop
# ---------------------------------------------------------------------------

WORKER_TASKS = [
    ("CodeAnalyzer",  "read_file",   lambda tk: tk.read_file("app.py")),
    ("CodeWriter",    "write_file",  lambda tk: tk.write_file("patch.py", f"# patch at {time.time()}\nprint('patched')\n")),
    ("CodeReviewer",  "review_code", lambda tk: tk.review_code(tk.read_file("utils.py"), "List vulnerabilities in 2 sentences.")),
    ("SQLAgent",      "query_db",    lambda tk: tk.query_db("SELECT username, role FROM users WHERE role='admin'")),
    ("DeployAgent",   "run_command", lambda tk: tk.run_command("wc -l app.py")),
]


def _worker_loop(
    worker_id: str,
    task_fn,
    sandbox: Sandbox,
    llm_fn,
    audit: AuditLog,
    auth_fn,
    stop_event: threading.Event,
    call_interval: float = 2.0,
):
    """
    Continuously execute *task_fn* until *stop_event* is set.
    Each iteration is logged in *audit*.
    """
    tk = AgentToolkit(
        sandbox_root=sandbox.root,
        db_path=sandbox.db_path,
        llm_fn=llm_fn,
        audit_log=audit,
        agent_id=worker_id,
        auth_fn=auth_fn,
    )
    while not stop_event.is_set():
        try:
            task_fn(tk)
        except PermissionError:
            # LEASH denied — log is already recorded in AgentToolkit
            pass
        except Exception as exc:
            # LLM or I/O error — record but keep looping
            audit.record(
                __import__("tools.agent_tools", fromlist=["ToolCall"]).ToolCall(
                    timestamp=time.time(),
                    agent_id=worker_id,
                    tool_name="unknown",
                    args={},
                    success=False,
                    auth_latency_ms=0,
                    tool_latency_ms=0,
                    total_latency_ms=0,
                    error=str(exc),
                )
            )
        stop_event.wait(call_interval)


# ---------------------------------------------------------------------------
# Scenario runners
# ---------------------------------------------------------------------------

def run_oauth_scenario(
    sandbox: Sandbox, llm_fn, pre_kill_calls: int, post_kill_duration: float,
) -> dict:
    """
    Simulate OAuth: bearer tokens valid for 3600 s.
    auth_fn always returns True (token is valid).
    """
    print("\n  ── Scenario A: OAuth 2.0 (bearer token, 1 h TTL) ──")
    audit = AuditLog()
    stop = threading.Event()

    # No auth — always allowed (simulates unexpired bearer token)
    threads = []
    for name, _, task_fn in WORKER_TASKS:
        t = threading.Thread(
            target=_worker_loop,
            args=(name, task_fn, sandbox, llm_fn, audit, None, stop, 1.5),
            daemon=True,
        )
        threads.append(t)

    # Start workers
    for t in threads:
        t.start()

    # Let workers run for a bit to build up successful calls
    print(f"    Workers running (building baseline) ...", flush=True)
    time.sleep(pre_kill_calls * 1.5 + 2)

    t_kill = time.time()
    print(f"    ORCHESTRATOR KILLED at T={t_kill:.3f}")
    print(f"    (OAuth: tokens remain valid — workers keep running)")

    # Let workers continue for post_kill_duration
    print(f"    Observing for {post_kill_duration:.0f}s after kill ...", flush=True)
    time.sleep(post_kill_duration)

    stop.set()
    for t in threads:
        t.join(timeout=5)

    calls_after = audit.successful_calls_after(t_kill)
    print(f"    Successful tool calls after kill: {len(calls_after)}")

    return {
        "scenario": "oauth_bearer",
        "t_kill": t_kill,
        "total_calls": len(audit.entries),
        "calls_after_kill": len(calls_after),
        "last_success_offset_s": round(calls_after[-1].timestamp - t_kill, 2) if calls_after else 0,
        "zombie_window_s": round(calls_after[-1].timestamp - t_kill, 2) if calls_after else 0,
        "audit": audit.to_list(),
    }


def run_leash_scenario(
    sandbox: Sandbox, llm_fn, pre_kill_calls: int, post_kill_duration: float,
) -> dict:
    """
    LEASH: liveness-bound credentials.
    After orchestrator is revoked, workers lose auth within W_max + Delta_h.
    """
    print("\n  ── Scenario B: LEASH (liveness-bound credentials) ──")

    config = LeashConfig(heartbeat_interval_secs=5, max_heartbeat_age_secs=15)
    leash_ctx = LEASHAuthContext(config)
    leash_ctx.register_parent("orchestrator")

    audit = AuditLog()
    stop = threading.Event()

    # Register children and start worker threads
    threads = []
    for name, primary_tool, task_fn in WORKER_TASKS:
        scopes = ["read_file", "write_file", "review_code", "query_db", "run_command"]
        leash_ctx.register_child("orchestrator", name, scopes)
        auth_fn = leash_ctx.make_auth_fn(name)

        t = threading.Thread(
            target=_worker_loop,
            args=(name, task_fn, sandbox, llm_fn, audit, auth_fn, stop, 1.5),
            daemon=True,
        )
        threads.append(t)

    for t in threads:
        t.start()

    # Let workers run to build up successful calls
    print(f"    Workers running (heartbeats active) ...", flush=True)
    time.sleep(pre_kill_calls * 1.5 + 2)

    t_kill = time.time()
    print(f"    ORCHESTRATOR REVOKED at T={t_kill:.3f}")
    leash_ctx.revoke_parent("orchestrator")

    expected_zombie = config.max_heartbeat_age_secs + config.heartbeat_interval_secs
    print(f"    (LEASH: heartbeats cease — expected zombie window ≤ {expected_zombie}s)")

    # Observe for longer than the zombie window
    print(f"    Observing for {post_kill_duration:.0f}s after revocation ...", flush=True)
    time.sleep(post_kill_duration)

    stop.set()
    for t in threads:
        t.join(timeout=5)
    leash_ctx.shutdown()

    calls_after = audit.successful_calls_after(t_kill)
    if calls_after:
        measured_zombie = round(calls_after[-1].timestamp - t_kill, 2)
    else:
        measured_zombie = 0.0

    print(f"    Successful tool calls after revocation: {len(calls_after)}")
    print(f"    Measured zombie window: {measured_zombie:.2f}s (bound: {expected_zombie}s)")

    return {
        "scenario": "leash",
        "config": {
            "heartbeat_interval_secs": config.heartbeat_interval_secs,
            "max_heartbeat_age_secs": config.max_heartbeat_age_secs,
        },
        "t_kill": t_kill,
        "total_calls": len(audit.entries),
        "calls_after_kill": len(calls_after),
        "last_success_offset_s": measured_zombie,
        "zombie_window_s": measured_zombie,
        "expected_zombie_bound_s": expected_zombie,
        "within_bound": measured_zombie <= expected_zombie,
        "audit": audit.to_list(),
    }


# ---------------------------------------------------------------------------
# Main
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

    print("=" * 70)
    print("  Experiment 12 — Real Zombie Agent Demonstration")
    print("=" * 70)
    print(f"  Model       : {model}")
    print(f"  Workers     : {len(WORKER_TASKS)}")
    print(f"  Pre-kill    : ~5 tool calls per worker")
    print(f"  Post-kill   : 45 s observation window")
    print("=" * 70)

    llm_fn = make_llm_fn(model, base_url, api_key)

    # Connectivity check
    print("\n  LLM check ... ", end="", flush=True)
    try:
        llm_fn("Reply OK.")
        print("OK")
    except Exception as exc:
        print(f"FAILED: {exc}")
        sys.exit(1)

    pre_kill_calls = 5
    post_kill_duration = 45.0  # seconds — well beyond LEASH zombie window

    with Sandbox() as sb:
        print(f"  Sandbox: {sb.root}\n")

        oauth_result = run_oauth_scenario(sb, llm_fn, pre_kill_calls, post_kill_duration)
        leash_result = run_leash_scenario(sb, llm_fn, pre_kill_calls, post_kill_duration)

    # ---------------------------------------------------------------------------
    # Comparison
    # ---------------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("  COMPARISON")
    print("=" * 70)
    print(f"  {'Metric':<40} {'OAuth':>12} {'LEASH':>12}")
    print(f"  {'─' * 40} {'─' * 12} {'─' * 12}")
    print(f"  {'Tool calls after kill':<40} {oauth_result['calls_after_kill']:>12} {leash_result['calls_after_kill']:>12}")
    print(f"  {'Zombie window (s)':<40} {oauth_result['zombie_window_s']:>12.1f} {leash_result['zombie_window_s']:>12.1f}")

    if leash_result["zombie_window_s"] > 0:
        reduction = oauth_result["zombie_window_s"] / leash_result["zombie_window_s"]
    else:
        reduction = float("inf")
    print(f"  {'Zombie window reduction':<40} {'':>12} {reduction:>11.0f}x")
    print(f"  {'Within theoretical bound?':<40} {'N/A':>12} {'YES' if leash_result['within_bound'] else 'NO':>12}")
    print("=" * 70)

    # ---------------------------------------------------------------------------
    # Save
    # ---------------------------------------------------------------------------
    output = {
        "experiment": "exp12_zombie_demo",
        "model": model,
        "timestamp": time.time(),
        "oauth": {k: v for k, v in oauth_result.items() if k != "audit"},
        "leash": {k: v for k, v in leash_result.items() if k != "audit"},
        "comparison": {
            "oauth_calls_after_kill": oauth_result["calls_after_kill"],
            "leash_calls_after_kill": leash_result["calls_after_kill"],
            "oauth_zombie_s": oauth_result["zombie_window_s"],
            "leash_zombie_s": leash_result["zombie_window_s"],
            "reduction_factor": round(reduction, 1) if reduction != float("inf") else "inf",
            "leash_within_bound": leash_result["within_bound"],
        },
        # Full audit logs for detailed analysis / paper figures
        "oauth_audit": oauth_result["audit"],
        "leash_audit": leash_result["audit"],
    }
    output_path = os.path.join(RESULTS_DIR, "exp12_zombie_demo.json")
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\n  Results saved to {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Exp 12: Zombie Agent Demo")
    parser.add_argument("--model", "-m", type=str, default="gpt-4o-mini-2024-07-18")
    args = parser.parse_args()
    run_experiment(model=args.model)
