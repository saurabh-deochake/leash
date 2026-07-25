#!/usr/bin/env python3
"""
Experiment 11 — Real LLM Agent Overhead Benchmark

Hypothesis
----------
LEASH authentication adds negligible overhead (< 0.5 % of total task time)
when real LLM inference dominates the latency of agent tool calls.

Method
------
1.  Define five representative software-engineering agent tasks that combine
    tool calls (file I/O, DB queries, shell commands) with real LLM calls
    via an OpenAI-compatible gateway (any compatible
    endpoint).
2.  Run each task N times *without* LEASH (baseline) and N times *with*
    LEASH authentication gating every tool call.
3.  Report per-task completion time, per-tool-call LEASH overhead, and the
    overhead ratio (with / without).

Requirements
------------
    export OPENAI_API_KEY="sk-..."
    export OPENAI_BASE_URL="https://api.openai.com/v1/"
    # Alternatively, for standard OpenAI:
    # export OPENAI_BASE_URL="https://api.openai.com/v1"
    pip install openai

Run
---
    python experiments/exp11_real_llm_overhead.py [--iterations 10] [--model gpt-4o-mini-2024-07-18]
"""

import argparse
import json
import os
import sys
import time
import statistics
from typing import Optional

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
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
# LLM helper
# ---------------------------------------------------------------------------

def make_llm_fn(model: str, base_url: str, api_key: str):
    """
    Return a ``(prompt: str) -> str`` callable that hits an
    OpenAI-compatible chat completions endpoint.
    """
    try:
        from openai import OpenAI
    except ImportError:
        print("ERROR: 'openai' package not installed. Run: pip install openai")
        sys.exit(1)

    client = OpenAI(api_key=api_key, base_url=base_url)

    def _call(prompt: str) -> str:
        resp = client.chat.completions.create(
            model=model,
            temperature=0.0,
            max_tokens=512,
            messages=[
                {"role": "system", "content": "You are a senior security engineer reviewing code. Be concise."},
                {"role": "user", "content": prompt},
            ],
        )
        return resp.choices[0].message.content or ""

    return _call


# ---------------------------------------------------------------------------
# Task definitions
# Each task appends a unique nonce to LLM prompts to prevent gateway caching.
# ---------------------------------------------------------------------------

import random
import string

def _nonce() -> str:
    """Short random string appended to prompts to defeat response caching."""
    return "[run-" + "".join(random.choices(string.ascii_lowercase, k=6)) + "]"


def task_single_read(tk: AgentToolkit) -> str:
    """Task 1: Read a file and ask the LLM what it does (1 tool + 1 LLM call)."""
    code = tk.read_file("utils.py")
    review = tk.review_code(code, f"Briefly explain what this module does in 2-3 sentences. {_nonce()}")
    return review


def task_read_and_write(tk: AgentToolkit) -> str:
    """Task 2: Read a file, ask the LLM to fix it, write the result (2 tools + 1 LLM call)."""
    code = tk.read_file("models.py")
    fixed = tk.review_code(
        code,
        "The hash_password function uses MD5. Rewrite ONLY that function to use "
        f"bcrypt. Return ONLY the Python code for the function, no explanation. {_nonce()}",
    )
    tk.write_file("models_fixed.py", fixed)
    return fixed


def task_security_audit(tk: AgentToolkit) -> str:
    """Task 3: Multi-file security audit (3 reads + 1 LLM call)."""
    app = tk.read_file("app.py")
    models = tk.read_file("models.py")
    utils = tk.read_file("utils.py")
    combined = f"# app.py\n{app}\n\n# models.py\n{models}\n\n# utils.py\n{utils}"
    review = tk.review_code(
        combined,
        "List all security vulnerabilities in this codebase. "
        f"For each, state the file, line, vulnerability type (CWE if possible), and severity. {_nonce()}",
    )
    return review


def task_db_analysis(tk: AgentToolkit) -> str:
    """Task 4: Query the database and ask the LLM to analyse results (1 DB + 1 LLM)."""
    rows = tk.query_db("SELECT username, role, email FROM users")
    prompt = (
        f"Analyse these user accounts for suspicious patterns {_nonce()} "
        "(e.g. admin accounts, unusual emails):\n\n"
        + json.dumps(rows, indent=2)
    )
    analysis = tk.review_code(prompt)  # reuse review_code as generic LLM call
    return analysis


def task_full_pipeline(tk: AgentToolkit) -> str:
    """Task 5: Read, review, fix, write, compile-check (3 tools + 2 LLM calls)."""
    code = tk.read_file("app.py")
    review = tk.review_code(
        code,
        "Identify the single most critical vulnerability in this Flask app. "
        f"Return ONLY a JSON object: {{\"vuln\": \"...\", \"fix\": \"...\"}} {_nonce()}",
    )
    # Write a patched stub
    tk.write_file("app_patched.py", f"# Auto-patched\n# Review: {review[:200]}\n{code[:500]}")
    # Syntax-check the patched file
    result = tk.run_command("python3 -m py_compile app_patched.py")
    return json.dumps({"review": review[:300], "compile": result})


TASKS = [
    ("T1: single_read", task_single_read),
    ("T2: read_and_write", task_read_and_write),
    ("T3: security_audit", task_security_audit),
    ("T4: db_analysis", task_db_analysis),
    ("T5: full_pipeline", task_full_pipeline),
]


# ---------------------------------------------------------------------------
# Experiment runner
# ---------------------------------------------------------------------------

def run_task_batch(
    sandbox: Sandbox,
    llm_fn,
    task_name: str,
    task_fn,
    iterations: int,
    use_leash: bool,
) -> dict:
    """Run *task_fn* for *iterations* and return timing stats."""
    config = LeashConfig(heartbeat_interval_secs=5, max_heartbeat_age_secs=15)
    leash_ctx: Optional[LEASHAuthContext] = None
    auth_fn = None

    if use_leash:
        leash_ctx = LEASHAuthContext(config)
        leash_ctx.register_parent("orchestrator")
        leash_ctx.register_child(
            "orchestrator", "worker-1",
            ["read_file", "write_file", "review_code", "query_db", "run_command"],
        )
        auth_fn = leash_ctx.make_auth_fn("worker-1")

    durations: list[float] = []
    audit_logs: list[dict] = []
    errors: list[str] = []

    for i in range(iterations):
        audit = AuditLog()
        tk = AgentToolkit(
            sandbox_root=sandbox.root,
            db_path=sandbox.db_path,
            llm_fn=llm_fn,
            audit_log=audit,
            agent_id="worker-1",
            auth_fn=auth_fn,
        )
        t0 = time.perf_counter()
        try:
            task_fn(tk)
            durations.append((time.perf_counter() - t0) * 1000)
        except Exception as exc:
            durations.append((time.perf_counter() - t0) * 1000)
            errors.append(f"iter {i}: {exc}")
        audit_logs.append(audit.summary())

    if leash_ctx:
        leash_ctx.shutdown()

    # Aggregate auth overhead from audit logs
    auth_overheads = [a.get("auth_latency_mean_ms", 0.0) for a in audit_logs if a]

    return {
        "task": task_name,
        "leash": use_leash,
        "iterations": iterations,
        "mean_ms": round(statistics.mean(durations), 2) if durations else 0,
        "median_ms": round(statistics.median(durations), 2) if durations else 0,
        "stdev_ms": round(statistics.stdev(durations), 2) if len(durations) > 1 else 0,
        "p99_ms": round(sorted(durations)[int(len(durations) * 0.99)] if durations else 0, 2),
        "min_ms": round(min(durations), 2) if durations else 0,
        "max_ms": round(max(durations), 2) if durations else 0,
        "auth_overhead_mean_ms": round(statistics.mean(auth_overheads), 4) if auth_overheads else 0,
        "errors": len(errors),
        "error_details": errors[:3],  # keep first 3 for debugging
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_experiment(iterations: int = 10, model: str = "gpt-4o-mini-2024-07-18"):
    api_key = os.environ.get("OPENAI_API_KEY", "")
    base_url = os.environ.get(
        "OPENAI_BASE_URL",
        "https://api.openai.com/v1/",
    )

    if not api_key:
        print("=" * 70)
        print("ERROR: Set OPENAI_API_KEY in your environment.")
        print("  export OPENAI_API_KEY='sk-...'")
        print("=" * 70)
        sys.exit(1)

    print("=" * 70)
    print("  Experiment 11 — Real LLM Agent Overhead Benchmark")
    print("=" * 70)
    print(f"  Model   : {model}")
    print(f"  Gateway : {base_url[:60]}...")
    print(f"  Iters   : {iterations} per task per mode")
    print(f"  Tasks   : {len(TASKS)}")
    print("=" * 70)

    llm_fn = make_llm_fn(model, base_url, api_key)

    # Quick connectivity check
    print("\n  Checking LLM connectivity ... ", end="", flush=True)
    try:
        t0 = time.perf_counter()
        resp = llm_fn("Reply with OK.")
        lat = (time.perf_counter() - t0) * 1000
        print(f"OK ({lat:.0f} ms)")
    except Exception as exc:
        print(f"FAILED: {exc}")
        sys.exit(1)

    all_results = []

    with Sandbox() as sb:
        print(f"\n  Sandbox: {sb.root}")
        print(f"  Files  : {sb.list_files()}\n")

        for task_name, task_fn in TASKS:
            print(f"  ── {task_name} {'─' * (50 - len(task_name))}")

            # --- baseline (no LEASH) ---
            print(f"    Baseline (no LEASH)  x{iterations} ... ", end="", flush=True)
            baseline = run_task_batch(sb, llm_fn, task_name, task_fn, iterations, use_leash=False)
            print(f"{baseline['mean_ms']:>8.1f} ms  (±{baseline['stdev_ms']:.1f})")

            # --- with LEASH ---
            print(f"    With LEASH           x{iterations} ... ", end="", flush=True)
            leash_run = run_task_batch(sb, llm_fn, task_name, task_fn, iterations, use_leash=True)
            print(f"{leash_run['mean_ms']:>8.1f} ms  (±{leash_run['stdev_ms']:.1f})")

            # --- overhead ---
            if baseline["mean_ms"] > 0:
                overhead_pct = ((leash_run["mean_ms"] - baseline["mean_ms"]) / baseline["mean_ms"]) * 100
                overhead_abs = leash_run["mean_ms"] - baseline["mean_ms"]
            else:
                overhead_pct = 0.0
                overhead_abs = 0.0

            print(f"    Overhead: {overhead_abs:+.1f} ms  ({overhead_pct:+.2f}%)")
            print(f"    LEASH auth overhead per tool call: {leash_run['auth_overhead_mean_ms']:.3f} ms")
            if baseline["errors"] or leash_run["errors"]:
                print(f"    Errors: baseline={baseline['errors']}, leash={leash_run['errors']}")
            print()

            all_results.append({
                "task": task_name,
                "baseline": baseline,
                "leash": leash_run,
                "overhead_ms": round(overhead_abs, 2),
                "overhead_pct": round(overhead_pct, 4),
            })

    # ---------------------------------------------------------------------------
    # Summary table
    # ---------------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("  SUMMARY")
    print("=" * 70)
    print(f"  {'Task':<25} {'Baseline':>10} {'LEASH':>10} {'Overhead':>10} {'%':>8}")
    print(f"  {'':─<25} {'(ms)':─>10} {'(ms)':─>10} {'(ms)':─>10} {'':─>8}")
    for r in all_results:
        print(
            f"  {r['task']:<25} "
            f"{r['baseline']['mean_ms']:>10.1f} "
            f"{r['leash']['mean_ms']:>10.1f} "
            f"{r['overhead_ms']:>+10.1f} "
            f"{r['overhead_pct']:>+7.2f}%"
        )

    total_base = sum(r["baseline"]["mean_ms"] for r in all_results)
    total_leash = sum(r["leash"]["mean_ms"] for r in all_results)
    total_ovh = total_leash - total_base
    total_pct = (total_ovh / total_base * 100) if total_base > 0 else 0
    print(f"  {'TOTAL':<25} {total_base:>10.1f} {total_leash:>10.1f} {total_ovh:>+10.1f} {total_pct:>+7.2f}%")
    print("=" * 70)

    # ---------------------------------------------------------------------------
    # Save results
    # ---------------------------------------------------------------------------
    output = {
        "experiment": "exp11_real_llm_overhead",
        "model": model,
        "iterations_per_task": iterations,
        "timestamp": time.time(),
        "tasks": all_results,
        "totals": {
            "baseline_ms": round(total_base, 2),
            "leash_ms": round(total_leash, 2),
            "overhead_ms": round(total_ovh, 2),
            "overhead_pct": round(total_pct, 4),
        },
    }
    output_path = os.path.join(RESULTS_DIR, "exp11_real_llm_overhead.json")
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\n  Results saved to {output_path}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Exp 11: Real LLM Overhead Benchmark")
    parser.add_argument("--iterations", "-n", type=int, default=10,
                        help="Iterations per task per mode (default: 10)")
    parser.add_argument("--model", "-m", type=str, default="gpt-4o-mini-2024-07-18",
                        help="Model name for the OpenAI-compatible endpoint")
    args = parser.parse_args()
    run_experiment(iterations=args.iterations, model=args.model)
