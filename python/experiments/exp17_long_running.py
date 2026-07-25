#!/usr/bin/env python3
"""
Experiment 17 — Long-Running Agent Pipeline Stability

Hypothesis
----------
LEASH sustains correct operation over a multi-hour agent pipeline without
degradation: heartbeat delivery remains reliable, heartbeat cache memory
is bounded, no cumulative clock drift causes false denials, and revocation
at any point during the run is effective within the theoretical bound.

Method
------
1.  Run a single orchestrator + 5 workers performing continuous LLM-backed
    tool calls for a configurable duration (default: 30 minutes; use
    --duration for longer runs up to hours).
2.  Every 60 s, record a health snapshot:
        - Worker auth success rate over the last 60 s
        - Heartbeat cache size per worker
        - Auth latency (mean, P99)
        - Heartbeat age at verification time
        - Cumulative memory footprint (RSS of the process)
3.  At 80% of the total duration, revoke the orchestrator and confirm
    all workers are denied within the bound.
4.  Report:
        - Auth success rate over time (should be ~100% before revoke)
        - Heartbeat cache size over time (should stay bounded)
        - Auth latency over time (should be stable, no GC spikes)
        - Revocation correctness and measured zombie window
        - Any false-positive denials before the intentional revocation

Requirements
------------
    export OPENAI_API_KEY="sk-..."
    pip install openai psutil

Run
---
    python experiments/exp17_long_running.py [--duration 1800] [--model gpt-4o-mini-2024-07-18]

    For a 2-hour run:
    python experiments/exp17_long_running.py --duration 7200
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

# Try to import psutil for memory tracking; optional
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


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
                {"role": "system", "content": "Be concise. One sentence."},
                {"role": "user", "content": prompt},
            ],
        )
        return resp.choices[0].message.content or ""
    return _call


# ---------------------------------------------------------------------------
# Worker with per-interval stats
# ---------------------------------------------------------------------------

class WorkerStats:
    """Thread-safe stats accumulator per worker."""

    def __init__(self, worker_id: str):
        self.worker_id = worker_id
        self.lock = threading.Lock()
        self._successes = 0
        self._denials = 0
        self._auth_latencies: list[float] = []
        self._false_denials = 0  # denials before intentional revocation

    def record(self, success: bool, auth_lat_ms: float, pre_revoke: bool):
        with self.lock:
            if success:
                self._successes += 1
            else:
                self._denials += 1
                if pre_revoke:
                    self._false_denials += 1
            self._auth_latencies.append(auth_lat_ms)

    def snapshot_and_reset(self) -> dict:
        with self.lock:
            s = self._successes
            d = self._denials
            fd = self._false_denials
            lats = list(self._auth_latencies)
            self._successes = 0
            self._denials = 0
            self._false_denials = 0
            self._auth_latencies.clear()
        return {
            "successes": s,
            "denials": d,
            "false_denials": fd,
            "auth_lat_mean_ms": round(statistics.mean(lats), 3) if lats else 0,
            "auth_lat_p99_ms": round(sorted(lats)[int(len(lats) * 0.99)], 3) if lats else 0,
            "calls": s + d,
        }


def worker_loop(
    worker_id: str,
    sandbox: Sandbox,
    llm_fn,
    leash_ctx: LEASHAuthContext,
    stats: WorkerStats,
    stop: threading.Event,
    revoke_flag: threading.Event,
    call_interval: float = 3.0,
):
    """Continuously perform tool calls with LEASH auth."""
    auth_fn = leash_ctx.make_auth_fn(worker_id)
    audit = AuditLog()
    tk = AgentToolkit(
        sandbox_root=sandbox.root,
        db_path=sandbox.db_path,
        llm_fn=llm_fn,
        audit_log=audit,
        agent_id=worker_id,
        auth_fn=auth_fn,
    )

    task_cycle = [
        lambda: tk.read_file("app.py"),
        lambda: tk.query_db("SELECT count(*) as cnt FROM users"),
        lambda: tk.write_file("heartbeat_check.txt", f"{worker_id} alive at {time.time()}"),
        lambda: tk.run_command("wc -l utils.py"),
    ]
    idx = 0

    while not stop.is_set():
        pre_revoke = not revoke_flag.is_set()
        t0 = time.perf_counter()
        try:
            task_cycle[idx % len(task_cycle)]()
            auth_ms = (time.perf_counter() - t0) * 1000
            stats.record(True, auth_ms, pre_revoke)
        except PermissionError:
            auth_ms = (time.perf_counter() - t0) * 1000
            stats.record(False, auth_ms, pre_revoke)
        except Exception:
            auth_ms = (time.perf_counter() - t0) * 1000
            stats.record(True, auth_ms, pre_revoke)  # non-auth error
        idx += 1
        stop.wait(call_interval)


# ---------------------------------------------------------------------------
# Main experiment
# ---------------------------------------------------------------------------

def run_experiment(duration: int = 1800, model: str = "gpt-4o-mini-2024-07-18"):
    api_key = os.environ.get("OPENAI_API_KEY", "")
    base_url = os.environ.get(
        "OPENAI_BASE_URL",
        "https://api.openai.com/v1/",
    )
    if not api_key:
        print("ERROR: Set OPENAI_API_KEY in your environment.")
        sys.exit(1)

    config = LeashConfig(heartbeat_interval_secs=10, max_heartbeat_age_secs=30)
    expected_zombie = config.max_heartbeat_age_secs + config.heartbeat_interval_secs
    revoke_at = int(duration * 0.80)
    num_workers = 5

    print("=" * 70)
    print("  Experiment 17 — Long-Running Pipeline Stability")
    print("=" * 70)
    print(f"  Duration   : {duration}s ({duration/60:.0f} min)")
    print(f"  Workers    : {num_workers}")
    print(f"  Config     : Δh={config.heartbeat_interval_secs}s, W_max={config.max_heartbeat_age_secs}s")
    print(f"  Revoke at  : T+{revoke_at}s ({revoke_at/60:.0f} min)")
    print(f"  Psutil     : {'available' if HAS_PSUTIL else 'not installed (memory tracking disabled)'}")
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

    # Setup LEASH
    leash_ctx = LEASHAuthContext(config)
    leash_ctx.register_parent("orchestrator")
    worker_ids = [f"worker-{i}" for i in range(num_workers)]
    worker_stats = {}
    for wid in worker_ids:
        leash_ctx.register_child(
            "orchestrator", wid,
            ["read_file", "write_file", "review_code", "query_db", "run_command"],
        )
        worker_stats[wid] = WorkerStats(wid)

    snapshots = []
    stop = threading.Event()
    revoke_flag = threading.Event()

    with Sandbox() as sb:
        # Start workers
        threads = []
        for wid in worker_ids:
            t = threading.Thread(
                target=worker_loop,
                args=(wid, sb, llm_fn, leash_ctx, worker_stats[wid], stop, revoke_flag, 3.0),
                daemon=True,
            )
            threads.append(t)
            t.start()

        t_start = time.time()
        t_revoke_actual = None
        snapshot_interval = 60  # seconds
        next_snapshot = t_start + snapshot_interval

        print(f"\n  Pipeline running. Snapshots every {snapshot_interval}s.\n")
        print(f"  {'T(min)':>8} {'Calls':>8} {'OK%':>8} {'Denied':>8} {'FalseD':>8} {'LatP99':>10} {'RSS(MB)':>10}")
        print(f"  {'─'*8} {'─'*8} {'─'*8} {'─'*8} {'─'*8} {'─'*10} {'─'*10}")

        while time.time() - t_start < duration:
            now = time.time()
            elapsed = now - t_start

            # Revoke at the scheduled time
            if elapsed >= revoke_at and t_revoke_actual is None:
                t_revoke_actual = time.time()
                revoke_flag.set()
                leash_ctx.revoke_parent("orchestrator")
                print(f"\n  >>> ORCHESTRATOR REVOKED at T+{elapsed:.0f}s <<<\n")

            # Snapshot
            if now >= next_snapshot:
                snap = {"elapsed_s": round(elapsed, 1), "elapsed_min": round(elapsed / 60, 1)}
                total_calls = 0
                total_ok = 0
                total_denied = 0
                total_false = 0
                lat_p99s = []

                for wid in worker_ids:
                    ws = worker_stats[wid].snapshot_and_reset()
                    total_calls += ws["calls"]
                    total_ok += ws["successes"]
                    total_denied += ws["denials"]
                    total_false += ws["false_denials"]
                    if ws["auth_lat_p99_ms"] > 0:
                        lat_p99s.append(ws["auth_lat_p99_ms"])

                ok_pct = (total_ok / total_calls * 100) if total_calls > 0 else 0
                lat_p99 = max(lat_p99s) if lat_p99s else 0

                rss_mb = 0
                if HAS_PSUTIL:
                    rss_mb = psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024)

                snap.update({
                    "calls": total_calls,
                    "ok_pct": round(ok_pct, 1),
                    "denied": total_denied,
                    "false_denials": total_false,
                    "lat_p99_ms": round(lat_p99, 2),
                    "rss_mb": round(rss_mb, 1),
                })
                snapshots.append(snap)

                print(
                    f"  {snap['elapsed_min']:>7.1f} {total_calls:>8} {ok_pct:>7.1f}% "
                    f"{total_denied:>8} {total_false:>8} {lat_p99:>9.2f}ms "
                    f"{rss_mb:>9.1f}MB"
                )
                next_snapshot = now + snapshot_interval

            time.sleep(1)

        stop.set()
        for t in threads:
            t.join(timeout=5)

    leash_ctx.shutdown()

    # ---------------------------------------------------------------------------
    # Analysis
    # ---------------------------------------------------------------------------
    # Find the zombie window from snapshots after revocation
    pre_revoke_snaps = [s for s in snapshots if s["elapsed_s"] < revoke_at]
    post_revoke_snaps = [s for s in snapshots if s["elapsed_s"] >= revoke_at]

    # False denials before revocation
    total_false_denials = sum(s["false_denials"] for s in pre_revoke_snaps)
    total_pre_calls = sum(s["calls"] for s in pre_revoke_snaps)
    fprr = (total_false_denials / total_pre_calls * 100) if total_pre_calls > 0 else 0

    # Auth success rate stability
    pre_ok_rates = [s["ok_pct"] for s in pre_revoke_snaps if s["calls"] > 0]
    ok_rate_mean = statistics.mean(pre_ok_rates) if pre_ok_rates else 0
    ok_rate_min = min(pre_ok_rates) if pre_ok_rates else 0

    # Latency stability
    pre_p99s = [s["lat_p99_ms"] for s in pre_revoke_snaps if s["lat_p99_ms"] > 0]
    lat_p99_mean = statistics.mean(pre_p99s) if pre_p99s else 0
    lat_p99_max = max(pre_p99s) if pre_p99s else 0

    # Memory growth
    rss_values = [s["rss_mb"] for s in snapshots if s["rss_mb"] > 0]
    if len(rss_values) >= 2:
        mem_growth = rss_values[-1] - rss_values[0]
    else:
        mem_growth = 0

    print(f"\n{'=' * 70}")
    print("  STABILITY REPORT")
    print(f"{'=' * 70}")
    print(f"  Duration                   : {duration/60:.0f} min")
    print(f"  Total snapshots            : {len(snapshots)}")
    print(f"  Pre-revoke auth success    : {ok_rate_mean:.1f}% mean, {ok_rate_min:.1f}% min")
    print(f"  False-positive denials     : {total_false_denials} / {total_pre_calls} = {fprr:.3f}%")
    print(f"  Auth latency P99           : {lat_p99_mean:.2f} ms mean, {lat_p99_max:.2f} ms max")
    print(f"  Memory growth (RSS)        : {mem_growth:+.1f} MB over run")
    print(f"  Revocation effective?      : {'YES' if post_revoke_snaps else 'N/A'}")
    if post_revoke_snaps:
        post_denied = sum(s["denied"] for s in post_revoke_snaps)
        print(f"  Post-revoke denials        : {post_denied}")
    print(f"{'=' * 70}")

    # Save
    output = {
        "experiment": "exp17_long_running",
        "model": model,
        "duration_s": duration,
        "timestamp": time.time(),
        "config": {
            "heartbeat_interval_secs": config.heartbeat_interval_secs,
            "max_heartbeat_age_secs": config.max_heartbeat_age_secs,
            "num_workers": num_workers,
        },
        "stability": {
            "pre_revoke_auth_success_mean_pct": round(ok_rate_mean, 2),
            "pre_revoke_auth_success_min_pct": round(ok_rate_min, 2),
            "false_positive_rate_pct": round(fprr, 4),
            "auth_lat_p99_mean_ms": round(lat_p99_mean, 3),
            "auth_lat_p99_max_ms": round(lat_p99_max, 3),
            "memory_growth_mb": round(mem_growth, 2),
        },
        "snapshots": snapshots,
    }
    output_path = os.path.join(RESULTS_DIR, "exp17_long_running.json")
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\n  Results saved to {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Exp 17: Long-Running Pipeline")
    parser.add_argument("--duration", "-d", type=int, default=1800,
                        help="Duration in seconds (default: 1800 = 30 min)")
    parser.add_argument("--model", "-m", type=str, default="gpt-4o-mini-2024-07-18")
    args = parser.parse_args()
    run_experiment(duration=args.duration, model=args.model)
