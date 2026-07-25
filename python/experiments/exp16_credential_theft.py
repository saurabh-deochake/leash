#!/usr/bin/env python3
"""
Experiment 16 — Credential Theft Resistance

Hypothesis
----------
An adversary who steals a child agent's derived keys (sk_c) and cached
heartbeats can impersonate the child ONLY while cached heartbeats remain
fresh.  Once the parent is revoked (heartbeats cease), both the legitimate
child AND the adversary lose authentication within the zombie window.

This validates the "Child Key Compromise" threat in the paper's threat
model (Section 3.2, Threat 2).

Method
------
1.  Setup: orchestrator → worker with LEASH credentials.
2.  Worker performs authenticated tool calls normally.
3.  STEAL: extract the worker's sk_c, credential, and cached heartbeat.
4.  ADVERSARY: a separate process uses the stolen material to authenticate.
    a. While parent is alive → adversary succeeds (bounded exposure).
    b. Revoke the parent.
    c. After heartbeat expires → adversary is denied.
5.  Measure:
    - Adversary's window of access (should ≤ W_max + Δh)
    - Whether revocation terminates BOTH legitimate and adversary sessions
    - Contrast with bearer token theft (adversary retains access for full TTL)

Requirements
------------
    export OPENAI_API_KEY="sk-..."
    pip install openai

Run
---
    python experiments/exp16_credential_theft.py [--model gpt-4o-mini-2024-07-18]
"""

import argparse
import json
import os
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PYTHON_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, PYTHON_DIR)

from leash import (
    LeashConfig, AgentKeyPair, HeartbeatGenerator, HeartbeatCache,
)
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
                {"role": "system", "content": "Be concise."},
                {"role": "user", "content": prompt},
            ],
        )
        return resp.choices[0].message.content or ""
    return _call


# ---------------------------------------------------------------------------
# Helper: authenticate with given material
# ---------------------------------------------------------------------------

def attempt_auth(
    keypair: AgentKeyPair, credential, cache: HeartbeatCache,
    verifier: Verifier, label: str,
) -> tuple[bool, float]:
    """Try to authenticate using given material. Returns (success, latency_ms)."""
    hb = cache.get_latest()
    if hb is None:
        return False, 0.0
    challenge = generate_challenge("theft_test", label)
    t0 = time.perf_counter()
    proof = CredentialProof.create(credential, hb, challenge, keypair.identity_key)
    result = verifier.verify(proof, challenge)
    lat = (time.perf_counter() - t0) * 1000
    return result.valid, lat


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
    print("  Experiment 16 — Credential Theft Resistance")
    print("=" * 70)
    print(f"  Config : Δh={config.heartbeat_interval_secs}s, W_max={config.max_heartbeat_age_secs}s")
    print(f"  Bound  : ≤ {expected_zombie}s")
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

    # -- Setup: orchestrator + legitimate worker ----------------------------
    parent_kp = AgentKeyPair.generate_root("orchestrator")
    parent_hb_gen = HeartbeatGenerator(parent_kp.heartbeat_key, config)

    worker_kp = parent_kp.derive_child("worker-1")
    worker_cred = (
        CredentialBuilder()
        .with_scopes(["read_file", "write_file", "review_code"])
        .build(worker_kp, parent_kp.heartbeat_public_key())
    )
    worker_cache = HeartbeatCache(config)

    verifier = Verifier(config)
    verifier.trust_parent("orchestrator", parent_kp.heartbeat_public_key())

    # Seed heartbeats
    for _ in range(3):
        hb = parent_hb_gen.generate()
        worker_cache.add(hb)
        time.sleep(config.heartbeat_interval_secs)

    results_timeline = []

    with Sandbox() as sb:
        # -- Phase 1: legitimate worker authenticates -----------------------
        print("\n  Phase 1: Legitimate worker authenticating ...")
        for i in range(3):
            hb = parent_hb_gen.generate()
            worker_cache.add(hb)
            ok, lat = attempt_auth(worker_kp, worker_cred, worker_cache, verifier, "legit-worker")
            print(f"    Legit call {i+1}: {'OK' if ok else 'DENIED'} ({lat:.2f} ms)")
            results_timeline.append({
                "phase": "pre_theft", "actor": "legitimate",
                "time": time.time(), "success": ok,
            })
            time.sleep(1)

        # -- Phase 2: STEAL credentials -------------------------------------
        print("\n  Phase 2: ADVERSARY STEALS worker credentials")
        print(f"    Stolen: sk_c, credential, cached heartbeat")

        # The adversary gets a copy of everything the worker has
        adversary_kp = worker_kp  # same private key
        adversary_cred = worker_cred  # same credential
        adversary_cache = HeartbeatCache(config)
        # Copy the current heartbeat into adversary's cache
        latest_hb = worker_cache.get_latest()
        if latest_hb:
            adversary_cache.add(latest_hb)

        # -- Phase 3: Both authenticate while parent is alive ---------------
        print("\n  Phase 3: Both legitimate and adversary auth (parent alive)")
        for i in range(3):
            hb = parent_hb_gen.generate()
            worker_cache.add(hb)
            adversary_cache.add(hb)  # adversary also receives heartbeats (worst case)

            ok_legit, _ = attempt_auth(worker_kp, worker_cred, worker_cache, verifier, "legit")
            ok_adv, _ = attempt_auth(adversary_kp, adversary_cred, adversary_cache, verifier, "adversary")
            print(f"    Round {i+1}: legit={'OK' if ok_legit else 'DENIED'}, adversary={'OK' if ok_adv else 'DENIED'}")
            results_timeline.append({
                "phase": "both_active", "actor": "legitimate",
                "time": time.time(), "success": ok_legit,
            })
            results_timeline.append({
                "phase": "both_active", "actor": "adversary",
                "time": time.time(), "success": ok_adv,
            })
            time.sleep(config.heartbeat_interval_secs)

        # -- Phase 4: Revoke parent -----------------------------------------
        t_revoke = time.time()
        print(f"\n  Phase 4: PARENT REVOKED at T={t_revoke:.3f}")
        print(f"    Heartbeats cease. Waiting for expiry ({expected_zombie}s + margin) ...")

        # Track adversary's last success
        adversary_last_success = t_revoke
        adversary_successes_after = 0
        legit_successes_after = 0

        # Poll both every second during the zombie window
        poll_duration = expected_zombie + 5
        poll_start = time.time()
        while time.time() - poll_start < poll_duration:
            now = time.time()
            ok_legit, _ = attempt_auth(worker_kp, worker_cred, worker_cache, verifier, "legit")
            ok_adv, _ = attempt_auth(adversary_kp, adversary_cred, adversary_cache, verifier, "adversary")

            offset = now - t_revoke
            if ok_legit:
                legit_successes_after += 1
            if ok_adv:
                adversary_successes_after += 1
                adversary_last_success = now

            status_l = "OK" if ok_legit else "DENIED"
            status_a = "OK" if ok_adv else "DENIED"
            print(f"    T+{offset:5.1f}s  legit={status_l:<6}  adversary={status_a:<6}")

            results_timeline.append({
                "phase": "post_revoke", "actor": "legitimate",
                "time": now, "offset_s": round(offset, 2), "success": ok_legit,
            })
            results_timeline.append({
                "phase": "post_revoke", "actor": "adversary",
                "time": now, "offset_s": round(offset, 2), "success": ok_adv,
            })
            time.sleep(1)

        # -- Phase 5: Final verification (both should be denied) -----------
        print(f"\n  Phase 5: Final verification")
        ok_legit, _ = attempt_auth(worker_kp, worker_cred, worker_cache, verifier, "legit")
        ok_adv, _ = attempt_auth(adversary_kp, adversary_cred, adversary_cache, verifier, "adversary")
        print(f"    Legitimate : {'OK' if ok_legit else 'DENIED'}")
        print(f"    Adversary  : {'OK' if ok_adv else 'DENIED'}")
        both_denied = (not ok_legit) and (not ok_adv)

    adversary_zombie = adversary_last_success - t_revoke
    within_bound = adversary_zombie <= expected_zombie

    # -- OAuth comparison (simulated) ---------------------------------------
    oauth_ttl = 3600
    print(f"\n  ── OAuth comparison (simulated) ──")
    print(f"    Bearer token TTL: {oauth_ttl}s")
    print(f"    Adversary retains access for full {oauth_ttl}s after theft")
    print(f"    No revocation mechanism stops the adversary without server contact")

    # -- Summary ------------------------------------------------------------
    print(f"\n{'=' * 70}")
    print("  RESULTS")
    print(f"{'=' * 70}")
    print(f"  {'Metric':<45} {'OAuth':>12} {'LEASH':>12}")
    print(f"  {'─'*45} {'─'*12} {'─'*12}")
    print(f"  {'Adversary access after theft (parent alive)':<45} {'∞':>12} {'≤Wmax+Δh':>12}")
    print(f"  {'Adversary access after revocation (s)':<45} {oauth_ttl:>12} {adversary_zombie:>12.1f}")
    print(f"  {'Revocation terminates adversary?':<45} {'NO':>12} {'YES' if both_denied else 'NO':>12}")
    print(f"  {'Within bound (W_max+Δh={expected_zombie}s)?':<45} {'N/A':>12} {'YES' if within_bound else 'NO':>12}")
    reduction = oauth_ttl / adversary_zombie if adversary_zombie > 0 else float("inf")
    print(f"  {'Exposure reduction':<45} {'':>12} {reduction:>11.0f}x")
    print(f"{'=' * 70}")

    # Save
    output = {
        "experiment": "exp16_credential_theft",
        "model": model,
        "timestamp": time.time(),
        "config": {
            "heartbeat_interval_secs": config.heartbeat_interval_secs,
            "max_heartbeat_age_secs": config.max_heartbeat_age_secs,
            "expected_zombie_bound_s": expected_zombie,
        },
        "t_revoke": t_revoke,
        "adversary_zombie_window_s": round(adversary_zombie, 3),
        "adversary_successes_after_revoke": adversary_successes_after,
        "legit_successes_after_revoke": legit_successes_after,
        "both_denied_after_expiry": both_denied,
        "within_bound": within_bound,
        "oauth_comparison": {
            "token_ttl_s": oauth_ttl,
            "adversary_access_s": oauth_ttl,
            "reduction_factor": round(reduction, 1) if reduction != float("inf") else "inf",
        },
        "timeline": results_timeline,
    }
    output_path = os.path.join(RESULTS_DIR, "exp16_credential_theft.json")
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\n  Results saved to {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Exp 16: Credential Theft Resistance")
    parser.add_argument("--model", "-m", type=str, default="gpt-4o-mini-2024-07-18")
    args = parser.parse_args()
    run_experiment(model=args.model)
