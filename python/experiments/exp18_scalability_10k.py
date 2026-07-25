#!/usr/bin/env python3
"""
Experiment 18: Scalability to 10K Agents

Extends Experiment 6 by measuring LEASH performance at swarm sizes of
5,000 and 10,000 agents — validating the O(1) per-verification claim
at enterprise scale.

Metrics:
  1. Parent-side: key derivation cost at N=5K, 10K
  2. Child-side: per-verification latency and throughput
  3. Revocation: all N children correctly denied after heartbeat expiry

Run with: python experiments/exp18_scalability_10k.py
"""

import time
import statistics
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from leash import LeashConfig, Verifier
from leash.keys import AgentKeyPair
from leash.heartbeat import Heartbeat, HeartbeatGenerator
from leash.credentials import CredentialBuilder, CredentialProof
from leash.verification import generate_challenge

RESULTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'results')
os.makedirs(RESULTS_DIR, exist_ok=True)


def test_parent_throughput(swarm_sizes):
    """Measure key derivation and heartbeat generation at large N."""
    print("\n" + "=" * 60)
    print("TEST 1: Parent Throughput at Large Scale")
    print("=" * 60)

    config = LeashConfig(heartbeat_interval_secs=10, max_heartbeat_age_secs=30)
    results = []

    for n in swarm_sizes:
        print(f"  Deriving {n} children...", end=" ", flush=True)
        parent = AgentKeyPair.generate_root(f"parent-{n}")

        t0 = time.perf_counter()
        children = [parent.derive_child(f"child-{i}") for i in range(n)]
        derivation_time = time.perf_counter() - t0

        gen = HeartbeatGenerator(parent.heartbeat_key, config)
        hb_times = []
        for _ in range(100):
            t0 = time.perf_counter()
            gen.generate()
            hb_times.append((time.perf_counter() - t0) * 1000)

        result = {
            "swarm_size": n,
            "derivation_total_ms": round(derivation_time * 1000, 2),
            "derivation_per_child_ms": round(derivation_time * 1000 / n, 3),
            "hb_gen_mean_ms": round(statistics.mean(hb_times), 3),
            "hb_gen_p99_ms": round(sorted(hb_times)[99], 3),
        }
        results.append(result)
        print(f"done ({result['derivation_total_ms']:.0f}ms total, "
              f"{result['derivation_per_child_ms']:.3f}ms/child, "
              f"hb_gen={result['hb_gen_mean_ms']:.3f}ms)")

    return results


def test_concurrent_verification(swarm_sizes):
    """Measure per-verification latency at N=5K and 10K."""
    print("\n" + "=" * 60)
    print("TEST 2: Per-Verification Latency at Scale")
    print("=" * 60)

    config = LeashConfig(heartbeat_interval_secs=10, max_heartbeat_age_secs=30)
    results = []

    for n in swarm_sizes:
        print(f"  Setting up {n} agents...", end=" ", flush=True)
        parent = AgentKeyPair.generate_root(f"parent-cv-{n}")
        children = [parent.derive_child(f"child-{i}") for i in range(n)]
        credentials = [
            CredentialBuilder().build(c, parent.heartbeat_public_key())
            for c in children
        ]

        verifier = Verifier(config)
        verifier.trust_parent(f"parent-cv-{n}", parent.heartbeat_public_key())

        hb = Heartbeat.create(parent.heartbeat_key, verifier.current_epoch())
        challenge = generate_challenge()

        print("creating proofs...", end=" ", flush=True)
        proofs = [
            CredentialProof.create(credentials[i], hb, challenge, children[i].identity_key)
            for i in range(n)
        ]

        print("verifying...", end=" ", flush=True)
        verify_times = []
        t0_total = time.perf_counter()
        for proof in proofs:
            t0 = time.perf_counter()
            verifier.verify(proof, challenge)
            verify_times.append((time.perf_counter() - t0) * 1000)
        total_time = (time.perf_counter() - t0_total) * 1000

        result = {
            "swarm_size": n,
            "verify_mean_ms": round(statistics.mean(verify_times), 3),
            "verify_p99_ms": round(sorted(verify_times)[int(n * 0.99)], 3),
            "verify_std_ms": round(statistics.stdev(verify_times), 3),
            "total_burst_ms": round(total_time, 2),
            "throughput_verifications_per_sec": round(n / (total_time / 1000), 1),
        }
        results.append(result)
        print(f"done")
        print(f"    mean={result['verify_mean_ms']:.3f}ms, "
              f"p99={result['verify_p99_ms']:.3f}ms, "
              f"throughput={result['throughput_verifications_per_sec']:.0f} verif/s")

    return results


def test_revocation_at_scale(swarm_sizes):
    """Confirm all N children denied after heartbeat expiry."""
    print("\n" + "=" * 60)
    print("TEST 3: Revocation Correctness at Scale")
    print("=" * 60)

    config = LeashConfig(heartbeat_interval_secs=2, max_heartbeat_age_secs=6)
    results = []

    for n in swarm_sizes:
        print(f"  Setting up {n} agents...", end=" ", flush=True)
        parent = AgentKeyPair.generate_root(f"parent-rp-{n}")
        children = [parent.derive_child(f"child-{i}") for i in range(n)]
        credentials = [
            CredentialBuilder().build(c, parent.heartbeat_public_key())
            for c in children
        ]

        verifier = Verifier(config)
        verifier.trust_parent(f"parent-rp-{n}", parent.heartbeat_public_key())

        gen = HeartbeatGenerator(parent.heartbeat_key, config)
        last_hb = gen.generate()

        # Verify all can auth initially
        challenge = generate_challenge()
        initial_ok = sum(
            1 for i in range(n)
            if verifier.verify(
                CredentialProof.create(credentials[i], last_hb, challenge, children[i].identity_key),
                challenge,
            ).valid
        )

        print(f"{initial_ok}/{n} authenticated. Waiting 9s for expiry...", end=" ", flush=True)
        revocation_time = time.time()
        time.sleep(9)

        # Check all children are denied
        denied = 0
        t0_check = time.perf_counter()
        for i in range(n):
            proof = CredentialProof.create(credentials[i], last_hb, challenge, children[i].identity_key)
            r = verifier.verify(proof, challenge)
            if not r.valid:
                denied += 1
        check_time = (time.perf_counter() - t0_check) * 1000

        elapsed = time.time() - revocation_time
        all_denied = denied == n

        result = {
            "swarm_size": n,
            "initial_authenticated": initial_ok,
            "denied_after_expiry": denied,
            "all_denied": all_denied,
            "elapsed_s": round(elapsed, 2),
            "check_all_ms": round(check_time, 2),
            "passed": all_denied,
        }
        results.append(result)
        status = "PASS" if all_denied else "FAIL"
        print(f"{denied}/{n} denied [{status}]")

    return results


def main():
    swarm_sizes = [5000, 10000]

    print("=" * 60)
    print("EXPERIMENT 18: Scalability to 10K Agents")
    print(f"  Swarm sizes: {swarm_sizes}")
    print("=" * 60)

    all_results = {
        "parent_throughput": test_parent_throughput(swarm_sizes),
        "concurrent_verification": test_concurrent_verification(swarm_sizes),
    }

    # Revocation test only at N=5000 (N=10000 would take too long for derivation + sleep)
    print("\n  [Revocation test at N=5000 — involves 9s real-time wait]")
    all_results["revocation_propagation"] = test_revocation_at_scale([5000])

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    cv = all_results["concurrent_verification"]
    for r in cv:
        print(f"  N={r['swarm_size']:>6}: verify_mean={r['verify_mean_ms']:.3f}ms, "
              f"p99={r['verify_p99_ms']:.3f}ms, "
              f"throughput={r['throughput_verifications_per_sec']:.0f} verif/s")

    # Compare with Experiment 6 baseline (N=1000)
    if len(cv) >= 1:
        print(f"\n  Reference from Experiment 6: N=1000 → ~5.4ms mean (Python)")
        print(f"  N={cv[-1]['swarm_size']}: {cv[-1]['verify_mean_ms']:.3f}ms mean")
        print(f"  → Scaling ratio: {cv[-1]['verify_mean_ms'] / 5.4:.2f}x")

    rp = all_results["revocation_propagation"]
    for r in rp:
        status = "PASS" if r["passed"] else "FAIL"
        print(f"\n  Revocation N={r['swarm_size']}: "
              f"{r['denied_after_expiry']}/{r['swarm_size']} denied [{status}]")

    # Save
    output_path = os.path.join(RESULTS_DIR, 'exp18_scalability_10k.json')
    with open(output_path, 'w') as f:
        json.dump(all_results, f, indent=2)
    print(f"\n  Results saved to {output_path}")


if __name__ == "__main__":
    main()
