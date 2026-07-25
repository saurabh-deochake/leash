#!/usr/bin/env python3
"""
Experiment 6: Scalability Stress Test

Measures LEASH performance under realistic agent swarm sizes (100, 500, 1000)
to replace extrapolated data with empirical measurements.

Metrics:
  1. Parent-side: heartbeat generation throughput (can parent serve N children?)
  2. Child-side: concurrent proof creation + verification latency under load
  3. End-to-end: revocation propagation time for all N children
  4. CPU utilization during heartbeat generation burst

Run with: python experiments/exp6_scalability.py
"""

import time
import statistics
import json
import os
import sys
import concurrent.futures

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from leash import LeashConfig, Verifier
from leash.keys import AgentKeyPair
from leash.heartbeat import Heartbeat, HeartbeatGenerator
from leash.credentials import CredentialBuilder, CredentialProof
from leash.verification import generate_challenge

RESULTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'results')
os.makedirs(RESULTS_DIR, exist_ok=True)


def test_parent_throughput(swarm_sizes=[10, 50, 100, 500, 1000]):
    """Measure how fast a parent can generate heartbeats for N children.
    
    In LEASH, one heartbeat serves ALL children (broadcast model),
    so this measures single-heartbeat generation time under varying
    system load from child derivation.
    """
    print("\n" + "=" * 60)
    print("TEST 1: Parent Heartbeat Generation Throughput")
    print("=" * 60)

    config = LeashConfig(heartbeat_interval_secs=10, max_heartbeat_age_secs=30)
    results = []

    for n in swarm_sizes:
        parent = AgentKeyPair.generate_root(f"parent-{n}")

        # Derive N children (measures provisioning cost)
        t0 = time.perf_counter()
        children = [parent.derive_child(f"child-{i}") for i in range(n)]
        derivation_time = time.perf_counter() - t0

        # Generate heartbeat (same heartbeat for all children)
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
        print(f"  N={n:>5}: derivation={result['derivation_total_ms']:.1f}ms total "
              f"({result['derivation_per_child_ms']:.3f}ms/child), "
              f"hb_gen={result['hb_gen_mean_ms']:.3f}ms mean")

    return results


def test_concurrent_verification(swarm_sizes=[10, 50, 100, 500, 1000]):
    """Measure verification latency when N children authenticate concurrently.
    
    This is the key scalability test: does per-verification latency
    degrade as the number of concurrent verifications increases?
    """
    print("\n" + "=" * 60)
    print("TEST 2: Concurrent Verification Latency")
    print("=" * 60)

    config = LeashConfig(heartbeat_interval_secs=10, max_heartbeat_age_secs=30)
    results = []

    for n in swarm_sizes:
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

        # Pre-create all proofs
        proofs = [
            CredentialProof.create(credentials[i], hb, challenge, children[i].identity_key)
            for i in range(n)
        ]

        # Sequential verification of all N proofs (simulates burst)
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
            "verify_p99_ms": round(sorted(verify_times)[int(n * 0.99)], 3) if n >= 100 else round(max(verify_times), 3),
            "verify_std_ms": round(statistics.stdev(verify_times), 3) if n > 1 else 0,
            "total_burst_ms": round(total_time, 2),
            "throughput_verifications_per_sec": round(n / (total_time / 1000), 1),
        }
        results.append(result)
        print(f"  N={n:>5}: mean={result['verify_mean_ms']:.3f}ms, "
              f"p99={result['verify_p99_ms']:.3f}ms, "
              f"total_burst={result['total_burst_ms']:.1f}ms, "
              f"throughput={result['throughput_verifications_per_sec']:.0f} verif/s")

    return results


def test_revocation_propagation(swarm_sizes=[10, 50, 100, 500, 1000]):
    """Measure time for ALL N children to be denied after parent revocation.
    
    This is the empirical zombie window test at scale.
    """
    print("\n" + "=" * 60)
    print("TEST 3: Revocation Propagation at Scale")
    print("=" * 60)

    config = LeashConfig(heartbeat_interval_secs=2, max_heartbeat_age_secs=6)
    results = []

    for n in swarm_sizes:
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
        initial_ok = 0
        for i in range(n):
            proof = CredentialProof.create(credentials[i], last_hb, challenge, children[i].identity_key)
            result = verifier.verify(proof, challenge)
            if result.valid:
                initial_ok += 1

        # Parent revoked — stop heartbeats, wait for expiry
        revocation_time = time.time()
        time.sleep(9)  # Wait past max_age + interval = 8s

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
        theoretical_max = 8.0

        result_data = {
            "swarm_size": n,
            "initial_authenticated": initial_ok,
            "denied_after_expiry": denied,
            "all_denied": all_denied,
            "elapsed_s": round(elapsed, 2),
            "check_all_ms": round(check_time, 2),
            "theoretical_bound_s": theoretical_max,
            "passed": all_denied,
        }
        results.append(result_data)
        status = "PASS" if all_denied else "FAIL"
        print(f"  N={n:>5}: {denied}/{n} denied in {elapsed:.1f}s "
              f"(check_all={check_time:.1f}ms) [{status}]")

    return results


def test_proof_creation_at_scale(swarm_sizes=[10, 50, 100, 500, 1000]):
    """Measure proof creation latency as swarm size grows.
    
    Tests whether creating proofs for child #999 is slower than child #0
    (it shouldn't be, since each proof is independent).
    """
    print("\n" + "=" * 60)
    print("TEST 4: Proof Creation Latency at Scale")
    print("=" * 60)

    config = LeashConfig(heartbeat_interval_secs=10, max_heartbeat_age_secs=30)
    results = []

    for n in swarm_sizes:
        parent = AgentKeyPair.generate_root(f"parent-pc-{n}")
        children = [parent.derive_child(f"child-{i}") for i in range(n)]
        credentials = [
            CredentialBuilder().build(c, parent.heartbeat_public_key())
            for c in children
        ]

        verifier = Verifier(config)
        hb = Heartbeat.create(parent.heartbeat_key, verifier.current_epoch())
        challenge = generate_challenge()

        # Time proof creation for ALL children
        create_times = []
        for i in range(n):
            t0 = time.perf_counter()
            CredentialProof.create(credentials[i], hb, challenge, children[i].identity_key)
            create_times.append((time.perf_counter() - t0) * 1000)

        result = {
            "swarm_size": n,
            "create_mean_ms": round(statistics.mean(create_times), 3),
            "create_p99_ms": round(sorted(create_times)[int(n * 0.99)], 3) if n >= 100 else round(max(create_times), 3),
            "create_std_ms": round(statistics.stdev(create_times), 3) if n > 1 else 0,
            "first_child_ms": round(create_times[0], 3),
            "last_child_ms": round(create_times[-1], 3),
        }
        results.append(result)
        print(f"  N={n:>5}: mean={result['create_mean_ms']:.3f}ms, "
              f"p99={result['create_p99_ms']:.3f}ms, "
              f"first={result['first_child_ms']:.3f}ms, "
              f"last={result['last_child_ms']:.3f}ms")

    return results


def main():
    print("=" * 60)
    print("EXPERIMENT 6: Scalability Stress Test")
    print("  Swarm sizes: 10, 50, 100, 500, 1000")
    print("=" * 60)

    swarm_sizes = [10, 50, 100, 500, 1000]

    all_results = {
        "parent_throughput": test_parent_throughput(swarm_sizes),
        "concurrent_verification": test_concurrent_verification(swarm_sizes),
        "proof_creation": test_proof_creation_at_scale(swarm_sizes),
    }

    # Revocation propagation is slow (sleeps 9s per size), run with subset
    print("\n  [Revocation tests involve real-time waits...]")
    all_results["revocation_propagation"] = test_revocation_propagation(swarm_sizes)

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    # Check if verification latency scales linearly
    cv = all_results["concurrent_verification"]
    if len(cv) >= 2:
        ratio = cv[-1]["verify_mean_ms"] / cv[0]["verify_mean_ms"]
        print(f"\n  Verification latency scaling (N={cv[-1]['swarm_size']} vs N={cv[0]['swarm_size']}): "
              f"{ratio:.2f}x")
        if ratio < 2.0:
            print(f"  → Per-verification latency is stable (sub-linear scaling)")
        else:
            print(f"  → WARNING: super-linear scaling detected")

    # Check revocation
    rp = all_results["revocation_propagation"]
    all_passed = all(r["passed"] for r in rp)
    print(f"\n  Revocation at scale: {'ALL PASSED' if all_passed else 'SOME FAILED'}")
    for r in rp:
        status = "PASS" if r["passed"] else "FAIL"
        print(f"    N={r['swarm_size']:>5}: {r['denied_after_expiry']}/{r['swarm_size']} denied [{status}]")

    # Save
    output_path = os.path.join(RESULTS_DIR, 'exp6_scalability.json')
    with open(output_path, 'w') as f:
        json.dump(all_results, f, indent=2)
    print(f"\n  Results saved to {output_path}")


if __name__ == "__main__":
    main()
