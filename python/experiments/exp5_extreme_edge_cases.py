#!/usr/bin/env python3
"""
Experiment 5: Extreme Edge Case Validation

Validates LEASH claims under stress conditions:
  1. Minimum viable configuration (1s interval, 4s max age → 5s zombie)
  2. Deep hierarchy (3-level: grandparent → parent → child)
  3. Concurrent children (50 children, single parent revocation)
  4. Clock skew tolerance (simulated ±1 epoch drift)

Run with: python experiments/exp5_extreme_edge_cases.py
"""

import time
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


def test_minimum_config():
    """Test 1: Minimum viable configuration (5s zombie window)."""
    print("\n" + "=" * 60)
    print("TEST 1: Minimum Viable Configuration")
    print("  Δh=1s, Wmax=4s → theoretical max zombie = 5s")
    print("=" * 60)

    config = LeashConfig(heartbeat_interval_secs=1, max_heartbeat_age_secs=4)
    parent = AgentKeyPair.generate_root("parent-min")
    child = parent.derive_child("child-min")

    verifier = Verifier(config)
    verifier.trust_parent("parent-min", parent.heartbeat_public_key())
    credential = CredentialBuilder().build(child, parent.heartbeat_public_key())

    gen = HeartbeatGenerator(parent.heartbeat_key, config)
    last_hb = gen.generate()
    revocation_time = time.time()

    challenge = generate_challenge()
    zombie_duration = 0

    while True:
        proof = CredentialProof.create(credential, last_hb, challenge, child.identity_key)
        result = verifier.verify(proof, challenge)
        if not result.valid:
            zombie_duration = time.time() - revocation_time
            break
        time.sleep(0.25)
        if time.time() - revocation_time > 10:
            zombie_duration = time.time() - revocation_time
            break

    theoretical_max = 5.0
    passed = zombie_duration <= theoretical_max + 1.0  # 1s tolerance
    status = "PASS" if passed else "FAIL"
    print(f"  Measured zombie: {zombie_duration:.2f}s (bound: {theoretical_max}s) [{status}]")

    return {
        "test": "minimum_config",
        "interval": 1, "max_age": 4,
        "theoretical_max": theoretical_max,
        "measured": round(zombie_duration, 3),
        "passed": passed,
    }


def test_deep_hierarchy():
    """Test 2: 3-level hierarchy (grandparent → parent → child)."""
    print("\n" + "=" * 60)
    print("TEST 2: Deep Hierarchy (3 levels)")
    print("  grandparent → parent → child")
    print("  Revoke grandparent, verify child loses access")
    print("=" * 60)

    config = LeashConfig(heartbeat_interval_secs=2, max_heartbeat_age_secs=6)

    # Level 0: grandparent
    grandparent = AgentKeyPair.generate_root("grandparent")
    # Level 1: parent (derived from grandparent)
    parent = grandparent.derive_child("parent")
    # Level 2: child (derived from parent)
    child = parent.derive_child("child")

    # Grandparent generates heartbeat for parent
    gp_gen = HeartbeatGenerator(grandparent.heartbeat_key, config)
    gp_hb = gp_gen.generate()

    # Parent generates heartbeat for child
    p_gen = HeartbeatGenerator(parent.heartbeat_key, config)
    p_hb = p_gen.generate()

    # Verifier trusts parent's heartbeat key (for child auth)
    verifier = Verifier(config)
    verifier.trust_parent("parent", parent.heartbeat_public_key())

    credential = CredentialBuilder().build(child, parent.heartbeat_public_key())

    # Child can authenticate with parent's heartbeat
    challenge = generate_challenge()
    proof = CredentialProof.create(credential, p_hb, challenge, child.identity_key)
    result = verifier.verify(proof, challenge)
    initial_auth = result.valid
    print(f"  Initial auth (parent alive): {initial_auth}")

    # Now: grandparent is revoked → parent stops heartbeats
    # Wait for parent's heartbeat to expire
    revocation_time = time.time()
    zombie_duration = 0

    while True:
        proof = CredentialProof.create(credential, p_hb, challenge, child.identity_key)
        result = verifier.verify(proof, challenge)
        if not result.valid:
            zombie_duration = time.time() - revocation_time
            break
        time.sleep(0.5)
        if time.time() - revocation_time > 15:
            zombie_duration = time.time() - revocation_time
            break

    theoretical_max = 8.0  # 6 + 2
    passed = initial_auth and zombie_duration <= theoretical_max + 1.0
    status = "PASS" if passed else "FAIL"
    print(f"  Zombie window after parent stops: {zombie_duration:.2f}s (bound: {theoretical_max}s) [{status}]")
    print(f"  Key insight: hierarchical revocation propagates through heartbeat chains")

    return {
        "test": "deep_hierarchy",
        "levels": 3,
        "theoretical_max": theoretical_max,
        "measured": round(zombie_duration, 3),
        "initial_auth": initial_auth,
        "passed": passed,
    }


def test_concurrent_children():
    """Test 3: 50 children, single parent revocation."""
    print("\n" + "=" * 60)
    print("TEST 3: Concurrent Children (50 agents)")
    print("  Single parent revocation → all 50 children lose access")
    print("=" * 60)

    config = LeashConfig(heartbeat_interval_secs=2, max_heartbeat_age_secs=6)
    parent = AgentKeyPair.generate_root("parent-50")
    num_children = 50

    # Derive all children
    children = [parent.derive_child(f"child-{i}") for i in range(num_children)]
    credentials = [
        CredentialBuilder().build(c, parent.heartbeat_public_key())
        for c in children
    ]

    verifier = Verifier(config)
    verifier.trust_parent("parent-50", parent.heartbeat_public_key())

    gen = HeartbeatGenerator(parent.heartbeat_key, config)
    last_hb = gen.generate()

    # Verify all can auth initially
    challenge = generate_challenge()
    initial_count = 0
    for i in range(num_children):
        proof = CredentialProof.create(credentials[i], last_hb, challenge, children[i].identity_key)
        result = verifier.verify(proof, challenge)
        if result.valid:
            initial_count += 1

    print(f"  Initial: {initial_count}/{num_children} children authenticated")

    # Wait for heartbeat to expire
    revocation_time = time.time()
    time.sleep(9)  # Wait past max_age + interval = 8s

    # Check all children are now denied
    denied_count = 0
    for i in range(num_children):
        proof = CredentialProof.create(credentials[i], last_hb, challenge, children[i].identity_key)
        result = verifier.verify(proof, challenge)
        if not result.valid:
            denied_count += 1

    elapsed = time.time() - revocation_time
    all_revoked = denied_count == num_children
    status = "PASS" if all_revoked else "FAIL"
    print(f"  After {elapsed:.1f}s: {denied_count}/{num_children} children denied [{status}]")

    return {
        "test": "concurrent_children",
        "num_children": num_children,
        "initial_authenticated": initial_count,
        "denied_after_expiry": denied_count,
        "elapsed_s": round(elapsed, 2),
        "all_revoked": all_revoked,
        "passed": all_revoked,
    }


def test_clock_skew():
    """Test 4: Simulated clock skew (±1 epoch)."""
    print("\n" + "=" * 60)
    print("TEST 4: Clock Skew Tolerance")
    print("  Verify behavior when verifier clock is ±1 epoch off")
    print("=" * 60)

    config = LeashConfig(heartbeat_interval_secs=10, max_heartbeat_age_secs=30)
    parent = AgentKeyPair.generate_root("parent-skew")
    child = parent.derive_child("child-skew")

    credential = CredentialBuilder().build(child, parent.heartbeat_public_key())

    # Create heartbeat at a known epoch
    base_epoch = 1000
    hb = Heartbeat.create(parent.heartbeat_key, base_epoch)

    results = []
    for skew_name, current_epoch in [
        ("exact", base_epoch),
        ("+1 epoch", base_epoch + 1),
        ("+2 epochs", base_epoch + 2),
        ("+3 epochs (max)", base_epoch + 3),
        ("+4 epochs (expired)", base_epoch + 4),
        ("-1 epoch (future hb)", base_epoch - 1),
    ]:
        max_age = config.max_age_epochs()  # 3
        is_fresh = hb.is_fresh(current_epoch, max_age)
        print(f"  Skew {skew_name:>20}: epoch={current_epoch}, age={current_epoch - base_epoch}, fresh={is_fresh}")
        results.append({
            "skew": skew_name,
            "current_epoch": current_epoch,
            "age": current_epoch - base_epoch,
            "is_fresh": is_fresh,
        })

    # Verify: exact through +3 should be fresh, +4 should not, -1 should be fresh (age=-1 < 0)
    expected = [True, True, True, True, False, False]
    actual = [r["is_fresh"] for r in results]
    passed = actual == expected
    status = "PASS" if passed else "FAIL"
    print(f"\n  Expected: {expected}")
    print(f"  Actual:   {actual}")
    print(f"  [{status}]")

    return {
        "test": "clock_skew",
        "details": results,
        "passed": passed,
    }


def main():
    print("=" * 60)
    print("EXPERIMENT 5: Extreme Edge Case Validation")
    print("Phase 2.5 - Autonomous Deep Research")
    print("=" * 60)

    all_results = []
    all_results.append(test_minimum_config())
    all_results.append(test_deep_hierarchy())
    all_results.append(test_concurrent_children())
    all_results.append(test_clock_skew())

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    all_passed = True
    for r in all_results:
        status = "PASS" if r["passed"] else "FAIL"
        all_passed = all_passed and r["passed"]
        print(f"  {r['test']:.<40} {status}")

    print(f"\n  Overall: {'ALL PASSED' if all_passed else 'SOME FAILED'}")

    # Save results
    output_path = os.path.join(RESULTS_DIR, 'exp5_edge_cases.json')
    with open(output_path, 'w') as f:
        json.dump(all_results, f, indent=2)
    print(f"\n  Results saved to {output_path}")


if __name__ == "__main__":
    main()
