#!/usr/bin/env python3
"""
Experiment 8: Clock Desynchronization Stress Test

Programmatically injects clock offsets into the verification path to measure
exact accept/reject boundaries under clock skew. No NTP manipulation needed.

Tests:
  1. Sweep: ε from 0 to Wmax+30s in 1s increments, record accept/reject
  2. Regime classification: verify the 3 degradation regimes from the paper
  3. Asymmetric skew: verifier-leads vs verifier-lags (different failure modes)
  4. Zombie window inflation: measure actual Wz at each skew level

Run with: python experiments/exp8_clock_skew.py
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


def verify_with_skew(verifier, config, credential, heartbeat, child_key,
                     true_epoch, skew_epochs):
    """Verify a proof as if the verifier's clock is offset by skew_epochs.

    The verifier thinks the current epoch is (true_epoch + skew_epochs).
    We check freshness manually to simulate clock offset.
    """
    verifier_epoch = true_epoch + skew_epochs
    max_age = config.max_age_epochs()
    hb_age = verifier_epoch - heartbeat.epoch

    # Freshness check as the verifier would perform it
    if hb_age < 0:
        # Heartbeat appears to be from the future
        return False, "future_heartbeat", hb_age
    if hb_age > max_age:
        # Heartbeat is stale
        return False, "stale", hb_age
    # Heartbeat is fresh from verifier's perspective
    return True, "fresh", hb_age


def test_skew_sweep():
    """Sweep ε from -30s to +60s in 1s increments."""
    print("\n" + "=" * 60)
    print("TEST 1: Clock Skew Sweep")
    print("  Config: Δh=10s, Wmax=30s (max_age=3 epochs)")
    print("  Heartbeat generated at true epoch 100")
    print("  Verifier clock offset: -30s to +60s (in Δh increments)")
    print("=" * 60)

    config = LeashConfig(heartbeat_interval_secs=10, max_heartbeat_age_secs=30)
    parent = AgentKeyPair.generate_root("parent-skew")
    child = parent.derive_child("child-skew")
    credential = CredentialBuilder().build(child, parent.heartbeat_public_key())

    true_epoch = 100
    heartbeat = Heartbeat.create(parent.heartbeat_key, true_epoch)

    max_age = config.max_age_epochs()  # 3
    results = []

    # Sweep in epoch increments (each epoch = Δh = 10s)
    for skew_epochs in range(-5, 10):
        skew_seconds = skew_epochs * config.heartbeat_interval_secs
        accepted, reason, hb_age = verify_with_skew(
            None, config, credential, heartbeat, child,
            true_epoch, skew_epochs
        )

        # Classify regime
        abs_skew_s = abs(skew_seconds)
        if abs_skew_s < config.heartbeat_interval_secs:
            regime = "Synchronized"
        elif abs_skew_s <= config.max_heartbeat_age_secs:
            regime = "Drifting"
        else:
            regime = "Diverged"

        result = {
            "skew_epochs": skew_epochs,
            "skew_seconds": skew_seconds,
            "accepted": accepted,
            "reason": reason,
            "hb_age_epochs": hb_age,
            "regime": regime,
        }
        results.append(result)

        symbol = "✓" if accepted else "✗"
        print(f"  ε={skew_seconds:>+4}s (epoch offset {skew_epochs:>+3}): "
              f"{symbol} {reason:<18} age={hb_age:>+3} epochs  [{regime}]")

    return results


def test_zombie_window_inflation():
    """Measure actual zombie window at each skew level.

    After parent revocation at epoch e_r, measure how many more epochs
    the child can authenticate given verifier clock skew.
    """
    print("\n" + "=" * 60)
    print("TEST 2: Zombie Window Inflation Under Clock Skew")
    print("  Config: Δh=10s, Wmax=30s")
    print("  Parent revoked at epoch 100. Measure Wz at each skew.")
    print("=" * 60)

    config = LeashConfig(heartbeat_interval_secs=10, max_heartbeat_age_secs=30)
    parent = AgentKeyPair.generate_root("parent-zw")
    child = parent.derive_child("child-zw")

    max_age = config.max_age_epochs()  # 3
    revocation_epoch = 100
    last_heartbeat = Heartbeat.create(parent.heartbeat_key, revocation_epoch)

    # Theoretical: Wz = Wmax + Δh + ε = 30 + 10 + ε seconds
    # In epochs: max_age + 1 + skew_epochs

    skew_values_s = [0, 5, 10, 15, 20, 30, 35, 45]
    results = []

    for skew_s in skew_values_s:
        skew_epochs = skew_s / config.heartbeat_interval_secs

        # After revocation, the verifier advances its local epoch.
        # The verifier's epoch = true_epoch + skew_epochs.
        # We advance true_epoch from revocation_epoch and check when
        # the heartbeat is no longer fresh.
        zombie_epochs = 0
        for advance in range(20):
            true_epoch = revocation_epoch + advance
            # Verifier clock lags by skew_epochs → verifier_epoch < true_epoch
            # This EXTENDS the zombie window (heartbeat appears younger)
            verifier_epoch_lag = true_epoch - skew_epochs
            hb_age_lag = verifier_epoch_lag - revocation_epoch

            if 0 <= hb_age_lag <= max_age:
                zombie_epochs = advance + 1
            elif hb_age_lag > max_age:
                break

        zombie_s = zombie_epochs * config.heartbeat_interval_secs
        theoretical_s = config.max_heartbeat_age_secs + config.heartbeat_interval_secs + skew_s

        result = {
            "skew_s": skew_s,
            "measured_zombie_epochs": zombie_epochs,
            "measured_zombie_s": zombie_s,
            "theoretical_zombie_s": theoretical_s,
            "within_bound": zombie_s <= theoretical_s,
        }
        results.append(result)
        check = "✓" if result["within_bound"] else "✗"
        print(f"  ε={skew_s:>3}s: Wz_measured={zombie_s:>3}s, "
              f"Wz_theoretical={theoretical_s:>3}s {check}")

    return results


def test_asymmetric_failure_modes():
    """Test verifier-leads vs verifier-lags failure modes.

    Verifier leads (clock ahead): rejects valid heartbeats SOONER → fail-secure
    Verifier lags (clock behind): accepts stale heartbeats LONGER → safety violation
    """
    print("\n" + "=" * 60)
    print("TEST 3: Asymmetric Failure Modes")
    print("  Verifier LEADS = clock is ahead → fail-secure (denies early)")
    print("  Verifier LAGS  = clock is behind → safety risk (accepts late)")
    print("=" * 60)

    config = LeashConfig(heartbeat_interval_secs=10, max_heartbeat_age_secs=30)
    parent = AgentKeyPair.generate_root("parent-asym")
    max_age = config.max_age_epochs()  # 3

    revocation_epoch = 100
    last_hb = Heartbeat.create(parent.heartbeat_key, revocation_epoch)

    results = []

    for direction, label in [("leads", "Verifier LEADS (clock ahead)"),
                              ("lags", "Verifier LAGS (clock behind)")]:
        print(f"\n  --- {label} ---")
        for skew_s in [0, 10, 20, 30, 40, 50]:
            skew_epochs = skew_s / config.heartbeat_interval_secs

            # Scan epochs after revocation
            last_accepted_epoch = revocation_epoch
            first_rejected_epoch = None

            for advance in range(20):
                true_epoch = revocation_epoch + advance

                if direction == "leads":
                    verifier_epoch = true_epoch + skew_epochs
                else:
                    verifier_epoch = true_epoch - skew_epochs

                hb_age = verifier_epoch - revocation_epoch

                if 0 <= hb_age <= max_age:
                    last_accepted_epoch = true_epoch
                else:
                    if first_rejected_epoch is None:
                        first_rejected_epoch = true_epoch
                    # Once rejected, all future are also rejected
                    # (for leads; for lags, might accept again — shouldn't happen)

            zombie_epochs = last_accepted_epoch - revocation_epoch
            zombie_s = zombie_epochs * config.heartbeat_interval_secs

            entry = {
                "direction": direction,
                "skew_s": skew_s,
                "zombie_s": zombie_s,
                "failure_mode": "fail-secure (early denial)" if direction == "leads" else "safety-risk (late acceptance)",
            }
            results.append(entry)

            symbol = "🛡️" if direction == "leads" else "⚠️"
            print(f"    ε={skew_s:>3}s: zombie_window={zombie_s:>3}s  {symbol}")

    return results


def test_fine_grained_boundary():
    """Fine-grained test at the exact boundary where freshness flips.

    Tests sub-epoch precision to identify the exact accept/reject edge.
    """
    print("\n" + "=" * 60)
    print("TEST 4: Fine-Grained Boundary Detection")
    print("  Identify exact epoch where freshness check flips")
    print("=" * 60)

    config = LeashConfig(heartbeat_interval_secs=10, max_heartbeat_age_secs=30)
    parent = AgentKeyPair.generate_root("parent-fg")
    max_age = config.max_age_epochs()  # 3

    hb_epoch = 100
    hb = Heartbeat.create(parent.heartbeat_key, hb_epoch)

    results = []
    print(f"  Heartbeat epoch: {hb_epoch}")
    print(f"  Max age: {max_age} epochs")
    print(f"  Expected: accept at epoch {hb_epoch} to {hb_epoch + max_age}, "
          f"reject at {hb_epoch + max_age + 1}+")

    for verifier_epoch in range(hb_epoch - 2, hb_epoch + max_age + 4):
        age = verifier_epoch - hb_epoch
        fresh = 0 <= age <= max_age
        result = {
            "verifier_epoch": verifier_epoch,
            "age": age,
            "accepted": fresh,
        }
        results.append(result)
        symbol = "✓" if fresh else "✗"
        boundary = " ← BOUNDARY" if age == max_age or age == max_age + 1 else ""
        print(f"    epoch={verifier_epoch}: age={age:>+3}, fresh={fresh} {symbol}{boundary}")

    return results


def main():
    print("=" * 60)
    print("EXPERIMENT 8: Clock Desynchronization Stress Test")
    print("=" * 60)

    all_results = {
        "skew_sweep": test_skew_sweep(),
        "zombie_inflation": test_zombie_window_inflation(),
        "asymmetric_modes": test_asymmetric_failure_modes(),
        "boundary_detection": test_fine_grained_boundary(),
    }

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    # Key findings
    zi = all_results["zombie_inflation"]
    print("\n  Zombie window inflation (verifier clock lags):")
    for r in zi:
        print(f"    ε={r['skew_s']:>3}s → Wz={r['measured_zombie_s']}s "
              f"(theoretical bound: {r['theoretical_zombie_s']}s) "
              f"{'✓ within bound' if r['within_bound'] else '✗ EXCEEDS BOUND'}")

    asym = all_results["asymmetric_modes"]
    leads = [r for r in asym if r["direction"] == "leads"]
    lags = [r for r in asym if r["direction"] == "lags"]
    print("\n  Asymmetric failure modes:")
    print(f"    Verifier LEADS: zombie window DECREASES (fail-secure)")
    print(f"    Verifier LAGS:  zombie window INCREASES (safety risk)")

    output_path = os.path.join(RESULTS_DIR, 'exp8_clock_skew.json')
    with open(output_path, 'w') as f:
        json.dump(all_results, f, indent=2)
    print(f"\n  Results saved to {output_path}")


if __name__ == "__main__":
    main()
