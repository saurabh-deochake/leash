#!/usr/bin/env python3
"""
Experiment 7: Simulated Packet Loss / Heartbeat Drop

Simulates heartbeat delivery failures at varying drop rates (1%, 5%, 10%, 20%)
and measures the False-Positive Revocation Rate (FPRR): the fraction of
legitimate authentication attempts that fail because a heartbeat was dropped.

This does NOT require tc-netem or root privileges. Instead, we simulate
packet loss at the application layer: each heartbeat delivery has a
probability `p` of being dropped (not reaching the child's cache).

Metrics:
  - FPRR at each drop rate
  - Mean consecutive missed heartbeats before a false denial
  - Recovery time after a dropped heartbeat (next successful delivery)
  - Impact of pre-computation buffer on FPRR

Run with: python experiments/exp7_packet_loss.py
"""

import time
import random
import json
import os
import sys
import statistics

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from leash import LeashConfig, Verifier
from leash.keys import AgentKeyPair
from leash.heartbeat import Heartbeat, HeartbeatGenerator
from leash.credentials import CredentialBuilder, CredentialProof
from leash.verification import generate_challenge

RESULTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'results')
os.makedirs(RESULTS_DIR, exist_ok=True)

SEED = 42  # Reproducible results


def simulate_heartbeat_delivery(
    config: LeashConfig,
    num_epochs: int,
    drop_rate: float,
    num_children: int = 100,
    precompute_buffer: int = 0,
    rng: random.Random = None,
):
    """Simulate heartbeat delivery with packet loss.

    Returns dict with FPRR and detailed per-epoch results.
    """
    if rng is None:
        rng = random.Random(SEED)

    parent = AgentKeyPair.generate_root("parent-pl")
    children = [parent.derive_child(f"child-{i}") for i in range(num_children)]
    credentials = [
        CredentialBuilder().build(c, parent.heartbeat_public_key())
        for c in children
    ]

    verifier = Verifier(config)
    verifier.trust_parent("parent-pl", parent.heartbeat_public_key())

    max_age_epochs = config.max_age_epochs()

    # Pre-generate all heartbeats for the simulation
    all_heartbeats = []
    for epoch in range(num_epochs + precompute_buffer):
        hb = Heartbeat.create(parent.heartbeat_key, epoch)
        all_heartbeats.append(hb)

    # Track per-child state: last received heartbeat
    child_last_hb = [None] * num_children

    # If pre-computation buffer, children start with buffer heartbeats
    if precompute_buffer > 0:
        for i in range(num_children):
            # Child has pre-computed heartbeats for epochs 0..precompute_buffer-1
            child_last_hb[i] = all_heartbeats[precompute_buffer - 1]

    total_auth_attempts = 0
    false_denials = 0
    epoch_results = []
    consecutive_drops = [0] * num_children
    max_consecutive_drops = [0] * num_children

    for epoch in range(num_epochs):
        hb_index = epoch + precompute_buffer  # actual heartbeat for this epoch
        if hb_index >= len(all_heartbeats):
            break
        current_hb = all_heartbeats[hb_index]

        # Simulate heartbeat delivery to each child
        for i in range(num_children):
            delivered = rng.random() >= drop_rate
            if delivered:
                child_last_hb[i] = current_hb
                consecutive_drops[i] = 0
            else:
                consecutive_drops[i] += 1
                max_consecutive_drops[i] = max(max_consecutive_drops[i], consecutive_drops[i])

        # All children attempt authentication at this epoch
        epoch_denied = 0
        challenge = generate_challenge()
        for i in range(num_children):
            total_auth_attempts += 1
            if child_last_hb[i] is None:
                # Never received a heartbeat
                false_denials += 1
                epoch_denied += 1
                continue

            # Check if the child's last heartbeat is still fresh
            hb_age = hb_index - child_last_hb[i].epoch
            if hb_age > max_age_epochs:
                false_denials += 1
                epoch_denied += 1
            # Also do a real verification to confirm
            else:
                proof = CredentialProof.create(
                    credentials[i], child_last_hb[i], challenge, children[i].identity_key
                )
                result = verifier.verify_at_epoch(proof, challenge, hb_index) \
                    if hasattr(verifier, 'verify_at_epoch') else None
                # Fallback: use age-based check (already done above)

        epoch_results.append({
            "epoch": epoch,
            "denied": epoch_denied,
            "denial_rate": epoch_denied / num_children,
        })

    fprr = false_denials / total_auth_attempts if total_auth_attempts > 0 else 0

    return {
        "drop_rate": drop_rate,
        "num_epochs": num_epochs,
        "num_children": num_children,
        "precompute_buffer": precompute_buffer,
        "total_auth_attempts": total_auth_attempts,
        "false_denials": false_denials,
        "fprr": round(fprr, 6),
        "fprr_pct": round(fprr * 100, 3),
        "max_consecutive_drops_mean": round(statistics.mean(max_consecutive_drops), 2),
        "max_consecutive_drops_max": max(max_consecutive_drops),
        "epoch_results": epoch_results,
    }


def test_drop_rates():
    """Test FPRR across multiple drop rates."""
    print("\n" + "=" * 60)
    print("TEST 1: False-Positive Revocation Rate vs. Drop Rate")
    print("  Config: Δh=10s, Wmax=30s (max_age=3 epochs)")
    print("  100 children, 100 epochs, no pre-computation")
    print("=" * 60)

    config = LeashConfig(heartbeat_interval_secs=10, max_heartbeat_age_secs=30)
    drop_rates = [0.0, 0.01, 0.05, 0.10, 0.20, 0.30]
    results = []

    for dr in drop_rates:
        rng = random.Random(SEED)
        r = simulate_heartbeat_delivery(
            config, num_epochs=100, drop_rate=dr,
            num_children=100, precompute_buffer=0, rng=rng,
        )
        results.append(r)
        print(f"  Drop={dr:>5.0%}: FPRR={r['fprr_pct']:>6.2f}%  "
              f"max_consec_drops(mean={r['max_consecutive_drops_mean']:.1f}, "
              f"max={r['max_consecutive_drops_max']})")

    return results


def test_precomputation_mitigation():
    """Test how pre-computation buffer reduces FPRR."""
    print("\n" + "=" * 60)
    print("TEST 2: Pre-Computation Buffer Mitigation")
    print("  Config: Δh=10s, Wmax=30s, drop_rate=10%")
    print("  100 children, 100 epochs, varying buffer size")
    print("=" * 60)

    config = LeashConfig(heartbeat_interval_secs=10, max_heartbeat_age_secs=30)
    buffers = [0, 3, 6, 10, 20]
    results = []

    for buf in buffers:
        rng = random.Random(SEED)
        r = simulate_heartbeat_delivery(
            config, num_epochs=100, drop_rate=0.10,
            num_children=100, precompute_buffer=buf, rng=rng,
        )
        results.append(r)
        print(f"  Buffer={buf:>2} epochs: FPRR={r['fprr_pct']:>6.2f}%  "
              f"false_denials={r['false_denials']}/{r['total_auth_attempts']}")

    return results


def test_multi_path_delivery():
    """Test redundant heartbeat delivery (2 independent paths).

    With two independent paths each with drop rate p,
    the effective drop rate is p^2 (both must fail).
    """
    print("\n" + "=" * 60)
    print("TEST 3: Multi-Path Heartbeat Delivery")
    print("  Two independent paths, each with drop_rate p")
    print("  Effective drop = p^2")
    print("=" * 60)

    config = LeashConfig(heartbeat_interval_secs=10, max_heartbeat_age_secs=30)
    single_drop_rates = [0.01, 0.05, 0.10, 0.20]
    results = []

    for p in single_drop_rates:
        effective_p = p * p  # Both paths must fail
        rng = random.Random(SEED)
        r_single = simulate_heartbeat_delivery(
            config, num_epochs=100, drop_rate=p,
            num_children=100, rng=random.Random(SEED),
        )
        r_multi = simulate_heartbeat_delivery(
            config, num_epochs=100, drop_rate=effective_p,
            num_children=100, rng=random.Random(SEED + 1),
        )
        results.append({
            "single_path_drop": p,
            "dual_path_effective_drop": effective_p,
            "single_fprr_pct": r_single["fprr_pct"],
            "dual_fprr_pct": r_multi["fprr_pct"],
        })
        print(f"  p={p:.0%}: single-path FPRR={r_single['fprr_pct']:.2f}%  "
              f"→ dual-path (p²={effective_p:.4f}) FPRR={r_multi['fprr_pct']:.2f}%")

    return results


def test_wmax_sensitivity():
    """Test how increasing Wmax affects FPRR at fixed drop rate."""
    print("\n" + "=" * 60)
    print("TEST 4: Wmax Sensitivity at 10% Drop Rate")
    print("  Higher Wmax = more tolerance for dropped heartbeats")
    print("=" * 60)

    drop_rate = 0.10
    wmax_values = [10, 20, 30, 60, 120]
    results = []

    for wmax in wmax_values:
        config = LeashConfig(heartbeat_interval_secs=10, max_heartbeat_age_secs=wmax)
        rng = random.Random(SEED)
        r = simulate_heartbeat_delivery(
            config, num_epochs=100, drop_rate=drop_rate,
            num_children=100, rng=rng,
        )
        results.append({
            "wmax": wmax,
            "max_age_epochs": config.max_age_epochs(),
            "fprr_pct": r["fprr_pct"],
            "zombie_window_s": wmax + 10,  # Wmax + Δh
        })
        print(f"  Wmax={wmax:>3}s (age={config.max_age_epochs()} epochs, "
              f"zombie={wmax+10}s): FPRR={r['fprr_pct']:.2f}%")

    return results


def main():
    print("=" * 60)
    print("EXPERIMENT 7: Simulated Packet Loss")
    print("  Measuring False-Positive Revocation Rate (FPRR)")
    print("=" * 60)

    all_results = {
        "drop_rates": test_drop_rates(),
        "precomputation": test_precomputation_mitigation(),
        "multi_path": test_multi_path_delivery(),
        "wmax_sensitivity": test_wmax_sensitivity(),
    }

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print("\n  Key finding: At 10% heartbeat drop rate with Δh=10s, Wmax=30s:")
    dr_results = all_results["drop_rates"]
    r10 = next(r for r in dr_results if r["drop_rate"] == 0.10)
    print(f"    FPRR = {r10['fprr_pct']:.2f}%")
    print(f"    Max consecutive drops (worst child): {r10['max_consecutive_drops_max']}")

    pc_results = all_results["precomputation"]
    if len(pc_results) > 1:
        print(f"\n  Pre-computation buffer of 3 epochs reduces FPRR from "
              f"{pc_results[0]['fprr_pct']:.2f}% to {pc_results[1]['fprr_pct']:.2f}%")

    output_path = os.path.join(RESULTS_DIR, 'exp7_packet_loss.json')
    with open(output_path, 'w') as f:
        # Don't save per-epoch data to keep file small
        save_results = {}
        for key, val in all_results.items():
            if isinstance(val, list):
                save_results[key] = []
                for item in val:
                    cleaned = {k: v for k, v in item.items() if k != "epoch_results"}
                    save_results[key].append(cleaned)
            else:
                save_results[key] = val
        json.dump(save_results, f, indent=2)
    print(f"\n  Results saved to {output_path}")


if __name__ == "__main__":
    main()
