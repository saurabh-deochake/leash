#!/usr/bin/env python3
"""
Experiment 19: Gossip-Based Heartbeat Propagation FPRR

Characterizes false-positive revocation rates when heartbeats are
distributed via gossip (peer-to-peer forwarding) rather than direct
push from parent to each child.

Key question: does correlated loss in gossip overlays increase FPRR
beyond the independent-loss model used in Experiment 7?

Design:
  - N=100 agents in a random gossip overlay
  - Parent sends heartbeat to a seed set
  - Each agent forwards to k random peers with probability (1 - drop_rate)
  - Measure: fraction of agents that never receive the heartbeat (FPRR)
  - Compare against Experiment 7 independent-loss baseline

Run with: python experiments/exp19_gossip_fprr.py
"""

import random
import statistics
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

RESULTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'results')
os.makedirs(RESULTS_DIR, exist_ok=True)

# Experiment 7 baselines for comparison (independent-loss model)
EXP7_INDEPENDENT_FPRR = {
    0.0: 0.0,
    0.01: 0.01,
    0.05: 0.07,
    0.10: 0.15,
    0.20: 0.39,
    0.30: 1.24,
}


def build_gossip_overlay(n: int, fanout: int, rng: random.Random) -> dict[int, list[int]]:
    """
    Build a random gossip overlay where each node has `fanout` random peers.

    Returns:
        dict mapping node_id -> list of peer node_ids
    """
    peers = {}
    for i in range(n):
        candidates = [j for j in range(n) if j != i]
        peers[i] = rng.sample(candidates, min(fanout, len(candidates)))
    return peers


def simulate_gossip_epoch(
    n: int,
    peers: dict[int, list[int]],
    seed_set: list[int],
    drop_rate: float,
    max_rounds: int,
    rng: random.Random,
) -> set[int]:
    """
    Simulate one epoch of gossip heartbeat propagation.

    The parent delivers the heartbeat to the seed set directly.
    Then for `max_rounds` rounds, each agent that has the heartbeat
    forwards it to each of its peers with probability (1 - drop_rate).

    Returns:
        Set of agent IDs that received the heartbeat
    """
    received = set()

    # Parent -> seed set (direct delivery, no drop)
    for s in seed_set:
        received.add(s)

    # Gossip rounds
    for _round in range(max_rounds):
        new_received = set()
        for sender in list(received):
            for peer in peers[sender]:
                if peer not in received and peer not in new_received:
                    if rng.random() > drop_rate:
                        new_received.add(peer)
        if not new_received:
            break  # Convergence
        received.update(new_received)

    return received


def run_gossip_fprr(
    n: int = 100,
    fanout: int = 3,
    seed_count: int = 5,
    drop_rate: float = 0.0,
    num_epochs: int = 200,
    max_rounds: int = 20,
    max_age_epochs: int = 3,
    seed: int = 42,
) -> dict:
    """
    Run a full FPRR measurement over multiple epochs.

    For each epoch, simulate gossip propagation. An agent experiences
    a false-positive denial if it fails to receive a heartbeat for
    (max_age_epochs + 1) consecutive epochs.

    Returns:
        dict with FPRR and related metrics
    """
    rng = random.Random(seed)
    peers = build_gossip_overlay(n, fanout, rng)

    # Seed set: fixed set of well-connected nodes
    seed_set = list(range(seed_count))

    # Track consecutive missed epochs per agent
    consecutive_missed = [0] * n
    false_denials = 0
    total_auth_attempts = 0
    max_consecutive_missed_all = [0] * n
    coverage_per_epoch = []

    for epoch in range(num_epochs):
        received = simulate_gossip_epoch(n, peers, seed_set, drop_rate, max_rounds, rng)
        coverage_per_epoch.append(len(received))

        for agent in range(n):
            if agent in received:
                consecutive_missed[agent] = 0
            else:
                consecutive_missed[agent] += 1
                max_consecutive_missed_all[agent] = max(
                    max_consecutive_missed_all[agent],
                    consecutive_missed[agent],
                )

            # Auth attempt: denied if missed > max_age_epochs consecutive
            total_auth_attempts += 1
            if consecutive_missed[agent] > max_age_epochs:
                false_denials += 1

    fprr = (false_denials / total_auth_attempts) * 100 if total_auth_attempts > 0 else 0.0
    mean_coverage = statistics.mean(coverage_per_epoch)
    min_coverage = min(coverage_per_epoch)

    return {
        "n": n,
        "fanout": fanout,
        "seed_count": seed_count,
        "drop_rate": drop_rate,
        "num_epochs": num_epochs,
        "max_age_epochs": max_age_epochs,
        "fprr_pct": round(fprr, 4),
        "false_denials": false_denials,
        "total_auth_attempts": total_auth_attempts,
        "mean_coverage": round(mean_coverage, 1),
        "min_coverage": min_coverage,
        "max_consecutive_missed_mean": round(
            statistics.mean(max_consecutive_missed_all), 2
        ),
        "max_consecutive_missed_max": max(max_consecutive_missed_all),
    }


def test_drop_rates():
    """Sweep per-hop drop rates and compare against Experiment 7."""
    print("\n" + "=" * 60)
    print("TEST 1: Gossip FPRR vs. Per-Hop Drop Rate")
    print("  (k=3 fanout, 5 seed nodes, N=100, 200 epochs)")
    print("=" * 60)

    drop_rates = [0.0, 0.05, 0.10, 0.20, 0.30]
    results = []

    for dr in drop_rates:
        r = run_gossip_fprr(drop_rate=dr, fanout=3, seed_count=5)
        exp7_ref = EXP7_INDEPENDENT_FPRR.get(dr, "N/A")
        results.append(r)
        print(f"  drop={dr:.0%}: gossip_FPRR={r['fprr_pct']:.4f}%, "
              f"exp7_independent={exp7_ref}%, "
              f"coverage={r['mean_coverage']:.0f}/{r['n']}, "
              f"max_consec_miss={r['max_consecutive_missed_max']}")

    return results


def test_fanout_sensitivity():
    """Measure FPRR at 10% drop rate with varying fan-out."""
    print("\n" + "=" * 60)
    print("TEST 2: Fan-Out Sensitivity (drop=10%, 5 seeds)")
    print("=" * 60)

    fanouts = [2, 3, 5, 8]
    results = []

    for k in fanouts:
        r = run_gossip_fprr(drop_rate=0.10, fanout=k, seed_count=5)
        results.append(r)
        print(f"  k={k}: FPRR={r['fprr_pct']:.4f}%, "
              f"coverage={r['mean_coverage']:.0f}/{r['n']}, "
              f"max_consec={r['max_consecutive_missed_max']}")

    return results


def test_seed_count_sensitivity():
    """Measure FPRR at 10% drop rate with varying seed set sizes."""
    print("\n" + "=" * 60)
    print("TEST 3: Seed Count Sensitivity (drop=10%, k=3)")
    print("=" * 60)

    seed_counts = [1, 3, 5, 10, 20]
    results = []

    for sc in seed_counts:
        r = run_gossip_fprr(drop_rate=0.10, fanout=3, seed_count=sc)
        results.append(r)
        print(f"  seeds={sc:>2}: FPRR={r['fprr_pct']:.4f}%, "
              f"coverage={r['mean_coverage']:.0f}/{r['n']}, "
              f"max_consec={r['max_consecutive_missed_max']}")

    return results


def test_high_loss_comparison():
    """Compare gossip vs. independent-loss at extreme drop rates."""
    print("\n" + "=" * 60)
    print("TEST 4: Gossip vs. Independent-Loss at High Drop Rates")
    print("  (k=3, 5 seeds vs. k=5, 10 seeds)")
    print("=" * 60)

    configs = [
        {"fanout": 3, "seed_count": 5, "label": "k=3, 5 seeds"},
        {"fanout": 5, "seed_count": 10, "label": "k=5, 10 seeds"},
    ]
    drop_rates = [0.10, 0.20, 0.30]
    results = []

    for cfg in configs:
        print(f"\n  Config: {cfg['label']}")
        for dr in drop_rates:
            r = run_gossip_fprr(
                drop_rate=dr, fanout=cfg["fanout"], seed_count=cfg["seed_count"]
            )
            r["config_label"] = cfg["label"]
            exp7_ref = EXP7_INDEPENDENT_FPRR.get(dr, "N/A")
            results.append(r)
            print(f"    drop={dr:.0%}: gossip={r['fprr_pct']:.4f}%, "
                  f"independent={exp7_ref}%")

    return results


def main():
    print("=" * 60)
    print("EXPERIMENT 19: Gossip-Based Heartbeat Propagation FPRR")
    print("=" * 60)

    all_results = {
        "drop_rate_sweep": test_drop_rates(),
        "fanout_sensitivity": test_fanout_sensitivity(),
        "seed_count_sensitivity": test_seed_count_sensitivity(),
        "high_loss_comparison": test_high_loss_comparison(),
    }

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY: Gossip FPRR vs. Experiment 7 Independent-Loss")
    print("=" * 60)

    print("\n  Drop Rate | Gossip (k=3) | Independent (Exp 7)")
    print("  " + "-" * 50)
    for r in all_results["drop_rate_sweep"]:
        dr = r["drop_rate"]
        exp7 = EXP7_INDEPENDENT_FPRR.get(dr, "N/A")
        ratio = f"{r['fprr_pct'] / exp7:.1f}x" if isinstance(exp7, (int, float)) and exp7 > 0 else "—"
        print(f"  {dr:>8.0%}  | {r['fprr_pct']:>11.4f}% | {exp7}%  ({ratio})")

    print("\n  Key finding: Gossip FPRR is {'HIGHER' if any(r['fprr_pct'] > EXP7_INDEPENDENT_FPRR.get(r['drop_rate'], 0) for r in all_results['drop_rate_sweep']) else 'COMPARABLE'} "
          "than independent-loss at elevated drop rates due to correlated forwarding failures.")

    # Save
    output_path = os.path.join(RESULTS_DIR, 'exp19_gossip_fprr.json')
    with open(output_path, 'w') as f:
        json.dump(all_results, f, indent=2)
    print(f"\n  Results saved to {output_path}")


if __name__ == "__main__":
    main()
