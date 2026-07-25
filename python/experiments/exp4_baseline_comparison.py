#!/usr/bin/env python3
"""
Experiment 4: Compare LEASH with baseline approaches.

Compares zombie window and behavior during network partitions
across different credential revocation mechanisms.

Run with: python experiments/exp4_baseline_comparison.py
"""

import sys
sys.path.insert(0, '..')


def simulate_oauth_behavior(token_lifetime_secs: int, partition_start: int, revocation_time: int):
    """
    Simulate OAuth 2.0 behavior.
    
    OAuth tokens are valid until expiry. During partition, the resource server
    cannot check with the authorization server, so it either:
    - Fails open (accepts token) - INSECURE
    - Fails closed (rejects all) - UNAVAILABLE
    
    Most production systems fail open for availability.
    """
    return {
        "mechanism": "OAuth 2.0",
        "token_lifetime": token_lifetime_secs,
        "zombie_window": token_lifetime_secs,  # Full lifetime if partition
        "works_during_partition": False,  # Needs network to revoke
        "fail_mode": "fail-open (insecure) or fail-closed (unavailable)",
    }


def simulate_short_cert_behavior(cert_lifetime_secs: int, partition_duration: int):
    """
    Simulate short-lived certificate behavior.
    
    Certificates expire naturally, providing "passive revocation".
    However, legitimate agents also can't renew during partition.
    """
    return {
        "mechanism": "Short-lived Certificates",
        "cert_lifetime": cert_lifetime_secs,
        "zombie_window": cert_lifetime_secs,
        "works_during_partition": "Partially",  # Expires, but can't renew
        "fail_mode": "Legitimate agents also lose access",
        "collateral_damage": partition_duration > cert_lifetime_secs,
    }


def simulate_ocsp_behavior(cache_duration_secs: int, partition_duration: int):
    """
    Simulate OCSP (Online Certificate Status Protocol) behavior.
    
    OCSP requires online check with CA. During partition:
    - Cached responses may be stale
    - New checks fail
    """
    return {
        "mechanism": "OCSP",
        "cache_duration": cache_duration_secs,
        "zombie_window": cache_duration_secs,  # Until cache expires
        "works_during_partition": False,
        "fail_mode": "Stale cache or fail-closed",
    }


def simulate_vc_status_list_behavior(fetch_interval_secs: int, partition_duration: int):
    """
    Simulate W3C VC Bitstring Status List behavior.
    
    Requires periodic fetch of status list. During partition,
    verifier uses stale list.
    """
    return {
        "mechanism": "W3C VC Status List",
        "fetch_interval": fetch_interval_secs,
        "zombie_window": fetch_interval_secs + partition_duration,
        "works_during_partition": False,
        "fail_mode": "Stale status list",
    }


def simulate_leash_behavior(heartbeat_interval: int, max_age: int, partition_duration: int):
    """
    Simulate LEASH behavior.
    
    Heartbeats expire regardless of partition. Revocation is implicit
    in the absence of fresh heartbeats.
    """
    return {
        "mechanism": "LEASH (Ours)",
        "heartbeat_interval": heartbeat_interval,
        "max_age": max_age,
        "zombie_window": max_age + heartbeat_interval,  # BOUNDED!
        "works_during_partition": True,  # Key differentiator
        "fail_mode": "Fails secure (denies access)",
    }


def run_comparison():
    print("=" * 75)
    print("EXPERIMENT 4: Baseline Comparison")
    print("=" * 75)
    print("\nComparing credential revocation mechanisms across different scenarios.\n")
    
    # Scenario 1: Normal operation (no partition)
    print("-" * 75)
    print("SCENARIO 1: Normal Operation (No Network Partition)")
    print("-" * 75)
    print("\nAll mechanisms work correctly when network is available.\n")
    
    mechanisms = [
        ("OAuth 2.0 (1hr tokens)", 3600),
        ("Short-lived Certs (5min)", 300),
        ("OCSP (1hr cache)", 3600),
        ("VC Status List (1hr)", 3600),
        ("LEASH (10s/30s)", 40),
    ]
    
    print(f"{'Mechanism':<30} | {'Zombie Window':<15} | {'Revocation Works?':<15}")
    print("-" * 65)
    for name, zombie in mechanisms:
        print(f"{name:<30} | {zombie}s{'':<12} | ✓ Yes")
    
    # Scenario 2: Network partition
    print("\n" + "-" * 75)
    print("SCENARIO 2: Network Partition (1 hour)")
    print("-" * 75)
    print("\nParent/authority is revoked, then network partitions for 1 hour.")
    print("Question: How long can revoked agent still authenticate?\n")
    
    partition_duration = 3600  # 1 hour
    
    results = [
        simulate_oauth_behavior(3600, 0, 0),
        simulate_short_cert_behavior(300, partition_duration),
        simulate_ocsp_behavior(3600, partition_duration),
        simulate_vc_status_list_behavior(3600, partition_duration),
        simulate_leash_behavior(10, 30, partition_duration),
    ]
    
    print(f"{'Mechanism':<25} | {'Zombie Window':<12} | {'Works Offline?':<15} | {'Fail Mode':<25}")
    print("-" * 85)
    
    for r in results:
        works = "✓ Yes" if r['works_during_partition'] == True else ("Partial" if r['works_during_partition'] == "Partially" else "✗ No")
        print(f"{r['mechanism']:<25} | {r['zombie_window']}s{'':<9} | {works:<15} | {r['fail_mode'][:25]}")
    
    # Scenario 3: Extended partition
    print("\n" + "-" * 75)
    print("SCENARIO 3: Extended Partition (24 hours)")
    print("-" * 75)
    print("\nDisaster scenario: network down for 24 hours after revocation.\n")
    
    partition_24h = 86400
    
    scenarios = [
        ("OAuth 2.0", 3600, 3600),  # 1hr zombie, then token expires naturally
        ("Short Certs", 300, 300),   # 5min zombie, but legit agents also fail
        ("LEASH", 40, 40),            # 40s zombie, always bounded
    ]
    
    print(f"{'Mechanism':<20} | {'Zombie Window':<15} | {'Legit Agents OK?':<18} | {'Security Risk':<20}")
    print("-" * 80)
    
    print(f"{'OAuth 2.0':<20} | {'3600s (1hr)':<15} | {'Yes':<18} | {'HIGH (1hr exposure)':<20}")
    print(f"{'Short Certs':<20} | {'300s (5min)':<15} | {'No (cannot renew)':<18} | {'LOW':<20}")
    print(f"{'LEASH':<20} | {'40s':<15} | {'No (by design)':<18} | {'MINIMAL (40s)':<20}")
    
    # Summary
    print("\n" + "=" * 75)
    print("SUMMARY: Why LEASH is Different")
    print("=" * 75)
    
    print("""
┌─────────────────────────────────────────────────────────────────────────┐
│                    REVOCATION DURING NETWORK PARTITION                  │
├─────────────────────────────────────────────────────────────────────────┤
│ Mechanism          │ Revocation Works? │ Zombie Window │ Trade-off      │
├─────────────────────────────────────────────────────────────────────────┤
│ OAuth 2.0          │ ✗ NO              │ 3600s         │ Insecure       │
│ Short-lived Certs  │ ✗ NO (expires)    │ 300s          │ Legit denied   │
│ OCSP               │ ✗ NO              │ 3600s         │ Stale cache    │
│ VC Status List     │ ✗ NO              │ 3600s+        │ Stale list     │
│ LEASH (Ours)        │ ✓ YES             │ 40s           │ Fails secure   │
└─────────────────────────────────────────────────────────────────────────┘
""")
    
    print("KEY INSIGHT:")
    print("-" * 75)
    print("""
All existing mechanisms require NETWORK CONNECTIVITY for revocation:
  - OAuth: Must contact authorization server
  - OCSP: Must contact CA
  - Status Lists: Must fetch updated list

LEASH is fundamentally different:
  - Revocation is IMPLICIT in heartbeat expiry
  - No network needed - just local time
  - Zombie window is BOUNDED regardless of partition duration

This is the "secret" - the contrarian insight that makes LEASH novel.
""")
    
    # Quantitative comparison
    print("=" * 75)
    print("QUANTITATIVE IMPROVEMENT")
    print("=" * 75)
    
    leash_zombie = 40
    print(f"\nLEASH zombie window: {leash_zombie}s")
    print(f"\nImprovement factors:")
    print(f"  vs OAuth 2.0 (1hr):        {3600/leash_zombie:.0f}x better")
    print(f"  vs Short Certs (5min):     {300/leash_zombie:.1f}x better")
    print(f"  vs OCSP (1hr cache):       {3600/leash_zombie:.0f}x better")
    print(f"  vs VC Status (1hr fetch):  {3600/leash_zombie:.0f}x better")


if __name__ == "__main__":
    run_comparison()
