#!/usr/bin/env python3
"""
Experiment 3: Measure cryptographic operation latency.

Hypothesis: All operations complete in <100ms on standard hardware,
making LEASH practical for resource-constrained edge devices.

Run with: python experiments/exp3_performance.py
"""

import time
import statistics
import sys
sys.path.insert(0, '..')

from leash import LeashConfig
from leash.keys import AgentKeyPair
from leash.heartbeat import Heartbeat
from leash.credentials import CredentialBuilder, CredentialProof
from leash.verification import Verifier, generate_challenge


def benchmark(name: str, func, iterations: int = 100):
    """Run a benchmark and return statistics."""
    times = []
    
    # Warmup
    for _ in range(5):
        func()
    
    # Actual benchmark
    for _ in range(iterations):
        start = time.perf_counter()
        func()
        end = time.perf_counter()
        times.append((end - start) * 1000)  # Convert to ms
    
    return {
        "name": name,
        "iterations": iterations,
        "mean_ms": statistics.mean(times),
        "std_ms": statistics.stdev(times) if len(times) > 1 else 0,
        "min_ms": min(times),
        "max_ms": max(times),
        "p99_ms": sorted(times)[int(iterations * 0.99)] if iterations >= 100 else max(times),
    }


def run_benchmarks():
    print("=" * 70)
    print("EXPERIMENT 3: Performance Benchmarks")
    print("=" * 70)
    print("\nHypothesis: All LEASH operations complete in <100ms")
    print("(enabling use on resource-constrained edge devices)\n")
    
    # Setup test fixtures
    config = LeashConfig()
    parent = AgentKeyPair.generate_root("parent")
    child = parent.derive_child("child")
    verifier = Verifier(config)
    verifier.trust_parent("parent", parent.heartbeat_public_key())
    credential = CredentialBuilder().build(child, parent.heartbeat_public_key())
    heartbeat = Heartbeat.create(parent.heartbeat_key, verifier.current_epoch())
    challenge = generate_challenge()
    proof = CredentialProof.create(credential, heartbeat, challenge, child.identity_key)
    
    # Define benchmarks
    benchmarks = [
        ("Key Generation (root)", 
         lambda: AgentKeyPair.generate_root("test")),
        
        ("Child Key Derivation", 
         lambda: parent.derive_child("test-child")),
        
        ("Heartbeat Generation", 
         lambda: Heartbeat.create(parent.heartbeat_key, 100)),
        
        ("Heartbeat Verification", 
         lambda: heartbeat.verify()),
        
        ("Credential Creation", 
         lambda: CredentialBuilder().build(child, parent.heartbeat_public_key())),
        
        ("Proof Creation", 
         lambda: CredentialProof.create(credential, heartbeat, challenge, child.identity_key)),
        
        ("Full Verification", 
         lambda: verifier.verify(proof, challenge)),
        
        ("Challenge Generation", 
         lambda: generate_challenge()),
    ]
    
    iterations = 100
    print(f"Running {iterations} iterations per operation...\n")
    
    print(f"{'Operation':<25} | {'Mean':<8} | {'Std':<8} | {'P99':<8} | {'Max':<8}")
    print(f"{'':<25} | {'(ms)':<8} | {'(ms)':<8} | {'(ms)':<8} | {'(ms)':<8}")
    print("-" * 70)
    
    results = []
    all_under_threshold = True
    threshold_ms = 100  # 100ms threshold
    
    for name, func in benchmarks:
        result = benchmark(name, func, iterations)
        results.append(result)
        
        under_threshold = result['max_ms'] < threshold_ms
        all_under_threshold = all_under_threshold and under_threshold
        
        marker = "✓" if under_threshold else "✗"
        print(f"{result['name']:<25} | {result['mean_ms']:<8.3f} | {result['std_ms']:<8.3f} | {result['p99_ms']:<8.3f} | {result['max_ms']:<8.3f} {marker}")
    
    print("\n" + "=" * 70)
    print("RESULTS SUMMARY")
    print("=" * 70)
    
    # Calculate totals for a complete auth flow
    auth_flow_ops = ["Heartbeat Generation", "Proof Creation", "Full Verification"]
    auth_flow_total = sum(r['mean_ms'] for r in results if r['name'] in auth_flow_ops)
    
    print(f"\nComplete authentication flow (heartbeat + proof + verify):")
    print(f"  Total latency: {auth_flow_total:.3f}ms")
    
    if all_under_threshold:
        print(f"\n✓ HYPOTHESIS CONFIRMED")
        print(f"  All operations complete in <{threshold_ms}ms on this hardware.")
    else:
        print(f"\n⚠ Some operations exceeded {threshold_ms}ms threshold")
    
    print("\n" + "-" * 70)
    print("EXTRAPOLATION TO CONSTRAINED DEVICES")
    print("-" * 70)
    
    # Estimate for constrained devices (typically 10-50x slower)
    slowdown_factors = [
        ("Raspberry Pi 4", 5),
        ("Raspberry Pi Zero", 20),
        ("ESP32", 50),
    ]
    
    print(f"\n{'Device':<20} | {'Slowdown':<10} | {'Auth Flow':<12} | {'Under 100ms?':<12}")
    print("-" * 60)
    
    for device, factor in slowdown_factors:
        estimated = auth_flow_total * factor
        under = "✓ Yes" if estimated < 100 else "✗ No"
        print(f"{device:<20} | {factor}x{'':<8} | {estimated:<10.1f}ms | {under}")
    
    print("\n" + "-" * 70)
    print("COMMUNICATION OVERHEAD")
    print("-" * 70)
    
    # Heartbeat size calculation
    heartbeat_size = 32 + 64 + 8 + 64  # commitment + signature + epoch + pubkey
    print(f"\nHeartbeat size: ~{heartbeat_size} bytes")
    print(f"At 10s interval: {heartbeat_size / 10:.1f} bytes/second per parent-child pair")
    print(f"For 100 children: {heartbeat_size * 100 / 10:.0f} bytes/second = {heartbeat_size * 100 / 10 / 1024:.2f} KB/s")


if __name__ == "__main__":
    run_benchmarks()
