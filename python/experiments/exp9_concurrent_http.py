#!/usr/bin/env python3
"""
Experiment 9: Concurrent HTTP Verifier Benchmark

Wraps LEASH verification in a FastAPI endpoint and measures P99 latency
under concurrent load using async HTTP clients.

Tests:
  1. Single-threaded baseline (no concurrency)
  2. Concurrent verification at 10, 50, 100, 500, 1000 simultaneous requests
  3. Sustained throughput test (requests/sec over 10 seconds)
  4. P99/P999 latency under load

Run with: python experiments/exp9_concurrent_http.py
"""

import asyncio
import json
import multiprocessing
import os
import signal
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

RESULTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'results')
os.makedirs(RESULTS_DIR, exist_ok=True)

# Port for the test server
TEST_PORT = 18923


def run_server():
    """Run FastAPI verification server in a subprocess."""
    import uvicorn
    from fastapi import FastAPI, HTTPException
    from pydantic import BaseModel

    from leash import LeashConfig, Verifier
    from leash.keys import AgentKeyPair
    from leash.heartbeat import Heartbeat
    from leash.credentials import CredentialBuilder, CredentialProof
    from leash.verification import generate_challenge

    app = FastAPI()

    # Pre-initialize crypto fixtures (shared across requests)
    config = LeashConfig(heartbeat_interval_secs=10, max_heartbeat_age_secs=30)
    parent = AgentKeyPair.generate_root("parent-http")
    child = parent.derive_child("child-http")
    verifier = Verifier(config)
    verifier.trust_parent("parent-http", parent.heartbeat_public_key())
    credential = CredentialBuilder().build(child, parent.heartbeat_public_key())

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/verify")
    def verify_endpoint():
        """Full LEASH verification: generate heartbeat, create proof, verify."""
        t0 = time.perf_counter()

        # Generate fresh heartbeat (simulates parent heartbeat delivery)
        hb = Heartbeat.create(parent.heartbeat_key, verifier.current_epoch())
        challenge = generate_challenge()
        proof = CredentialProof.create(credential, hb, challenge, child.identity_key)
        result = verifier.verify(proof, challenge)

        elapsed_ms = (time.perf_counter() - t0) * 1000

        return {
            "valid": result.valid,
            "latency_ms": round(elapsed_ms, 3),
        }

    uvicorn.run(app, host="127.0.0.1", port=TEST_PORT, log_level="error")


async def wait_for_server(timeout=10):
    """Wait for the server to be ready."""
    import httpx
    start = time.time()
    async with httpx.AsyncClient() as client:
        while time.time() - start < timeout:
            try:
                r = await client.get(f"http://127.0.0.1:{TEST_PORT}/health")
                if r.status_code == 200:
                    return True
            except Exception:
                pass
            await asyncio.sleep(0.1)
    return False


async def benchmark_concurrent(concurrency: int, total_requests: int):
    """Send total_requests to the verify endpoint with given concurrency."""
    import httpx

    latencies = []
    errors = 0
    semaphore = asyncio.Semaphore(concurrency)

    async def make_request(client):
        nonlocal errors
        async with semaphore:
            try:
                t0 = time.perf_counter()
                r = await client.post(f"http://127.0.0.1:{TEST_PORT}/verify")
                elapsed = (time.perf_counter() - t0) * 1000
                if r.status_code == 200:
                    latencies.append(elapsed)
                else:
                    errors += 1
            except Exception:
                errors += 1

    async with httpx.AsyncClient(timeout=30.0) as client:
        t_start = time.perf_counter()
        tasks = [make_request(client) for _ in range(total_requests)]
        await asyncio.gather(*tasks)
        total_time = time.perf_counter() - t_start

    if not latencies:
        return {
            "concurrency": concurrency,
            "total_requests": total_requests,
            "errors": errors,
            "error": "no successful requests",
        }

    latencies.sort()
    n = len(latencies)

    return {
        "concurrency": concurrency,
        "total_requests": total_requests,
        "successful": n,
        "errors": errors,
        "total_time_s": round(total_time, 3),
        "throughput_rps": round(n / total_time, 1),
        "mean_ms": round(statistics.mean(latencies), 3),
        "median_ms": round(latencies[n // 2], 3),
        "p90_ms": round(latencies[int(n * 0.90)], 3),
        "p99_ms": round(latencies[int(n * 0.99)], 3),
        "p999_ms": round(latencies[min(int(n * 0.999), n - 1)], 3),
        "max_ms": round(latencies[-1], 3),
        "min_ms": round(latencies[0], 3),
    }


async def run_benchmarks():
    """Run all concurrency benchmarks."""
    print("\n  Waiting for server to start...")
    ready = await wait_for_server()
    if not ready:
        print("  ERROR: Server failed to start!")
        return None

    print("  Server is ready.\n")

    # Test 1: Baseline (sequential)
    print("=" * 60)
    print("TEST 1: Sequential Baseline (concurrency=1)")
    print("=" * 60)
    baseline = await benchmark_concurrent(concurrency=1, total_requests=100)
    print(f"  mean={baseline['mean_ms']:.2f}ms, p99={baseline['p99_ms']:.2f}ms, "
          f"throughput={baseline['throughput_rps']:.0f} rps")

    # Test 2: Increasing concurrency
    print("\n" + "=" * 60)
    print("TEST 2: Concurrent Verification")
    print("=" * 60)

    concurrency_levels = [10, 50, 100, 200, 500]
    concurrent_results = []

    for c in concurrency_levels:
        total = max(c * 2, 500)  # At least 500 requests or 2x concurrency
        r = await benchmark_concurrent(concurrency=c, total_requests=total)
        concurrent_results.append(r)
        print(f"  C={c:>4}: mean={r['mean_ms']:>8.2f}ms, "
              f"p99={r['p99_ms']:>8.2f}ms, "
              f"throughput={r['throughput_rps']:>7.1f} rps, "
              f"errors={r['errors']}")

    # Test 3: Sustained throughput (fixed duration)
    print("\n" + "=" * 60)
    print("TEST 3: Sustained Load (5 seconds, concurrency=100)")
    print("=" * 60)

    sustained = await benchmark_concurrent(concurrency=100, total_requests=2000)
    print(f"  Sustained: {sustained['throughput_rps']:.0f} rps over "
          f"{sustained['total_time_s']:.1f}s")
    print(f"  mean={sustained['mean_ms']:.2f}ms, p99={sustained['p99_ms']:.2f}ms, "
          f"p999={sustained['p999_ms']:.2f}ms")

    return {
        "baseline": baseline,
        "concurrent": concurrent_results,
        "sustained": sustained,
    }


def main():
    print("=" * 60)
    print("EXPERIMENT 9: Concurrent HTTP Verifier Benchmark")
    print("  FastAPI + async HTTP client (httpx)")
    print("=" * 60)

    # Start server in subprocess
    server_proc = multiprocessing.Process(target=run_server, daemon=True)
    server_proc.start()

    try:
        results = asyncio.run(run_benchmarks())

        if results is None:
            print("\n  FAILED: Could not run benchmarks")
            return

        # Summary
        print("\n" + "=" * 60)
        print("SUMMARY")
        print("=" * 60)

        baseline = results["baseline"]
        print(f"\n  Baseline (sequential): {baseline['mean_ms']:.2f}ms mean, "
              f"{baseline['p99_ms']:.2f}ms p99")

        concurrent = results["concurrent"]
        if concurrent:
            worst = max(concurrent, key=lambda r: r.get("p99_ms", 0))
            best_tp = max(concurrent, key=lambda r: r.get("throughput_rps", 0))
            print(f"  Peak throughput: {best_tp['throughput_rps']:.0f} rps "
                  f"(at C={best_tp['concurrency']})")
            print(f"  Worst P99: {worst['p99_ms']:.2f}ms "
                  f"(at C={worst['concurrency']})")

            # Degradation ratio
            if baseline["mean_ms"] > 0:
                ratio = worst["p99_ms"] / baseline["mean_ms"]
                print(f"  Degradation ratio (worst P99 / baseline mean): {ratio:.1f}x")

        sustained = results["sustained"]
        print(f"  Sustained throughput: {sustained['throughput_rps']:.0f} rps "
              f"(p99={sustained['p99_ms']:.2f}ms)")

        output_path = os.path.join(RESULTS_DIR, 'exp9_concurrent_http.json')
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n  Results saved to {output_path}")

    finally:
        server_proc.terminate()
        server_proc.join(timeout=5)
        if server_proc.is_alive():
            server_proc.kill()


if __name__ == "__main__":
    main()
