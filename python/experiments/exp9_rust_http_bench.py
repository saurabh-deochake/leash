"""
Experiment 9 (Rust): Concurrent HTTP Verification Benchmark
Benchmarks the Rust LEASH verification server under concurrent load.
Server must be running at http://127.0.0.1:18924 before executing.
"""

import asyncio
import time
import json
import statistics
import httpx

SERVER_URL = "http://127.0.0.1:18924"
RESULTS_PATH = "../results/exp9_rust_http.json"


async def sequential_baseline(n=200):
    """Measure sequential single-request latency."""
    latencies = []
    async with httpx.AsyncClient(base_url=SERVER_URL) as client:
        for _ in range(n):
            t0 = time.perf_counter()
            resp = await client.post("/verify")
            elapsed_ms = (time.perf_counter() - t0) * 1000
            assert resp.status_code == 200
            data = resp.json()
            assert data["valid"] is True
            latencies.append(elapsed_ms)
    return latencies


async def concurrent_burst(concurrency, total_requests=500):
    """Send total_requests with given concurrency level."""
    semaphore = asyncio.Semaphore(concurrency)
    latencies = []
    errors = 0

    async def single_request(client):
        nonlocal errors
        async with semaphore:
            t0 = time.perf_counter()
            try:
                resp = await client.post("/verify")
                elapsed_ms = (time.perf_counter() - t0) * 1000
                if resp.status_code == 200:
                    latencies.append(elapsed_ms)
                else:
                    errors += 1
            except Exception:
                errors += 1

    pool_limits = httpx.Limits(
        max_connections=concurrency + 50,
        max_keepalive_connections=concurrency,
    )
    async with httpx.AsyncClient(
        base_url=SERVER_URL, timeout=60.0, limits=pool_limits
    ) as client:
        t_start = time.perf_counter()
        tasks = [asyncio.create_task(single_request(client)) for _ in range(total_requests)]
        await asyncio.gather(*tasks)
        total_time = time.perf_counter() - t_start

    throughput = len(latencies) / total_time if total_time > 0 else 0
    return latencies, errors, throughput


async def sustained_load(concurrency, duration_s=10):
    """Sustained load for a fixed duration."""
    latencies = []
    errors = 0
    stop = asyncio.Event()

    async def worker(client):
        nonlocal errors
        while not stop.is_set():
            t0 = time.perf_counter()
            try:
                resp = await client.post("/verify")
                elapsed_ms = (time.perf_counter() - t0) * 1000
                if resp.status_code == 200:
                    latencies.append(elapsed_ms)
                else:
                    errors += 1
            except Exception:
                errors += 1

    pool_limits = httpx.Limits(
        max_connections=concurrency + 50,
        max_keepalive_connections=concurrency,
    )
    async with httpx.AsyncClient(
        base_url=SERVER_URL, timeout=60.0, limits=pool_limits
    ) as client:
        workers = [asyncio.create_task(worker(client)) for _ in range(concurrency)]
        await asyncio.sleep(duration_s)
        stop.set()
        await asyncio.gather(*workers, return_exceptions=True)

    throughput = len(latencies) / duration_s if duration_s > 0 else 0
    return latencies, errors, throughput


def summarize(latencies):
    if not latencies:
        return {"mean_ms": 0, "p50_ms": 0, "p99_ms": 0, "min_ms": 0, "max_ms": 0}
    s = sorted(latencies)
    return {
        "mean_ms": round(statistics.mean(s), 3),
        "p50_ms": round(s[len(s) // 2], 3),
        "p99_ms": round(s[int(len(s) * 0.99)], 3),
        "min_ms": round(s[0], 3),
        "max_ms": round(s[-1], 3),
    }


async def main():
    results = {}

    # 1. Sequential baseline
    print("=" * 60)
    print("Sequential baseline (200 requests)")
    lats = await sequential_baseline(200)
    s = summarize(lats)
    results["sequential"] = {**s, "count": len(lats)}
    print(f"  Mean: {s['mean_ms']:.3f} ms  P99: {s['p99_ms']:.3f} ms")

    # 2. Burst benchmarks at various concurrency levels
    concurrency_levels = [1, 10, 50, 100, 200, 500]
    results["burst"] = {}
    for c in concurrency_levels:
        total = max(500, c * 5)
        print(f"\nBurst C={c} ({total} requests)")
        lats, errs, throughput = await concurrent_burst(c, total)
        s = summarize(lats)
        results["burst"][str(c)] = {
            **s,
            "throughput_rps": round(throughput, 1),
            "errors": errs,
            "count": len(lats),
        }
        print(f"  Mean: {s['mean_ms']:.3f} ms  P99: {s['p99_ms']:.3f} ms  "
              f"Throughput: {throughput:.1f} rps  Errors: {errs}")

    # 3. Sustained load test (10s at C=100)
    print(f"\nSustained load C=100, 10s")
    lats, errs, throughput = await sustained_load(100, 10)
    s = summarize(lats)
    results["sustained_c100_10s"] = {
        **s,
        "throughput_rps": round(throughput, 1),
        "errors": errs,
        "count": len(lats),
        "duration_s": 10,
    }
    print(f"  Mean: {s['mean_ms']:.3f} ms  P99: {s['p99_ms']:.3f} ms  "
          f"Throughput: {throughput:.1f} rps  Errors: {errs}  Total: {len(lats)}")

    # Save results
    with open(RESULTS_PATH, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to {RESULTS_PATH}")


if __name__ == "__main__":
    asyncio.run(main())
