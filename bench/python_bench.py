#!/usr/bin/env python3
"""
Simple endpoint latency benchmark to validate SLO gates.

Measures p95 latency and error rate for key endpoints on ports 5000 (quality dashboard)
and 5001 (realtime dashboard).

Usage:
    python bench/python_bench.py --iterations 100 --delay 0.05
"""

import argparse
import statistics
import time
from typing import List, Tuple

import requests

ENDPOINTS = [
    ("http://127.0.0.1:5000/api/prediction", "GET"),
    ("http://127.0.0.1:5000/api/trends", "GET"),
    ("http://127.0.0.1:5000/api/metrics", "GET"),
    ("http://127.0.0.1:5000/api/system-health", "GET"),
    ("http://127.0.0.1:5001/api/realtime/metrics", "GET"),
    ("http://127.0.0.1:5001/api/realtime/alerts", "GET"),
    ("http://127.0.0.1:5001/api/realtime/system-status", "GET"),
]


def measure(endpoint: str, method: str, iterations: int, delay: float) -> Tuple[float, float]:
    durations: List[float] = []
    errors = 0
    for _ in range(iterations):
        start = time.perf_counter()
        try:
            if method.upper() == "GET":
                resp = requests.get(endpoint, timeout=5)
            else:
                resp = requests.request(method, endpoint, timeout=5)
            # Consider non-2xx as errors
            if not (200 <= resp.status_code < 300):
                errors += 1
        except Exception:
            errors += 1
        finally:
            durations.append(time.perf_counter() - start)
        if delay > 0:
            time.sleep(delay)

    p95 = statistics.quantiles(durations, n=100)[94] if len(durations) >= 20 else max(durations)
    err_rate = errors / len(durations) if durations else 1.0
    return p95, err_rate


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=50)
    parser.add_argument("--delay", type=float, default=0.02)
    args = parser.parse_args()

    print("Benchmarking endpoints...")
    results = []
    for ep, method in ENDPOINTS:
        p95, err = measure(ep, method, args.iterations, args.delay)
        results.append((ep, p95, err))
        print(f"{ep}: p95={p95:.4f}s, err_rate={err*100:.2f}%")

    # Gate summary (from project_rules.yaml defaults)
    slo_p95 = 0.2
    slo_err = 0.005
    violating = [r for r in results if r[1] > slo_p95 or r[2] > slo_err]
    if violating:
        print("\nSLO VIOLATIONS:")
        for ep, p95, err in violating:
            print(
                f"- {ep}: p95={p95:.4f}s (> {slo_p95}s) or err_rate={err*100:.2f}% (> {slo_err*100:.2f}%)"
            )
    else:
        print("\nAll endpoints meet SLO gates (p95 and error rate).")


if __name__ == "__main__":
    main()
