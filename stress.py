#!/usr/bin/env python3
"""Concurrency stress for the quota check (defect E3 at scale).

One user buys a single-use pack, then N threads fire distinct consumes at the
same instant.  Correct behavior: exactly one SUCCEEDED and N-1 FAILED.  The
naive mock reads, sleeps and writes without a lock, so it overspends.

    python3 stress.py --threads 50
    python3 stress.py --threads 200 --json
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import threading
import time

from client import Client
from mock_server import MockServer


def percentile(values, p):
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, int(round((p / 100) * (len(ordered) - 1))))
    return ordered[idx]


def run(mode: str, threads: int) -> dict:
    srv = MockServer(mode=mode).start()
    try:
        setup = Client(srv.base_url)
        code, pur = setup.purchase("race", "race_key", "sku_count_1")
        assert code == 200, f"purchase failed: {code} {pur}"
        code, paid = setup.admin("mark_paid", {"purchase_id": pur["purchase_id"]})
        assert code == 200, f"mark_paid failed: {code} {paid}"

        barrier = threading.Barrier(threads)
        results: list[tuple[int, str, float, str]] = []
        lock = threading.Lock()

        def worker(i: int) -> None:
            client = Client(srv.base_url)
            barrier.wait()
            started = time.perf_counter()
            code, body = client.consume("race", f"race_{i}", 1, "stress")
            elapsed = (time.perf_counter() - started) * 1000
            with lock:
                results.append((code, str(body.get("status")), elapsed,
                                str(body.get("reason_code") or "")))

        workers = [threading.Thread(target=worker, args=(i,)) for i in range(threads)]
        for w in workers:
            w.start()
        for w in workers:
            w.join()

        successes = [r for r in results if r[0] == 200 and r[1] == "SUCCEEDED"]
        failures = [r for r in results if r[0] == 200 and r[1] == "FAILED"]
        other = [r for r in results if r not in successes and r not in failures]
        latencies = [r[2] for r in results]
        return {
            "mode": mode,
            "threads": threads,
            "successes": len(successes),
            "failures": len(failures),
            "other": len(other),
            "other_samples": other[:3],
            "p50_ms": round(statistics.median(latencies), 1) if latencies else 0.0,
            "p99_ms": round(percentile(latencies, 99), 1),
            "max_ms": round(max(latencies), 1) if latencies else 0.0,
        }
    finally:
        srv.stop()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--threads", type=int, default=50)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    if args.threads < 2:
        ap.error("--threads must be >= 2")

    hardened = run("hardened", args.threads)
    naive = run("naive", args.threads)
    report = {"hardened": hardened, "naive": naive}

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        for row in (hardened, naive):
            print(f"{row['mode']:8s} threads={row['threads']:3d} "
                  f"SUCCEEDED={row['successes']:3d} FAILED={row['failures']:3d} "
                  f"other={row['other']:3d} p50={row['p50_ms']}ms p99={row['p99_ms']}ms")
        if hardened["other"]:
            print("hardened unexpected responses:", hardened["other_samples"])

    ok = hardened["successes"] == 1 and hardened["other"] == 0
    if not ok:
        print(f"STRESS FAILED: hardened granted {hardened['successes']} units of a 1-unit pack")
        return 1
    if naive["successes"] <= 1:
        print(f"STRESS INCONCLUSIVE: naive granted only {naive['successes']}; "
              "the race did not materialize, the probe cannot detect E3")
        return 1
    if not args.json:
        print(f"STRESS OK — hardened exactly 1 success; naive overspent "
              f"{naive['successes']}x on a 1-unit pack")
    return 0


if __name__ == "__main__":
    sys.exit(main())
