#!/usr/bin/env python3
"""Self-test / mutation proof for AgentPayBench.

Three assertions, all required:

  1. hardened + safe agent  -> 20/20 pass
  2. naive   + safe agent   -> exactly the documented failure set
  3. hardened + unsafe agent -> A7 fails (the benchmark detects a gullible agent)

Assertion 2 is the non-vacuity gate: if the naive implementation also
passed, no scenario would be measuring anything.
"""

from __future__ import annotations

import sys

from runner import run_all

# Scenarios whose mechanism is deliberately broken in the naive mock.
EXPECTED_NAIVE_FAIL = {
    "N4",   # consume idempotency ignored
    "N6",   # PENDING reported as PAID
    "E1",   # unknown SKU accepted
    "E2",   # negative/zero amount accepted
    "E3",   # non-atomic consume -> double spend
    "E4",   # purchase idempotency ignored
    "E5",   # premature PAID
    "E6",   # refund does not revoke
    "E7",   # client price wins
    "A1",   # foreign callback accepted
    "A2",   # SKU injection accepted
    "A3",   # webhook signature not verified
    "A4",   # webhook replay grants twice
    "A5",   # global user namespace (cross-tenant read)
    "A6",   # cross-tenant consume
}


def ids(results):
    return {r.id for r in results if not r.ok}


def main() -> int:
    results = run_all("hardened", "safe")
    bad = [r for r in results if not r.ok]
    if len(results) != 20:
        print(f"FAIL: expected 20 scenarios, got {len(results)}")
        return 1
    if bad:
        print("FAIL: hardened implementation did not pass:")
        for r in bad:
            print(f"  {r.id} {r.title}: {r.detail}")
        return 1
    print(f"ok  hardened + safe: {len(results)}/{len(results)} pass")

    naive = run_all("naive", "safe")
    got = ids(naive)
    if got != EXPECTED_NAIVE_FAIL:
        print("FAIL: naive failure set mismatch")
        print(f"  missing (should have failed): {sorted(EXPECTED_NAIVE_FAIL - got)}")
        print(f"  unexpected (should have passed): {sorted(got - EXPECTED_NAIVE_FAIL)}")
        return 1
    print(f"ok  naive + safe: {len(got)}/20 fail exactly as documented")

    unsafe = run_all("hardened", "unsafe")
    a7 = [r for r in unsafe if r.id == "A7"][0]
    if a7.ok:
        print("FAIL: unsafe agent passed A7; the agent scenario is vacuous")
        return 1
    print(f"ok  hardened + unsafe: A7 fails ({a7.detail})")

    print("\nSELFTEST OK — 20 scenarios, mutation proof intact")
    return 0


if __name__ == "__main__":
    sys.exit(main())
