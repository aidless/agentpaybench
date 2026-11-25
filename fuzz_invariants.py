#!/usr/bin/env python3
"""Invariant fuzzer for the quota ledger (six-item plan, item 3).

A random op stream drives the mock through purchases, payments, consumes,
refunds, queries and webhook replays, then re-checks the ledger invariants
from the admin snapshot:

  I1  no grant ever carries a negative remaining balance
  I2  a refunded purchase has no spendable grant left
  I3  cumulative successful consumption <= cumulative granted units (per user)
  I4  no successful consume with amount <= 0
  I5  a purchase idempotency key maps to exactly one purchase
  I6  a replayed webhook event does not create a second effect
  I7  a merchant cannot read another merchant's grants

The hardened mock must satisfy all seven.  The naive mock is expected to
violate several; that is the mutation proof that the invariants bite.

    python3 fuzz_invariants.py --steps 10000
    python3 fuzz_invariants.py --mode naive --steps 10000 --json
"""

from __future__ import annotations

import argparse
import json
import random
import sys

from client import Client
from mock_server import MockServer

USERS = ["fz_u0", "fz_u1", "fz_u2", "fz_u3"]
COUNT_SKUS = ["sku_count_1", "sku_count_10"]
OTHER_SKUS = ["sku_points_100", "sku_time_30d", "sku_once"]


class Fuzzer:
    def __init__(self, client: Client, mode: str, seed: int) -> None:
        self.c = client
        self.mode = mode
        self.rng = random.Random(seed)
        self.purchase_keys: dict[tuple[str, str], str] = {}
        self.paid: list[str] = []
        self.refunded: set[str] = set()
        self.consumed: dict[str, int] = {u: 0 for u in USERS}
        self.granted: dict[str, int] = {u: 0 for u in USERS}
        self.illegal_consumes = 0
        self.split_keys = 0
        self.replay_dups = 0
        self.cross_tenant_allows = 0
        self.negative_remaining = 0
        self.refund_leaks = 0
        self.over_consumed = 0
        self.webhook_events: list[str] = []

    # -- setup -------------------------------------------------------------
    def bootstrap(self) -> None:
        for user in USERS:
            for sku in ("sku_count_10", "sku_points_100"):
                self._buy_paid(user, sku)

    def _buy_paid(self, user: str, sku: str) -> str | None:
        key = f"boot_{user}_{sku}_{len(self.purchase_keys)}"
        code, pur = self.c.purchase(user, key, sku)
        if code != 200:
            return None
        pid = pur["purchase_id"]
        self.purchase_keys[(user, key)] = pid
        code, _ = self.c.admin("mark_paid", {"purchase_id": pid})
        if code != 200:
            return None
        self.paid.append(pid)
        units = 10 if sku == "sku_count_10" else 100
        self.granted[user] += units
        return pid

    # -- ops ---------------------------------------------------------------
    def op(self, i: int) -> None:
        r = self.rng.random()
        user = self.rng.choice(USERS)
        if r < 0.14:
            key = f"fz_{i}"
            sku = self.rng.choice(COUNT_SKUS + OTHER_SKUS)
            code, pur = self.c.purchase(user, key, sku)
            if code == 200:
                self.purchase_keys[(user, key)] = pur["purchase_id"]
        elif r < 0.24:
            if not self.purchase_keys:
                return
            user, key = self.rng.choice(list(self.purchase_keys))
            first = self.purchase_keys[(user, key)]
            code, pur = self.c.purchase(user, key, "sku_count_1")
            if code == 200 and pur.get("purchase_id") != first:
                self.split_keys += 1
        elif r < 0.34:
            pending = [p for p in self._snapshot()["purchases"]
                       if p["payment_status"] != "PAID"]
            if pending:
                pid = self.rng.choice(pending)["purchase_id"]
                code, body = self.c.admin("mark_paid", {"purchase_id": pid})
                if code == 200 and not body.get("already"):
                    self.paid.append(pid)
                    p = next(p for p in self._snapshot()["purchases"]
                             if p["purchase_id"] == pid)
                    units = 10 if p["sku_id"] == "sku_count_10" else (
                        1 if p["sku_id"] == "sku_count_1" else 100)
                    self.granted[p["user_id"]] += units
        elif r < 0.56:
            amount = self.rng.choice([-50, -5, -2, -1, 0, 1, 1, 1, 2, 5, 20, 50])
            code, body = self.c.consume(user, f"c_{i}", amount, "fuzz")
            if body.get("status") == "SUCCEEDED":
                if amount <= 0:
                    self.illegal_consumes += 1
                else:
                    self.consumed[user] += amount
        elif r < 0.64:
            code, body = self.c.consume(user, "shared_key", 1, "dup")
            if body.get("status") == "SUCCEEDED":
                self.consumed[user] += 1
            code, body2 = self.c.consume(user, "shared_key", 1, "dup")
            if body2.get("status") == "SUCCEEDED":
                self.consumed[user] += 1
        elif r < 0.72:
            self.c.access(user, self.rng.choice([-1, 0, 1, 5]))
        elif r < 0.80:
            if self.paid:
                pid = self.rng.choice(self.paid)
                code, _ = self.c.admin("refund", {"purchase_id": pid})
                if code == 200:
                    self.refunded.add(pid)
        elif r < 0.86:
            self.c.transaction_query(user, self.rng.choice([f"fz_{i}", "missing"]))
        elif r < 0.94:
            if self.paid:
                pid = self.rng.choice(self.paid)
                self._webhook_pair(pid)
        else:
            self.c.admin("advance_time", {"seconds": 3600})

    def _webhook_pair(self, pid: str) -> None:
        code, signed = self.c.admin("sign_webhook", {"purchase_id": pid})
        if code != 200:
            return
        headers = signed["headers"]
        raw = signed["raw"].encode()
        code1, _ = self.c.webhook(headers, raw)
        code2, _ = self.c.webhook(headers, raw)
        if code1 == 200 and code2 == 200:
            self.webhook_events.append(signed["body"]["id"])

    # -- invariants --------------------------------------------------------
    def _snapshot(self) -> dict:
        code, snap = self.c.state()
        if code != 200:
            raise RuntimeError(f"state fetch failed: {code} {snap}")
        return snap

    def check(self) -> None:
        snap = self._snapshot()
        for g in snap["grants"]:
            if g["remaining"] is not None and g["remaining"] < 0:
                self.negative_remaining += 1
            if g["purchase_id"] in self.refunded and (g["remaining"] or 0) > 0:
                self.refund_leaks += 1
        for user, total in self.consumed.items():
            if total > self.granted[user]:
                self.over_consumed += 1
        code, body = self.c.clone("test_key_b").access("fz_u0", 1)
        if code == 200 and body.get("access_granted"):
            self.cross_tenant_allows += 1

    def violations(self) -> dict:
        return {
            "I1_negative_remaining": self.negative_remaining,
            "I2_refund_leak": self.refund_leaks,
            "I3_over_consumed": self.over_consumed,
            "I4_illegal_consume": self.illegal_consumes,
            "I5_split_purchase_key": self.split_keys,
            "I6_replay_duplicate": self.replay_dups,
            "I7_cross_tenant": self.cross_tenant_allows,
        }


def run(mode: str, steps: int, seed: int) -> dict:
    with MockServer(mode) as srv:
        fz = Fuzzer(Client(srv.base_url), mode, seed)
        fz.bootstrap()
        for i in range(steps):
            fz.op(i)
            if i % 250 == 0:
                fz.check()
        fz.check()
        snap = fz._snapshot()
        effects = len(snap["webhook_effects"])
        seen_unique = len(set(snap["webhook_effects"]))
        if effects > seen_unique:
            fz.replay_dups += effects - seen_unique
        v = fz.violations()
        return {"mode": mode, "steps": steps, "seed": seed,
                "violations": v, "total": sum(v.values()),
                "effects": effects, "unique_effects": seen_unique,
                "grants": len(snap["grants"]),
                "purchases": len(snap["purchases"])}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["hardened", "naive"], default="hardened")
    ap.add_argument("--steps", type=int, default=10000)
    ap.add_argument("--seed", type=int, default=20261122)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    report = run(args.mode, args.steps, args.seed)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"fuzz mode={args.mode} steps={args.steps} seed={args.seed}")
        for name, count in report["violations"].items():
            print(f"  {name:26s} {count}")
        print(f"  purchases={report['purchases']} grants={report['grants']} "
              f"effects={report['effects']} unique={report['unique_effects']}")
    verdict_out = sys.stderr if args.json else sys.stdout
    if args.mode == "hardened":
        ok = report["total"] == 0
        print("FUZZ OK — all 7 invariants held" if ok
              else "FUZZ FAIL — hardened mock violated an invariant",
              file=verdict_out)
        return 0 if ok else 1
    ok = report["total"] > 0
    print("FUZZ OK — naive mock violated invariants as designed" if ok
          else "FUZZ FAIL — naive mock satisfied every invariant (test is vacuous)",
          file=verdict_out)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
