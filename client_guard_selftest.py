#!/usr/bin/env python3
"""Self-test for the client-side guard (C1-C3).

Two runs, both required:

  1. StrictGuard  -> C1, C2, C3 pass
  2. NaiveGuard   -> C1, C2, C3 fail (the scenarios measure something)

C3 runs against the *naive* server on purpose: the guard must hold even when
the server does not dedupe webhooks.
"""

from __future__ import annotations

import sys
import traceback

from client import Client
from client_guard import GuardedClient, GuardError, NaiveGuard, StrictGuard
from mock_server import WEBHOOK_SECRET, MockServer


def c1(client, guard_cls):
    g = GuardedClient(client, guard=guard_cls())
    code, first = g.purchase("u1", "sku_count_10")
    assert code == 200, f"first purchase: {code} {first}"
    assert g.last_key and g.last_key.startswith("grd_"), f"key: {g.last_key!r}"
    code, second = g.purchase("u1", "sku_count_10")
    assert code == 200, f"second purchase: {code} {second}"
    assert second["purchase_id"] == first["purchase_id"], (
        f"retry created a new order: {first['purchase_id']} -> {second['purchase_id']}")
    assert second["idempotency_key"] == g.last_key
    return f"same purchase_id {first['purchase_id']} on retry, key {g.last_key[:12]}..."


def c2(client, guard_cls):
    g = GuardedClient(client, guard=guard_cls())
    bad = [0, -3, float("nan"), float("inf"), 1.5, "5", True, None]
    for amount in bad:
        try:
            g.consume("u1", amount)
        except GuardError:
            continue
        raise AssertionError(f"amount {amount!r} reached the network")
    for amount in (0, -1):
        try:
            g.access("u1", amount)
        except GuardError:
            continue
        raise AssertionError(f"access amount {amount!r} reached the network")
    code, state = client.state()
    assert len(state.get("grants", [])) == 0, f"grant created: {state.get('grants')}"
    return f"rejected {len(bad) + 2} invalid amounts before HTTP; no grant"


def c3(client, guard_cls):
    code, pur = client.purchase("u1", "c3_key", "sku_once")
    assert code == 200, f"purchase: {code} {pur}"
    code, _ = client.admin("mark_paid", {"purchase_id": pur["purchase_id"]})
    assert code == 200, "mark_paid failed"
    code, signed = client.admin("sign_webhook", {
        "purchase_id": pur["purchase_id"], "event_id": "evt_c3_replay"})
    assert code == 200, f"sign_webhook: {code} {signed}"
    raw, headers = signed["raw"].encode(), signed["headers"]

    g = GuardedClient(client, guard=guard_cls())
    code, body, _ = g.deliver_webhook(raw, headers, WEBHOOK_SECRET)
    assert code == 200, f"first delivery: {code} {body}"
    code2, body2, _ = g.deliver_webhook(raw, headers, WEBHOOK_SECRET)
    assert code2 == 200 and body2.get("duplicate") is True, (
        f"replay not blocked locally: {code2} {body2}")
    _, state = client.state()
    effects = state.get("webhook_effects", [])
    assert len(effects) == 1, f"replay applied {len(effects)} times: {effects}"
    return "2 deliveries -> 1 effect (duplicate short-circuited)"


CASES = [("C1", "idempotency key", c1), ("C2", "amount validation", c2),
         ("C3", "webhook replay", c3)]


def run_case(name, fn, guard_cls):
    srv = MockServer(mode="naive" if name == "C3" else "hardened").start()
    try:
        client = Client(srv.base_url)
        return fn(client, guard_cls)
    finally:
        srv.stop()


def main() -> int:
    failures = 0
    print("strict guard")
    for name, title, fn in CASES:
        try:
            detail = run_case(name, fn, StrictGuard)
            print(f"ok   {name} {title}: {detail}")
        except Exception as exc:
            failures += 1
            print(f"FAIL {name} {title}: {exc}")
            traceback.print_exc()

    print("\nnaive guard (each case must fail)")
    for name, title, fn in CASES:
        try:
            detail = run_case(name, fn, NaiveGuard)
            failures += 1
            print(f"FAIL {name} {title}: unexpectedly passed ({detail})")
        except Exception as exc:
            print(f"ok   {name} {title} failed as designed: {exc}")

    if failures:
        print(f"\nCLIENT GUARD SELFTEST FAILED ({failures})")
        return 1
    print("\nCLIENT GUARD SELFTEST OK — 3 guarded cases pass, 3 naive cases fail")
    return 0


if __name__ == "__main__":
    sys.exit(main())
