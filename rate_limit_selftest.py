#!/usr/bin/env python3
"""Rate-limit checks (six-item plan, item 4).

E8  server: a credential gets 120 status queries per minute; the 121st is 429
    with a retry_after.  The naive mock has no limiter.
C4  client: never re-poll the same transaction faster than 15 s, so a caller
    cannot burn the budget or hammer a PENDING order.

    python3 rate_limit_selftest.py
"""

from __future__ import annotations

import sys

from client import Client
from client_guard import GuardedClient, QueryThrottle, QueryTooSoon
from mock_server import MockServer

LIMIT = 120


def e8(mode: str) -> tuple[bool, str]:
    with MockServer(mode) as srv:
        c = Client(srv.base_url)
        code, pur = c.purchase("rl_user", "rl_key", "sku_count_1")
        if code != 200:
            return False, f"setup purchase failed: {code} {pur}"
        c.admin("mark_paid", {"purchase_id": pur["purchase_id"]})
        codes = []
        for _ in range(LIMIT + 1):
            code, body = c.transaction_query("rl_user", "rl_key")
            codes.append((code, body))
        first_bad = next((i for i, (code, _) in enumerate(codes, 1)
                          if code != 200), None)
        last_code, last_body = codes[-1]
        if mode == "hardened":
            ok = first_bad == LIMIT + 1 and last_code == 429 and \
                isinstance(last_body.get("retry_after"), int) and \
                1 <= last_body["retry_after"] <= 60
            return ok, f"first non-200 at #{first_bad}, last={last_code} {last_body}"
        # naive must fail this check: no 429 at all.
        return first_bad is None and last_code == 200, \
            f"first non-200 at {first_bad}, last={last_code}"


def c4() -> tuple[bool, str]:
    now = [1000.0]
    throttle = QueryThrottle(15.0, clock=lambda: now[0])

    class FakeClient:
        calls = 0

        def transaction_query(self, user_id, key):
            self.calls += 1
            return 200, {"status": "PENDING"}

    fake = FakeClient()
    guarded = GuardedClient(fake, throttle=throttle)
    code, _ = guarded.transaction_query("u", "k")
    if code != 200 or fake.calls != 1:
        return False, "first query did not go through"
    try:
        guarded.transaction_query("u", "k")
        return False, "second query inside 15 s was allowed"
    except QueryTooSoon as exc:
        if not 14.9 <= exc.wait <= 15.0:
            return False, f"reported wait {exc.wait} outside [14.9, 15.0]"
    if fake.calls != 1:
        return False, "blocked query still reached the network"
    now[0] += 14.9
    try:
        guarded.transaction_query("u", "k")
        return False, "query at 14.9 s was allowed"
    except QueryTooSoon:
        pass
    now[0] += 0.1
    code, _ = guarded.transaction_query("u", "k")
    if code != 200 or fake.calls != 2:
        return False, "query after 15 s was not sent"
    return True, "15 s backoff enforced with a fake clock (2 sends, 2 blocks)"


def main() -> int:
    hard_ok, hard_detail = e8("hardened")
    naive_ok, naive_detail = e8("naive")
    client_ok, client_detail = c4()
    print(f"{'ok  ' if hard_ok else 'FAIL'} E8 hardened: {hard_detail}")
    print(f"{'ok  ' if naive_ok else 'FAIL'} E8 naive (must fail to be a real test): {naive_detail}")
    print(f"{'ok  ' if client_ok else 'FAIL'} C4 client backoff: {client_detail}")
    ok = hard_ok and naive_ok and client_ok
    print("\nRATE LIMIT OK — E8 passes hardened and fails naive; C4 holds"
          if ok else "\nRATE LIMIT FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
