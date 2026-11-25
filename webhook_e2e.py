#!/usr/bin/env python3
"""End-to-end webhook lifecycle checks (W1-W4).

The 20 main scenarios only cover *delivery verification*.  These checks cover
the management surface the SDK also exposes:

  W1  registration rejects HTTP / loopback / link-local URLs
  W2  rotation invalidates the old secret
  W3  retry does not apply an already-seen event twice
  W4  a disabled endpoint receives nothing

Each case asserts hardened behavior; the same case runs against the naive
mock and must fail, which is the non-vacuity proof.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
import time
import traceback

from client import Client
from mock_server import MockServer

BAD_URLS = [
    "http://merchant.example.com/hook",
    "https://127.0.0.1/hook",
    "https://localhost/hook",
    "https://169.254.169.254/latest/meta-data",
    "https://10.0.0.5/hook",
]
GOOD_URL = "https://merchant.example.com/opcpay/hook"


def signed(raw: bytes, secret: str, event_id: str) -> dict:
    ts = str(int(time.time()))
    sig = "v1=" + hmac.new(secret.encode(), f"{ts}.".encode() + raw,
                           hashlib.sha256).hexdigest()
    return {"yirenfu-signature": sig, "yirenfu-timestamp": ts,
            "yirenfu-event-id": event_id}


def event_bytes(event_id: str) -> bytes:
    return json.dumps({
        "id": event_id, "type": "entitlement.observed",
        "project_id": "test_key", "user_id": "u1",
        "created_at": "2026-11-22T00:00:00Z",
        "data": {"decision": "ALLOW"},
    }, separators=(",", ":")).encode()


def paid_purchase(client, key):
    code, pur = client.purchase("u1", key, "sku_once")
    assert code == 200, f"purchase: {code} {pur}"
    code, body = client.admin("mark_paid", {"purchase_id": pur["purchase_id"]})
    assert code == 200, f"mark_paid: {code} {body}"
    return pur


def w1(client):
    for url in BAD_URLS:
        code, body = client.save_webhook(url)
        assert code == 400, f"accepted {url}: {code} {body}"
    code, saved = client.save_webhook(GOOD_URL)
    assert code == 200 and saved["configured"] is True, f"good url: {code} {saved}"
    assert saved.get("secret"), f"no secret returned: {saved}"
    code, cfg = client.webhook_settings()
    assert code == 200 and cfg["url"] == GOOD_URL and cfg["enabled"] is True, cfg
    return f"{len(BAD_URLS)} bad URLs rejected; {GOOD_URL} configured"


def w2(client):
    code, saved = client.save_webhook(GOOD_URL)
    assert code == 200, saved
    old = saved["secret"]
    paid_purchase(client, "rot_key")

    raw = event_bytes("evt_rotate")
    code, body = client.webhook(signed(raw, old, "evt_rotate"), raw)
    assert code == 200, f"pre-rotation delivery: {code} {body}"

    code, rotated = client.rotate_webhook()
    assert code == 200 and rotated["secret"] != old, f"rotate: {code} {rotated}"

    code, body = client.webhook(signed(raw, old, "evt_rotate"), raw)
    assert code == 401, f"old secret still accepted: {code} {body}"

    fresh = event_bytes("evt_after_rotate")
    code, body = client.webhook(signed(fresh, rotated["secret"], "evt_after_rotate"), fresh)
    assert code == 200, f"new secret rejected: {code} {body}"
    return "old secret 401 after rotation; new secret 200"


def w3(client):
    code, saved = client.save_webhook(GOOD_URL)
    assert code == 200, saved
    paid_purchase(client, "retry_key")

    code, signed_evt = client.admin("sign_webhook", {
        "purchase_id": list_any_purchase(client), "event_id": "evt_retry"})
    assert code == 200, f"sign: {code} {signed_evt}"
    raw, headers = signed_evt["raw"].encode(), signed_evt["headers"]
    code, body = client.webhook(headers, raw)
    assert code == 200, f"delivery: {code} {body}"

    for _ in range(2):
        code, body = client.retry_event("evt_retry")
        assert code == 200, f"retry: {code} {body}"
    _, state = client.state()
    effects = state["webhook_effects"]
    assert len(effects) == 1, f"retry applied {len(effects)} times: {effects}"
    code, evts = client.events()
    assert code == 200 and any(e["event_id"] == "evt_retry" for e in evts["items"]), evts
    return "2 retries -> still 1 effect; event listed"


def w4(client):
    code, saved = client.save_webhook(GOOD_URL, enabled=False)
    assert code == 200 and saved["enabled"] is False, saved

    paid_purchase(client, "disabled_key")
    code, signed_evt = client.admin("sign_webhook", {
        "purchase_id": list_any_purchase(client), "event_id": "evt_disabled"})
    assert code == 200, signed_evt
    code, body = client.webhook(signed_evt["headers"], signed_evt["raw"].encode())
    assert code == 403, f"disabled endpoint accepted: {code} {body}"
    _, state = client.state()
    assert state["webhook_effects"] == [], state["webhook_effects"]
    return "disabled endpoint: 403, 0 effects"


def list_any_purchase(client):
    """The newest purchase id; the admin signer needs one."""
    _, state = client.state()
    return state["purchases"][-1]["purchase_id"]


CASES = [("W1", "registration", w1), ("W2", "rotation", w2),
         ("W3", "retry idempotency", w3), ("W4", "disabled endpoint", w4)]


def run_case(fn, mode):
    srv = MockServer(mode=mode).start()
    try:
        return fn(Client(srv.base_url))
    finally:
        srv.stop()


def main() -> int:
    failures = 0
    print("hardened")
    for name, title, fn in CASES:
        try:
            detail = run_case(fn, "hardened")
            print(f"ok   {name} {title}: {detail}")
        except Exception as exc:
            failures += 1
            print(f"FAIL {name} {title}: {exc}")
            traceback.print_exc()

    print("\nnaive (each case must fail)")
    for name, title, fn in CASES:
        try:
            detail = run_case(fn, "naive")
            failures += 1
            print(f"FAIL {name} {title}: unexpectedly passed ({detail})")
        except Exception as exc:
            print(f"ok   {name} {title} failed as designed: {exc}")

    if failures:
        print(f"\nWEBHOOK E2E FAILED ({failures})")
        return 1
    print("\nWEBHOOK E2E OK — 4 hardened cases pass, 4 naive cases fail")
    return 0


if __name__ == "__main__":
    sys.exit(main())
