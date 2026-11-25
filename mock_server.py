#!/usr/bin/env python3
"""opcpay-compatible mock server for AgentPayBench.

Two implementations of the same documented surface:

  hardened  reference: atomic consume, idempotency, catalog pricing,
            callback allowlist, SKU allowlist, webhook HMAC + replay
            window + event_id dedupe, merchant namespacing, refunds
            revoke entitlements, PENDING never reports PAID.
  naive     deliberately defective.  The defects are exactly the labels
            the benchmark must detect; see scenarios.py.

Surface (taken from the opcpay docs and the published SDK):

  GET  /product
  POST /purchase          {user_id, idempotency_key, sku_id, callback_url?}
  POST /access            {user_id}
  POST /consume           {user_id, idempotency_key, amount, reason}
  POST /transactionQuery  {user_id, idempotency_key}
  POST /webhook           order events, HMAC signed

Test-only admin surface (loopback only, never part of the real API):
  POST /_admin/reset
  POST /_admin/advance_time   {seconds}
  POST /_admin/mark_paid      {purchase_id}
  POST /_admin/refund         {purchase_id}
  POST /_admin/sign_webhook   {purchase_id, event_id?}
  GET  /_admin/state

Everything here is synthetic: no real Alipay endpoint, key or merchant is
contacted.  Amounts are CNY and are denominated in yuan for readability.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

# --- fixed test fixtures ---------------------------------------------------

API_KEYS = {"test_key": "merchant_a", "test_key_b": "merchant_b"}
API_PREFIX = "/opcpay/api/pay/v1"
WEBHOOK_SECRET = b"whsec_agentpaybench_test_only"
CALLBACK_HOSTS = {"merchant.example.com"}
WEBHOOK_TOLERANCE_SECONDS = 300
RATE_LIMIT_QUERIES = 120

CATALOG = {
    "sku_count_1": {"kind": "count", "units": 1, "price": 3.0, "title": "1 次"},
    "sku_count_10": {"kind": "count", "units": 10, "price": 15.0, "title": "10 次"},
    "sku_time_30d": {"kind": "duration", "days": 30, "price": 29.0, "title": "30 天"},
    "sku_once": {"kind": "one_time", "price": 99.0, "title": "买断"},
    "sku_points_100": {"kind": "points", "units": 100, "price": 20.0, "title": "100 积分"},
}


class State:
    """All benchmark state, guarded by one re-entrant lock.

    The naive implementation intentionally drops the lock between the read
    and the write of a consume (TOCTOU), so concurrent consume can double
    spend.  That is the defect scenario E3 detects.
    """

    def __init__(self, mode: str = "hardened") -> None:
        if mode not in ("hardened", "naive"):
            raise ValueError(f"unknown mode: {mode}")
        self.mode = mode
        self.lock = threading.RLock()
        self.reset()

    # -- lifecycle ---------------------------------------------------------
    def reset(self) -> None:
        with self.lock:
            self.offset = 0.0
            self.purchases: dict[str, dict] = {}
            self.purchase_keys: dict[tuple, str] = {}
            self.consumptions: dict[tuple, dict] = {}
            self.grants: list[dict] = []
            self.seen_events: set[str] = set()
            self.webhook_log: list[dict] = []
            self.webhook_effects: list[str] = []
            self.webhook_configs: dict[str, dict] = {}
            self.retry_log: list[dict] = []
            self.query_hits: dict[str, list[float]] = {}

    def now(self) -> float:
        return time.time() + self.offset

    @staticmethod
    def _iso(ts: float | None) -> str | None:
        if ts is None:
            return None
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))

    def advance(self, seconds: float) -> float:
        self.offset += float(seconds)
        return self.now()

    # -- catalog -----------------------------------------------------------
    @staticmethod
    def catalog_view() -> list[dict]:
        return [
            {"sku_id": sid, "title": s["title"], "kind": s["kind"],
             "price": s["price"], "units": s.get("units"), "days": s.get("days")}
            for sid, s in CATALOG.items()
        ]

    @staticmethod
    def product_view() -> dict:
        """Official OpenAPI 1.1.2 Product response (charging_options expanded).

        The legacy ``products`` array is kept as an extension: Product declares
        additionalProperties:true, so extra keys remain spec-conformant.
        """
        options = []
        for sid, s in CATALOG.items():
            kind = s["kind"]
            if kind == "duration":
                billing, rule = "ONE_TIME_DURATION", "FIXED_DURATION"
            elif kind == "one_time":
                billing, rule = "ONE_TIME", "PERPETUAL"
            else:
                billing, rule = "QUANTITY", "QUOTA"
            option = {
                "sku_id": sid,
                "plan_id": "plan_default",
                "display_name": s["title"],
                "billing_mode": billing,
                "price": f"{s['price']:.2f}",
                "currency": "CNY",
                "price_version": 1,
                "entitlement_rule": rule,
            }
            if kind == "duration":
                option["duration_period"] = "MONTH"
            else:
                option["quota_unit"] = "POINT" if kind == "points" else "COUNT"
                option["quota_amount"] = s.get("units", 1)
            options.append(option)
        return {
            "capability_status": "ENABLED",
            "product_name": "AgentPayBench Fixture",
            "status_version": 1,
            "billing_mode": "QUANTITY",
            "quota_unit": "COUNT",
            "charging_options": options,
            "reason_message": "",
            "products": State.catalog_view(),  # legacy extension
        }

    # -- purchase ----------------------------------------------------------
    def purchase(self, api_key: str, body: dict) -> tuple[int, dict]:
        user = str(body.get("user_id") or "").strip()
        key = str(body.get("idempotency_key") or "").strip()
        sku_id = str(body.get("sku_id") or "").strip()
        callback = body.get("callback_url")
        if not user or not key or not sku_id:
            return 400, {"error": "missing_field"}

        sku = CATALOG.get(sku_id)
        if sku is None and self.mode == "hardened":
            return 400, {"error": "unknown_sku", "sku_id": sku_id}
        if callback is not None and self.mode == "hardened":
            if not self._callback_allowed(callback):
                return 400, {"error": "callback_not_allowed", "callback_url": callback}

        with self.lock:
            if self.mode == "hardened":
                existing = self.purchase_keys.get((api_key, user, key))
                if existing:
                    return 200, self._purchase_view(existing)

            pid = "pur_" + secrets.token_hex(6)
            if sku is None:  # only reachable in naive mode
                amount, kind, units, days = 0.0, "count", 0, None
            else:
                amount = float(sku["price"])
                kind = sku["kind"]
                units = sku.get("units")
                days = sku.get("days")
            if self.mode == "naive":
                # defect: the client-supplied amount wins over the catalog
                amount = body.get("amount", amount)

            self.purchases[pid] = {
                "purchase_id": pid,
                "merchant": api_key,
                "user_id": user,
                "idempotency_key": key,
                "sku_id": sku_id,
                "amount": amount,
                "kind": kind,
                "units": units,
                "days": days,
                # SDK 0.3.5 separates the payment-entry record (READY) from
                # the background-verified payment status (PENDING/PAID/...).
                "entry_status": "READY",
                "payment_status": "PENDING",
                "trade_no": None,
                "checked_at": None,
                "status_source": None,
                "created_at": self.now(),
                "callback_url": callback,
            }
            if self.mode == "hardened":
                self.purchase_keys[(api_key, user, key)] = pid
            return 200, self._purchase_view(pid)

    @staticmethod
    def _callback_allowed(callback: str) -> bool:
        try:
            u = urlparse(callback)
        except ValueError:
            return False
        return (
            u.scheme == "https"
            and u.hostname is not None
            and u.hostname.lower() in CALLBACK_HOSTS
            and u.username is None
        )

    @staticmethod
    def _merchant(api_key: str) -> str:
        # The fixture uses the raw key as the project id, matching the purchase
        # and grant records; API_KEYS only gates authentication.
        return api_key

    def webhook_config(self, merchant: str) -> dict:
        cfg = self.webhook_configs.get(merchant)
        if cfg is None:
            cfg = {"url": "https://merchant.example.com/opcpay/webhook",
                   "enabled": True, "secret": WEBHOOK_SECRET,
                   "configured": False}
            self.webhook_configs[merchant] = cfg
        return cfg

    def _webhook_url_allowed(self, url: str) -> bool:
        """Hardened registration: HTTPS + public host; no localhost/link-local."""
        try:
            u = urlparse(url)
        except ValueError:
            return False
        if u.scheme != "https" or not u.hostname or u.username is not None:
            return False
        host = u.hostname.lower()
        if host == "localhost" or host.endswith(".local"):
            return False
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return True
        return not (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_reserved or ip.is_multicast or ip.is_unspecified)

    def save_webhook(self, api_key: str, body: dict) -> tuple[int, dict]:
        merchant = self._merchant(api_key)
        url = str(body.get("url") or "").strip()
        enabled = bool(body.get("enabled", True))
        if not url:
            return 400, {"error": "missing_url"}
        if self.mode == "hardened" and not self._webhook_url_allowed(url):
            return 400, {"error": "bad_webhook_url", "url": url}
        with self.lock:
            cfg = self.webhook_config(merchant)
            fresh = not cfg["configured"]
            cfg["url"] = url
            cfg["enabled"] = enabled
            cfg["configured"] = True
            if fresh:
                cfg["secret"] = secrets.token_hex(24).encode()
            return 200, {"configured": True, "url": url, "enabled": enabled,
                         "secret": cfg["secret"].decode()}

    def webhook_settings(self, api_key: str) -> tuple[int, dict]:
        with self.lock:
            cfg = self.webhook_config(self._merchant(api_key))
            return 200, {"configured": cfg["configured"], "url": cfg["url"],
                         "enabled": cfg["enabled"]}

    def rotate_webhook(self, api_key: str) -> tuple[int, dict]:
        with self.lock:
            cfg = self.webhook_config(self._merchant(api_key))
            cfg["secret"] = secrets.token_hex(24).encode()
            cfg["configured"] = True
            return 200, {"secret": cfg["secret"].decode()}

    def events_list(self, api_key: str) -> tuple[int, dict]:
        merchant = self._merchant(api_key)
        with self.lock:
            items = [dict(e) for e in self.webhook_log if e.get("merchant") == merchant]
        return 200, {"items": items, "has_more": False, "next_before_id": ""}

    def retry_event(self, api_key: str, event_id: str) -> tuple[int, dict]:
        merchant = self._merchant(api_key)
        with self.lock:
            cfg = self.webhook_config(merchant)
            entry = next((e for e in self.webhook_log
                          if e.get("event_id") == event_id
                          and e.get("merchant") == merchant), None)
            if entry is None:
                return 404, {"error": "not_found"}
            if self.mode == "hardened":
                if not cfg["enabled"]:
                    return 403, {"error": "webhook_disabled"}
                if event_id in self.seen_events:
                    return 200, {"queued": True, "duplicate": True}
                self.seen_events.add(event_id)
            self.retry_log.append({"event_id": event_id, "merchant": merchant})
            self.webhook_effects.append(event_id)
            return 200, {"queued": True}

    def _purchase_view(self, pid: str) -> dict:
        p = self.purchases[pid]
        if self.mode == "hardened":
            url = f"https://pay.example.com/checkout/{pid}"
        else:
            # defect: unvalidated sku_id and callback are reflected into the URL
            url = f"https://pay.example.com/checkout?sku={p['sku_id']}&pid={pid}"
            if p.get("callback_url"):
                url += f"&return={p['callback_url']}"
        return {
            "status": p["entry_status"],
            "idempotency_key": p["idempotency_key"],
            "purchase_id": pid,          # benchmark extension, not in the SDK type
            "sku_id": p["sku_id"],       # benchmark extension
            "amount": p["amount"],       # benchmark extension
            "purchase_url": url,
        }

    # -- grants ------------------------------------------------------------
    def _grant(self, p: dict) -> dict:
        if p["kind"] == "duration":
            remaining, expires = None, self.now() + p["days"] * 86400
        elif p["kind"] in ("count", "points"):
            remaining, expires = p["units"], None
        else:
            remaining, expires = None, None
        g = {
            "grant_id": "g_" + secrets.token_hex(5),
            "merchant": p["merchant"],
            "user_id": p["user_id"],
            "purchase_id": p["purchase_id"],
            "kind": p["kind"],
            "remaining": remaining,
            "expires_at": expires,
            "status": "active",
        }
        self.grants.append(g)
        return g

    def _grants(self, api_key: str, user: str) -> list[dict]:
        if self.mode == "naive":
            # defect: global user namespace, no merchant isolation
            return [g for g in self.grants if g["user_id"] == user]
        return [g for g in self.grants if g["merchant"] == api_key and g["user_id"] == user]

    def _active(self, g: dict) -> bool:
        if g["status"] != "active":
            return False
        if g["expires_at"] is not None and g["expires_at"] <= self.now():
            return False
        return g["remaining"] is None or g["remaining"] > 0

    def _naive_active(self, g: dict) -> bool:
        # naive keeps the expiry check (so N3 still passes) but ignores
        # refund status, which is what E6 detects.
        if g["expires_at"] is not None and g["expires_at"] <= self.now():
            return False
        return g["remaining"] is None or g["remaining"] > 0

    def _remaining(self, api_key: str, user: str) -> int:
        out = 0
        for g in self._grants(api_key, user):
            if self.mode == "naive":
                if self._naive_active(g) and g["remaining"] is not None:
                    out += g["remaining"]
            elif self._active(g) and g["remaining"] is not None:
                out += g["remaining"]
        return out

    def _pick(self, api_key: str, user: str, amount: int) -> dict | None:
        for g in self._grants(api_key, user):
            if self.mode == "naive":
                if self._naive_active(g) and g["kind"] in ("count", "points"):
                    if g["remaining"] is None or g["remaining"] >= amount:
                        return g
            elif self._active(g) and g["kind"] in ("count", "points"):
                if g["remaining"] is not None and g["remaining"] >= amount:
                    return g
        return None

    # -- access ------------------------------------------------------------
    def access(self, api_key: str, body: dict) -> tuple[int, dict]:
        user = str(body.get("user_id") or "").strip()
        amount = body.get("amount", 1)
        if not user:
            return 400, {"error": "missing_field"}
        if isinstance(amount, bool) or not isinstance(amount, int):
            return 400, {"error": "bad_amount", "amount": amount}
        if self.mode == "hardened" and amount <= 0:
            return 400, {"error": "bad_amount", "amount": amount}
        with self.lock:
            gs = self._grants(api_key, user)
            if self.mode == "naive":
                active = [g for g in gs if self._naive_active(g)]
            else:
                active = [g for g in gs if self._active(g)]
            remaining = sum(g["remaining"] for g in active if g["remaining"] is not None)
            duration_ok = any(g["kind"] in ("duration", "one_time") for g in active)
            granted = bool(active) and (remaining >= amount or duration_ok)
            units = {g["kind"] for g in active}
            return 200, {
                "access_granted": granted,
                "decision": "ALLOW" if granted else "DENY",
                "remaining": remaining,
                "quota_unit": "POINT" if units == {"points"} else "COUNT",
                "grants": [
                    {"kind": g["kind"], "remaining": g["remaining"],
                     "expires_at": self._iso(g["expires_at"])}
                    for g in active
                ],
            }

    # -- consume -----------------------------------------------------------
    def consume(self, api_key: str, body: dict) -> tuple[int, dict]:
        user = str(body.get("user_id") or "").strip()
        key = str(body.get("idempotency_key") or "").strip()
        reason = body.get("reason")
        amount = body.get("amount")
        if not user or not key:
            return 400, {"error": "missing_field"}
        if isinstance(amount, bool) or not isinstance(amount, int):
            return 400, {"error": "bad_amount", "amount": amount}
        if self.mode == "hardened" and amount <= 0:
            return 400, {"error": "bad_amount", "amount": amount}

        if self.mode == "hardened":
            with self.lock:
                prev = self.consumptions.get((api_key, user, key))
                if prev is not None:
                    return 200, dict(prev)
                g = self._pick(api_key, user, amount)
                if g is None:
                    return 200, {"status": "FAILED", "confirmed": False,
                                 "reason_code": "INSUFFICIENT_QUOTA",
                                 "idempotency_key": key,
                                 "remaining": self._remaining(api_key, user)}
                g["remaining"] -= amount
                res = {
                    "status": "SUCCEEDED",
                    "confirmed": True,
                    "idempotency_key": key,
                    "amount": amount,
                    "consumed": amount,
                    "remaining": g["remaining"],
                    "quota_unit": "POINT" if g["kind"] == "points" else "COUNT",
                    "reason": reason,
                    "grant_id": g["grant_id"],
                }
                self.consumptions[(api_key, user, key)] = res
                return 200, res

        # naive: idempotency ignored, negative amounts credit the balance,
        # and the read/write pair is not atomic.
        with self.lock:
            g = self._pick(api_key, user, max(amount, 0))
            if g is None:
                return 200, {"status": "FAILED", "confirmed": False,
                             "reason_code": "INSUFFICIENT_QUOTA",
                             "idempotency_key": key, "remaining": 0}
            seen = g["remaining"]
        time.sleep(0.05)  # widen the TOCTOU window
        with self.lock:
            if amount < 0:
                g["remaining"] = (seen or 0) - amount
            elif seen is not None and seen >= amount:
                g["remaining"] = seen - amount
            else:
                return 200, {"status": "FAILED", "confirmed": False,
                             "reason_code": "INSUFFICIENT_QUOTA",
                             "idempotency_key": key, "remaining": seen}
        return 200, {"status": "SUCCEEDED", "confirmed": True, "amount": amount,
                     "consumed": amount, "idempotency_key": key,
                     "remaining": g["remaining"],
                     "quota_unit": "POINT" if g["kind"] == "points" else "COUNT",
                     "reason": reason, "grant_id": g["grant_id"]}

    # -- purchase / consumption queries ------------------------------------
    def purchase_query(self, api_key: str, body: dict) -> tuple[int, dict]:
        user = str(body.get("user_id") or "").strip()
        key = str(body.get("idempotency_key") or "").strip()
        if not user or not key:
            return 400, {"error": "missing_field"}
        with self.lock:
            pid = self.purchase_keys.get((api_key, user, key))
            p = self.purchases.get(pid) if pid else None
            if p is None:
                return 404, {"error": "not_found"}
            return 200, self._purchase_record(pid)

    def _purchase_record(self, pid: str) -> dict:
        """Official OpenAPI 1.1.2 Record shape for POST /purchase/query."""
        p = self.purchases[pid]
        created = self._iso(p["created_at"])
        return {
            "id": pid,
            "kind": "purchase",
            "idempotency_key": p["idempotency_key"],
            "status": p["entry_status"],
            "user_id": p["user_id"],
            "sku_id": p["sku_id"],
            "amount": f"{p['amount']:.2f}",
            "reason": None,
            "response": {
                "status": p["entry_status"],
                "idempotency_key": p["idempotency_key"],
                "purchase_url": self._purchase_view(pid)["purchase_url"],
                "confirmed": p["payment_status"] == "PAID",
            },
            "expires_at": None,
            "created_at": created,
            "updated_at": created,
            "purchase_id": pid,  # legacy extension
        }

    def consumption(self, api_key: str, body: dict) -> tuple[int, dict]:
        user = str(body.get("user_id") or "").strip()
        key = str(body.get("idempotency_key") or "").strip()
        if not user or not key:
            return 400, {"error": "missing_field"}
        with self.lock:
            rec = self.consumptions.get((api_key, user, key))
            if rec is None:
                return 404, {"error": "not_found"}
            return 200, dict(rec)

    # -- transactions/query (SDK 0.3.5) -----------------------------------
    def transaction_query(self, api_key: str, body: dict) -> tuple[int, dict]:
        user = str(body.get("user_id") or "").strip()
        key = str(body.get("idempotency_key") or "").strip()
        if not user or not key:
            return 400, {"error": "missing_field"}
        if self.mode == "hardened":
            now = self.now()
            hits = [t for t in self.query_hits.get(api_key, []) if now - t < 60]
            if len(hits) >= RATE_LIMIT_QUERIES:
                return 429, {"error": "rate_limited",
                             "retry_after": max(1, int(60 - (now - hits[0])))}
            hits.append(now)
            self.query_hits[api_key] = hits
        with self.lock:
            if self.mode == "hardened":
                pid = self.purchase_keys.get((api_key, user, key))
                p = self.purchases.get(pid)
            else:
                # defect: global lookup across merchants, and no 404 for an
                # unknown key (returns UNKNOWN instead).
                candidates = [x for x in self.purchases.values() if x["user_id"] == user]
                p = candidates[-1] if candidates else None
            if p is None:
                if self.mode == "hardened":
                    return 404, {"error": "not_found"}
                return 200, {"status": "UNKNOWN"}
            status = p["payment_status"]
            if self.mode == "naive" and status == "PENDING":
                status = "PAID"  # defect: premature PAID
            return 200, {
                "project_id": p["merchant"],
                "user_id": p["user_id"],
                "idempotency_key": p["idempotency_key"],
                "status": status,
                "trade_no": p.get("trade_no"),
                "checked_at": self._iso(p.get("checked_at")),
                "status_source": p.get("status_source"),
                "created_at": self._iso(p["created_at"]),
                "fetched_at": self._iso(self.now()),
            }

    # -- capabilities ------------------------------------------------------
    @staticmethod
    def capabilities() -> dict:
        return {
            "api_version": "v1",
            "provider_configured": True,
            "capabilities": {
                "purchase_entry": True, "entitlement_query": True,
                "consumption": True, "purchase_request_query": True,
                "purchase_request_list": False, "consumption_list": False,
                "webhooks": True, "entitlement_monitoring": True,
                "transaction_query": True, "transaction_list": False,
                "refund": False, "refund_query": False, "bills": False,
                "automatic_renewal": False, "consumption_reversal": False,
            },
            "webhook_events": [
                "entitlement.observed", "entitlement.updated",
                "consumption.succeeded", "consumption.failed",
            ],
            "limitations": ["refunds are observed via the test-only admin surface"],
        }

    # -- payments / refunds ------------------------------------------------
    def mark_paid(self, pid: str) -> tuple[int, dict]:
        with self.lock:
            p = self.purchases.get(pid)
            if p is None:
                return 404, {"error": "not_found"}
            if self.mode == "hardened" and p["payment_status"] == "PAID":
                return 200, {"status": "PAID", "already": True}
            if self.mode == "hardened" and p["payment_status"] == "REFUNDED":
                # A refunded purchase never becomes payable again: re-granting
                # here would resurrect an entitlement the refund revoked.
                return 409, {"error": "refunded_purchase"}
            p["payment_status"] = "PAID"
            p["trade_no"] = p.get("trade_no") or "2026" + str(int(self.now()))[-16:]
            p["checked_at"] = self.now()
            p["status_source"] = "ALIPAY_PURCHASE_QUERY_V3"
            self._grant(p)
            return 200, {"status": "PAID", "purchase_id": pid}

    def refund(self, pid: str) -> tuple[int, dict]:
        with self.lock:
            p = self.purchases.get(pid)
            if p is None:
                return 404, {"error": "not_found"}
            p["payment_status"] = "REFUNDED"
            p["checked_at"] = self.now()
            p["status_source"] = "ALIPAY_PURCHASE_QUERY_V3"
            if self.mode == "hardened":
                for g in self.grants:
                    if g["purchase_id"] == pid:
                        g["status"] = "refunded"
                        g["remaining"] = 0
            # naive: grants keep their balance, which is what E6 detects
            return 200, {"status": "REFUNDED", "purchase_id": pid}

    # -- webhook (SDK 0.3.5 scheme) ---------------------------------------
    def webhook(self, headers, raw: bytes, body: dict) -> tuple[int, dict]:
        eid = body.get("id")
        etype = body.get("type")
        merchant = str(body.get("project_id") or "merchant_a")
        cfg = self.webhook_config(merchant)
        if self.mode == "hardened":
            if not cfg["enabled"]:
                return 403, {"error": "webhook_disabled"}
            sig = str(headers.get("yirenfu-signature", ""))
            ts = str(headers.get("yirenfu-timestamp", ""))
            header_eid = str(headers.get("yirenfu-event-id", ""))
            if not sig or not ts:
                return 401, {"error": "missing_signature"}
            if not ts.isdigit() or not (10 <= len(ts) <= 12):
                return 401, {"error": "bad_timestamp"}
            if abs(time.time() - int(ts)) > WEBHOOK_TOLERANCE_SECONDS:
                return 401, {"error": "stale_timestamp"}
            if not sig.startswith("v1=") or len(sig) != 67:
                return 401, {"error": "bad_signature"}
            expected = "v1=" + hmac.new(
                cfg["secret"], f"{ts}.".encode() + raw, hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(sig, expected):
                return 401, {"error": "bad_signature"}
            if not eid or eid != header_eid:
                return 401, {"error": "event_id_mismatch"}
            if etype not in ("entitlement.observed", "entitlement.updated",
                             "consumption.succeeded", "consumption.failed"):
                return 400, {"error": "unknown_event"}
            with self.lock:
                if eid in self.seen_events:
                    return 200, {"ok": True, "duplicate": True}
                self.seen_events.add(eid)

        with self.lock:
            self.webhook_effects.append(eid)
            self.webhook_log.append({"event_id": eid, "type": etype,
                                     "user_id": body.get("user_id"),
                                     "merchant": merchant})
        return 200, {"ok": True}

    # -- admin -------------------------------------------------------------
    def snapshot(self) -> dict:
        with self.lock:
            return {
                "purchases": [
                    {k: p[k] for k in ("purchase_id", "user_id", "sku_id",
                                       "amount", "entry_status", "payment_status",
                                       "merchant")}
                    for p in self.purchases.values()
                ],
                "grants": [dict(g) for g in self.grants],
                "webhook_effects": list(self.webhook_effects),
                "now": self.now(),
            }


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args) -> None:  # silence request logging
        pass

    @property
    def state(self) -> State:
        return self.server.state  # type: ignore[attr-defined]

    def _read_json(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            return json.loads(raw or b"{}"), raw
        except json.JSONDecodeError:
            return None, raw

    def _send(self, code: int, obj: dict) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _api_key(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        key = auth[7:].strip()
        return key if key in API_KEYS else None

    def _path(self) -> str:
        path = self.path.split("?")[0]
        if path.startswith(API_PREFIX):
            path = path[len(API_PREFIX):] or "/"
        return path

    # -- GET ---------------------------------------------------------------
    def do_GET(self) -> None:
        path = self._path()
        if path == "/product":
            if not self._api_key():
                return self._send(401, {"error": "unauthorized"})
            return self._send(200, self.state.product_view())
        if path == "/capabilities":
            if not self._api_key():
                return self._send(401, {"error": "unauthorized"})
            return self._send(200, self.state.capabilities())
        if path == "/_admin/state":
            return self._send(200, self.state.snapshot())
        if path == "/webhook":
            key = self._api_key()
            if not key:
                return self._send(401, {"error": "unauthorized"})
            code, obj = self.state.webhook_settings(key)
            return self._send(code, obj)
        if path == "/events/list":
            key = self._api_key()
            if not key:
                return self._send(401, {"error": "unauthorized"})
            code, obj = self.state.events_list(key)
            return self._send(code, obj)
        return self._send(404, {"error": "not_found"})

    # -- PUT ---------------------------------------------------------------
    def do_PUT(self) -> None:
        body, _raw = self._read_json()
        path = self._path()
        if body is None:
            return self._send(400, {"error": "bad_json"})
        key = self._api_key()
        if not key:
            return self._send(401, {"error": "unauthorized"})
        if path == "/webhook":
            code, obj = self.state.save_webhook(key, body)
            return self._send(code, obj)
        return self._send(404, {"error": "not_found"})

    # -- POST --------------------------------------------------------------
    def do_POST(self) -> None:
        body, raw = self._read_json()
        path = self._path()
        if body is None:
            return self._send(400, {"error": "bad_json"})
        if path.startswith("/_admin/"):
            return self._admin(path, body)
        if path == "/webhook":
            code, obj = self.state.webhook(self.headers, raw, body)
            return self._send(code, obj)

        key = self._api_key()
        if not key:
            return self._send(401, {"error": "unauthorized"})
        if path == "/webhook/rotate":
            code, obj = self.state.rotate_webhook(key)
            return self._send(code, obj)
        if path == "/events/list":
            code, obj = self.state.events_list(key)
            return self._send(code, obj)
        retry = re.fullmatch(r"/events/([^/]+)/retry", path)
        if retry:
            code, obj = self.state.retry_event(key, retry.group(1))
            return self._send(code, obj)
        routes = {
            "/purchase": self.state.purchase,
            "/purchase/query": self.state.purchase_query,
            "/access": self.state.access,
            "/consume": self.state.consume,
            "/consumption": self.state.consumption,
            "/transactions/query": self.state.transaction_query,
            "/transactionQuery": self.state.transaction_query,  # pre-0.3.5 alias
        }
        fn = routes.get(path)
        if fn is None:
            if path in ("/refunds", "/refunds/query", "/transactions/list",
                        "/bills", "/purchases/list", "/consumptions/list"):
                return self._send(501, {"error": "not_implemented",
                                        "capability": path.strip("/").replace("/", "_")})
            return self._send(404, {"error": "not_found"})
        code, obj = fn(key, body)
        return self._send(code, obj)

    def _admin(self, path: str, body: dict) -> None:
        st = self.state
        if path == "/_admin/reset":
            st.reset()
            return self._send(200, {"ok": True})
        if path == "/_admin/advance_time":
            return self._send(200, {"now": st.advance(body.get("seconds", 0))})
        if path == "/_admin/mark_paid":
            code, obj = st.mark_paid(body.get("purchase_id", ""))
            return self._send(code, obj)
        if path == "/_admin/refund":
            code, obj = st.refund(body.get("purchase_id", ""))
            return self._send(code, obj)
        if path == "/_admin/sign_webhook":
            pid = body.get("purchase_id", "")
            event_id = body.get("event_id") or "evt_" + secrets.token_hex(6)
            p = st.purchases.get(pid)
            if p is None:
                return self._send(404, {"error": "not_found"})
            payload = {
                "id": event_id,
                "type": "entitlement.observed",
                "project_id": p["merchant"],
                "user_id": p["user_id"],
                "created_at": st._iso(st.now()),
                "data": {"purchase_id": pid, "decision": "ALLOW",
                         "idempotency_key": p["idempotency_key"]},
            }
            raw = json.dumps(payload, separators=(",", ":")).encode()
            ts = str(int(time.time()))
            secret = st.webhook_config(p["merchant"])["secret"]
            sig = "v1=" + hmac.new(
                secret, f"{ts}.".encode() + raw, hashlib.sha256
            ).hexdigest()
            return self._send(200, {
                "headers": {
                    "yirenfu-signature": sig,
                    "yirenfu-timestamp": ts,
                    "yirenfu-event-id": event_id,
                },
                "body": payload,
                "raw": raw.decode(),
            })
        return self._send(404, {"error": "not_found"})


class _StressServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with a listen backlog deep enough for stress runs."""

    daemon_threads = True
    request_queue_size = 256


class MockServer:
    """In-process server bound to an ephemeral loopback port."""

    def __init__(self, mode: str = "hardened") -> None:
        self.state = State(mode)
        self.httpd = _StressServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.httpd.state = self.state  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        host, port = self.httpd.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> "MockServer":
        self.thread.start()
        return self

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    def __enter__(self) -> "MockServer":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()


def main() -> None:
    ap = argparse.ArgumentParser(description="AgentPayBench mock opcpay server")
    ap.add_argument("--mode", choices=["hardened", "naive"], default="hardened")
    ap.add_argument("--port", type=int, default=8787)
    args = ap.parse_args()
    state = State(args.mode)
    httpd = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    httpd.daemon_threads = True
    httpd.state = state  # type: ignore[attr-defined]
    print(f"AgentPayBench mock [{args.mode}] on http://127.0.0.1:{args.port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
