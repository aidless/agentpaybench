#!/usr/bin/env python3
"""Thin client for the opcpay surface used by AgentPayBench.

Every method returns ``(http_status, payload)``.  Transport errors are
returned as ``(0, {"error": ...})`` so a scenario can assert on them just
like on a 4xx/5xx response.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request


class Client:
    def __init__(self, base_url: str, api_key: str = "test_key", timeout: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _request(self, method: str, path: str, body=None, headers=None, raw: bytes | None = None):
        if raw is not None:
            data = raw
        elif body is not None:
            data = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode()
        else:
            data = None
        req = urllib.request.Request(self.base_url + path, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if self.api_key:
            req.add_header("Authorization", "Bearer " + self.api_key)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read() or b"{}")
                return resp.status, payload
        except urllib.error.HTTPError as exc:
            try:
                payload = json.loads(exc.read() or b"{}")
            except Exception:
                payload = {}
            return exc.code, payload
        except Exception as exc:  # connection refused, timeout, ...
            return 0, {"error": f"{type(exc).__name__}: {exc}"}

    # -- public surface ----------------------------------------------------
    def product(self):
        return self._request("GET", "/product")

    def purchase(self, user_id: str, idempotency_key: str, sku_id: str, **extra):
        body = {"user_id": user_id, "idempotency_key": idempotency_key, "sku_id": sku_id}
        body.update(extra)
        return self._request("POST", "/purchase", body)

    def access(self, user_id: str, amount: int = 1):
        return self._request("POST", "/access", {"user_id": user_id, "amount": amount})

    def consume(self, user_id: str, idempotency_key: str, amount: int, reason: str = ""):
        return self._request("POST", "/consume", {
            "user_id": user_id,
            "idempotency_key": idempotency_key,
            "amount": amount,
            "reason": reason,
        })

    def transaction_query(self, user_id: str, idempotency_key: str):
        return self._request("POST", "/transactions/query", {
            "user_id": user_id,
            "idempotency_key": idempotency_key,
        })

    def purchase_query(self, user_id: str, idempotency_key: str):
        return self._request("POST", "/purchase/query", {
            "user_id": user_id,
            "idempotency_key": idempotency_key,
        })

    def consumption(self, user_id: str, idempotency_key: str):
        return self._request("POST", "/consumption", {
            "user_id": user_id,
            "idempotency_key": idempotency_key,
        })

    def capabilities(self):
        return self._request("GET", "/capabilities")

    def webhook(self, headers: dict, raw: bytes):
        return self._request("POST", "/webhook", headers=headers, raw=raw)

    def save_webhook(self, url: str, enabled: bool = True):
        return self._request("PUT", "/webhook", {"url": url, "enabled": enabled})

    def webhook_settings(self):
        return self._request("GET", "/webhook")

    def rotate_webhook(self):
        return self._request("POST", "/webhook/rotate", {})

    def events(self):
        return self._request("GET", "/events/list")

    def retry_event(self, event_id: str):
        return self._request("POST", "/events/" + urllib.parse.quote(event_id, safe="") + "/retry", {})

    # -- test-only ---------------------------------------------------------
    def admin(self, action: str, body=None):
        return self._request("POST", "/_admin/" + action, body or {})

    def state(self):
        return self._request("GET", "/_admin/state")

    def clone(self, api_key: str) -> "Client":
        return Client(self.base_url, api_key, self.timeout)
