#!/usr/bin/env python3
"""Client-side guard for the three gaps in opcpay SDK 0.3.5 (F1-F3).

The SDK deliberately leaves these to the application:

  F1  purchase()/consume() silently drop an empty idempotency key
  F2  access()/consume() forward 0, negative, NaN and non-numeric amounts
  F3  verifyWebhook() checks signature/time/event-id but not replay

This module is the reference guard used by the C1-C3 scenarios:

  C1  every write carries a non-empty, stable idempotency key
  C2  invalid amounts never reach the network
  C3  a replayed webhook event is applied at most once

The guard is deliberately small and dependency-free; it is not a substitute
for server-side checks.  C3 is tested against the *naive* server on purpose:
a client guard must hold even when the server does not dedupe.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import threading
import time
import uuid
from pathlib import Path


class GuardError(ValueError):
    """A client-side validation failure; nothing was sent."""


# -- F2: amount validation --------------------------------------------------
MAX_AMOUNT = 1_000_000


def validate_amount(amount, *, maximum: int = MAX_AMOUNT, allow_zero: bool = False) -> int:
    """Return a positive int or raise GuardError.

    Rejects bool (a subclass of int), NaN/inf, fractions, strings, zero and
    negatives.  Integral floats are accepted and normalised.
    """
    if isinstance(amount, bool) or amount is None:
        raise GuardError(f"amount must be a number, got {amount!r}")
    if isinstance(amount, float):
        if not math.isfinite(amount) or not amount.is_integer():
            raise GuardError(f"amount must be a finite integer, got {amount!r}")
        amount = int(amount)
    if not isinstance(amount, int):
        raise GuardError(f"amount must be an int, got {type(amount).__name__}")
    if amount < 0 or (amount == 0 and not allow_zero):
        raise GuardError(f"amount must be positive, got {amount}")
    if amount > maximum:
        raise GuardError(f"amount exceeds {maximum}, got {amount}")
    return amount


# -- F1: idempotency keys ---------------------------------------------------
class KeyStore:
    """Stable key per logical operation, optionally persisted to JSON.

    Persistence matters: a retry after a process restart must reuse the key,
    otherwise the server sees a new operation.
    """

    def __init__(self, path: str | os.PathLike | None = None) -> None:
        self.path = Path(path) if path else None
        self._data: dict[str, str] = {}
        if self.path and self.path.exists():
            try:
                self._data = json.loads(self.path.read_text())
            except (OSError, ValueError) as exc:
                raise GuardError(f"cannot read key store {self.path}: {exc}") from exc

    def resolve(self, key: str | None, scope: str | None = None) -> str:
        if key is not None and str(key).strip():
            return str(key).strip()
        if scope and scope in self._data:
            return self._data[scope]
        fresh = "grd_" + uuid.uuid4().hex
        if scope:
            self._data[scope] = fresh
            self._flush()
        return fresh

    def _flush(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(self._data, indent=2, sort_keys=True))
        os.replace(tmp, self.path)


# -- F3: webhook verification + replay --------------------------------------
_TS = re.compile(r"^\d{10,12}$")
_SIG = re.compile(r"^v1=[a-f0-9]{64}$")


def verify_webhook(raw: bytes, headers: dict, secret,
                   now: int | None = None, window: int = 300) -> dict:
    """Verify an opcpay webhook exactly like SDK 0.3.5, then return the event."""
    if not isinstance(raw, (bytes, bytearray)) or not secret:
        raise GuardError("raw body (bytes) and secret are required")
    stamp = str(headers.get("yirenfu-timestamp") or "")
    signature = str(headers.get("yirenfu-signature") or "")
    now = int(time.time()) if now is None else int(now)
    if not _TS.match(stamp) or abs(now - int(stamp)) > window:
        raise GuardError("stale or malformed timestamp")
    if not _SIG.match(signature):
        raise GuardError("malformed signature")
    secret_bytes = secret.encode() if isinstance(secret, str) else bytes(secret)
    expected = "v1=" + hmac.new(
        secret_bytes, stamp.encode() + b"." + bytes(raw), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise GuardError("signature mismatch")
    try:
        event = json.loads(bytes(raw))
    except ValueError as exc:
        raise GuardError(f"invalid JSON: {exc}") from exc
    if not event.get("id") or event["id"] != headers.get("yirenfu-event-id"):
        raise GuardError("event id mismatch")
    return event


class ReplayGuard:
    """Remember event ids for a TTL; ``accept`` returns False on a replay."""

    def __init__(self, ttl: int = 3600, max_entries: int = 100_000) -> None:
        self.ttl = ttl
        self.max_entries = max_entries
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def accept(self, event_id: str, now: float | None = None) -> bool:
        if not event_id:
            raise GuardError("event id is required")
        now = time.time() if now is None else now
        with self._lock:
            self._purge(now)
            if event_id in self._seen:
                return False
            if len(self._seen) >= self.max_entries:
                oldest = min(self._seen, key=self._seen.get)
                self._seen.pop(oldest, None)
            self._seen[event_id] = now
            return True

    def _purge(self, now: float) -> None:
        cutoff = now - self.ttl
        for eid, seen in list(self._seen.items()):
            if seen < cutoff:
                self._seen.pop(eid, None)


# -- guards -----------------------------------------------------------------
class StrictGuard:
    def __init__(self, keys: KeyStore | None = None, replay: ReplayGuard | None = None) -> None:
        self.keys = keys or KeyStore()
        self.replay = replay or ReplayGuard()

    def key(self, key: str | None, scope: str) -> str:
        return self.keys.resolve(key, scope)

    def amount(self, amount) -> int:
        return validate_amount(amount)

    def verify(self, raw: bytes, headers: dict, secret: str) -> dict:
        return verify_webhook(raw, headers, secret)

    def accept_event(self, event_id: str) -> bool:
        return self.replay.accept(event_id)


class NaiveGuard:
    """The defect: pass everything through.  Used to prove C1-C3 can fail."""

    def key(self, key: str | None, scope: str) -> str:
        return "" if key is None else str(key)

    def amount(self, amount):
        return amount

    def verify(self, raw: bytes, headers: dict, secret: str) -> dict:
        return json.loads(raw)

    def accept_event(self, event_id: str) -> bool:
        return True


class QueryTooSoon(GuardError):
    """C4: a status poll arrived before the 15 s backoff elapsed."""

    def __init__(self, wait: float) -> None:
        self.wait = wait
        super().__init__(f"query too soon; retry in {wait:.1f}s")


class QueryThrottle:
    """C4: never re-query the same transaction faster than ``min_interval``.

    The provider asks for >= 15 s between status queries and charges the
    credential a 120/min budget.  Callers pass a fake clock in tests so the
    check is deterministic and costs no wall time.
    """

    def __init__(self, min_interval: float = 15.0, clock=None) -> None:
        self.min_interval = float(min_interval)
        self.clock = clock or time.monotonic
        self._last: dict[str, float] = {}

    def acquire(self, key: str) -> None:
        now = self.clock()
        last = self._last.get(key)
        if last is not None:
            wait = self.min_interval - (now - last)
            if wait > 0:
                raise QueryTooSoon(wait)
        self._last[key] = now


class GuardedClient:
    """Thin wrapper around ``client.Client`` that applies the guard first."""

    def __init__(self, client, guard=None, throttle=None) -> None:
        self.client = client
        self.guard = guard or StrictGuard()
        self.throttle = throttle or QueryThrottle()
        self.last_key: str | None = None

    def purchase(self, user_id: str, sku_id: str, *, idempotency_key: str | None = None,
                 callback_url: str | None = None):
        self.last_key = self.guard.key(
            idempotency_key, f"purchase:{user_id}:{sku_id}")
        extra = {"callback_url": callback_url} if callback_url else {}
        return self.client.purchase(user_id, self.last_key, sku_id, **extra)

    def access(self, user_id: str, amount=1):
        amount = self.guard.amount(amount)
        return self.client.access(user_id, amount)

    def consume(self, user_id: str, amount, *, reason: str = "",
                idempotency_key: str | None = None):
        amount = self.guard.amount(amount)
        self.last_key = self.guard.key(
            idempotency_key, f"consume:{user_id}:{amount}:{reason}")
        return self.client.consume(user_id, self.last_key, amount, reason)

    def transaction_query(self, user_id: str, idempotency_key: str):
        """Status poll with the C4 backoff applied before the request."""
        self.throttle.acquire(f"query:{user_id}:{idempotency_key}")
        return self.client.transaction_query(user_id, idempotency_key)

    def deliver_webhook(self, raw: bytes, headers: dict, secret: str):
        """Verify, dedupe, then deliver.  Returns (code, payload, event)."""
        event = self.guard.verify(raw, headers, secret)
        if not self.guard.accept_event(event["id"]):
            return 200, {"duplicate": True, "event_id": event["id"]}, event
        code, body = self.client.webhook(headers, raw)
        return code, body, event
