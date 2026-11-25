#!/usr/bin/env python3
"""Contract conformance: drive the mock, validate against the OFFICIAL OpenAPI.

The main selftest compares the mock against itself (hardened vs naive).  This
checker uses an external yardstick: the real opcpay OpenAPI 1.1.2 spec, fetched
without credentials from
  https://ai6666.com/opcpay/api/v1/pay/developer/openapi.json

It drives each implemented endpoint on the hardened mock and checks the
response against the spec's declared response schema (required fields, enums,
types, $ref, items, and additionalProperties:false where declared).  It also
checks the capability-flag contract and the method/path inventory.

This needs no merchant key and makes no real payment: the spec is public and
the traffic stays on the in-process mock.

    python3 openapi_conformance.py
    python3 openapi_conformance.py --json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from client import Client
from mock_server import MockServer

SPEC_PATH = Path(__file__).with_name("opcpay-openapi-1.1.2.json")


def load_spec() -> dict:
    with SPEC_PATH.open(encoding="utf-8") as fh:
        return json.load(fh)


# -- a small JSON-Schema subset validator ----------------------------------
def _deref(schema: dict, spec: dict) -> dict:
    ref = schema.get("$ref")
    if not ref:
        return schema
    node = spec
    for part in ref.lstrip("#/").split("/"):
        node = node[part.replace("~1", "/").replace("~0", "~")]
    return {**node, **{k: v for k, v in schema.items() if k != "$ref"}}


def _type_ok(value, declared) -> bool:
    if isinstance(declared, list):
        return any(_type_ok(value, t) for t in declared)
    mapping = {
        "object": lambda v: isinstance(v, dict),
        "array": lambda v: isinstance(v, list),
        "string": lambda v: isinstance(v, str),
        "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
        "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
        "boolean": lambda v: isinstance(v, bool),
        "null": lambda v: v is None,
    }
    fn = mapping.get(declared)
    return fn(value) if fn else True


def validate(value, schema: dict, spec: dict, path="$") -> list[str]:
    """Return a list of contract violations (empty == conforms)."""
    schema = _deref(schema, spec)
    errors: list[str] = []
    if "type" in schema and not _type_ok(value, schema["type"]):
        errors.append(f"{path}: type {type(value).__name__} != {schema['type']}")
        return errors  # deeper checks would be meaningless
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: {value!r} not in enum {schema['enum']}")
    if isinstance(value, dict):
        for req in schema.get("required", []):
            if req not in value:
                errors.append(f"{path}: missing required field '{req}'")
        props = schema.get("properties", {})
        for k, v in value.items():
            if k in props:
                errors += validate(v, props[k], spec, f"{path}.{k}")
            elif schema.get("additionalProperties") is False:
                errors.append(f"{path}: unexpected field '{k}' (additionalProperties:false)")
    if isinstance(value, list) and "items" in schema:
        for i, item in enumerate(value):
            errors += validate(item, schema["items"], spec, f"{path}[{i}]")
    return errors


# -- drive the mock --------------------------------------------------------
def probe(spec: dict) -> dict:
    with MockServer("hardened") as srv:
        c = Client(srv.base_url)
        samples: dict[str, tuple[int, dict]] = {}

        samples["GET /product"] = c.product()
        samples["GET /capabilities"] = c.capabilities()

        code, pur = c.purchase("cf_user", "cf_key", "sku_count_1")
        samples["POST /purchase"] = (code, pur)
        samples["POST /purchase/query"] = c.purchase_query("cf_user", "cf_key")
        c.admin("mark_paid", {"purchase_id": pur.get("purchase_id", "")})
        samples["POST /access"] = c.access("cf_user", 1)
        samples["POST /consume"] = c.consume("cf_user", "cf_eat", 1, "conformance")
        samples["POST /consumption"] = c.consumption("cf_user", "cf_eat")
        samples["POST /transactions/query"] = c.transaction_query("cf_user", "cf_key")

        samples["GET /webhook"] = c.webhook_settings()
        samples["PUT /webhook"] = c.save_webhook("https://merchant.example.com/hook")
        samples["POST /webhook/rotate"] = c.rotate_webhook()
        samples["POST /events/list"] = c.events()

    op_to_schema = {}
    for path, item in spec["paths"].items():
        for method, op in item.items():
            if method not in ("get", "post", "put", "patch", "delete"):
                continue
            schema = (op.get("responses", {}).get("200", {})
                      .get("content", {}).get("application/json", {}).get("schema"))
            if schema:
                op_to_schema[f"{method.upper()} {path}"] = schema

    results = []
    alias_map = {"POST /events/list": "POST /events/list"}
    for label, (code, body) in samples.items():
        key = alias_map.get(label, label)
        schema = op_to_schema.get(key)
        if schema is None:
            results.append({"endpoint": label, "http": code, "schema": None,
                            "errors": [f"no 200 response schema for {key}"],
                            "conforms": False})
            continue
        errs = validate(body, schema, spec) if code == 200 else [
            f"HTTP {code}: {body}"]
        results.append({"endpoint": label, "http": code,
                        "schema": schema.get("$ref", "inline").split("/")[-1],
                        "errors": errs, "conforms": not errs})
    return {"results": results}


def capability_check(spec: dict) -> dict:
    """The spec requires an exact set of 15 boolean capability flags."""
    required = spec["components"]["schemas"]["CapabilityFlags"]["required"]
    with MockServer("hardened") as srv:
        code, body = Client(srv.base_url).capabilities()
    flags = body.get("capabilities", {}) if code == 200 else {}
    missing = [k for k in required if k not in flags]
    non_bool = [k for k, v in flags.items() if k in required and not isinstance(v, bool)]
    return {"required": required, "declared": flags,
            "missing": missing, "non_bool": non_bool,
            "conforms": code == 200 and not missing and not non_bool}


def inventory_check(spec: dict) -> dict:
    """Which official operations does the mock route implement?"""
    official = set()
    for path, item in spec["paths"].items():
        for method, op in item.items():
            if method in ("get", "post", "put", "patch", "delete"):
                official.add(f"{method.upper()} {path}")
    with MockServer("hardened") as srv:
        # Probe each operation with a valid key; 404 means no route, any other
        # status means the route exists.  Method mismatches are detected by
        # probing the spec's method only.
        c = Client(srv.base_url)
        implemented = set()
        for label in official:
            method, path = label.split(" ", 1)
            path = path.replace("{event}", "evt_probe")
            code, body = c._request(
                method, "/opcpay/api/pay/v1" + path,
                body={} if method in ("post", "put", "patch") else None)
            # retry_event returns 404 when the event does not exist; that is a
            # route that works, not a missing route.  Seed one first.
            if code == 404 and "/retry" in path:
                # Seed a purchase then a genuinely signed+logged event so the
                # retry route resolves it (fake signatures are rejected).
                _, seed_pur = c.purchase("inv_user", "inv_key", "sku_count_1")
                _, signed = c.admin("sign_webhook", {
                    "purchase_id": seed_pur.get("purchase_id", ""),
                    "event_id": "evt_probe"})
                c.webhook(signed["headers"], signed["raw"].encode())
                code, body = c._request(method, "/opcpay/api/pay/v1" + path, body={})
            if code != 404:
                implemented.add(label)
    return {"official": sorted(official), "implemented": sorted(implemented),
            "missing": sorted(official - implemented)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    spec = load_spec()

    probe_r = probe(spec)
    cap = capability_check(spec)
    inv = inventory_check(spec)

    print(f"Official spec: {spec['info']['title']} v{spec['info']['version']}")
    print(f"Server in spec: {spec['servers'][0]['url']}\n")
    print(f"{'endpoint':30s} {'http':>4s}  {'schema':18s} verdict")
    for r in probe_r["results"]:
        verdict = "OK" if r["conforms"] else "FAIL: " + "; ".join(r["errors"][:2])
        print(f"{r['endpoint']:30s} {r['http']:>4d}  {str(r['schema']):18s} {verdict}")
    print(f"\nCapability flags: {'OK' if cap['conforms'] else 'FAIL'}"
          + (f"  missing={cap['missing']} non_bool={cap['non_bool']}"
             if not cap["conforms"] else ""))
    print(f"Operation inventory: {len(inv['implemented'])}/{len(inv['official'])} official ops routed")
    if inv["missing"]:
        print("  not routed: " + ", ".join(inv["missing"]))

    conforms = (all(r["conforms"] for r in probe_r["results"])
                and cap["conforms"])
    print("\nOPENAPI CONFORMANCE OK — mock satisfies the official 1.1.2 response contracts"
          if conforms else
          "\nOPENAPI CONFORMANCE: gaps found (see FAIL rows) — mock is a benchmark fixture, not a full gateway clone")

    if args.json:
        print(json.dumps({"spec_version": spec["info"]["version"],
                          "probe": probe_r, "capabilities": cap,
                          "inventory": inv, "conforms": conforms},
                         ensure_ascii=False, indent=2))
    return 0 if conforms else 1


if __name__ == "__main__":
    sys.exit(main())
