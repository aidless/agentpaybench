#!/usr/bin/env python3
"""用官方 OpenAPI 1.1.2 规范预检真实沙箱请求体；不发包、不读 key。

用法：
  python3 live_sandbox_prep.py --out live_sandbox_prep_report.json

只对将发给 pay.ai6666.com 的请求做本地 schema 预检，并生成带占位符的
curl 清单。真实支付、退款、webhook 仍需用户自己的测试商户 yrp_live_ key。
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC_PATH = HERE / "opcpay-openapi-1.1.2.json"


def load_spec() -> dict:
    return json.loads(SPEC_PATH.read_text(encoding="utf-8"))


def request_schemas(spec: dict) -> dict[str, tuple[str, dict]]:
    out = {}
    for path, item in spec["paths"].items():
        for method, op in item.items():
            if method not in {"get", "post", "put"}:
                continue
            ref = (
                op.get("requestBody", {})
                .get("content", {})
                .get("application/json", {})
                .get("schema", {})
                .get("$ref", "")
            )
            if not ref:
                continue
            name = ref.rsplit("/", 1)[-1]
            out[f"{method.upper()} {path}"] = (name, spec["components"]["schemas"][name])
    return out


def check_type(value, typ: str) -> bool:
    return {
        "string": lambda v: isinstance(v, str),
        "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
        "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
        "boolean": lambda v: isinstance(v, bool),
        "object": lambda v: isinstance(v, dict),
        "array": lambda v: isinstance(v, list),
    }.get(typ, lambda v: True)(value)


def validate(schema: dict, value, root: dict, path: str = "$") -> list[str]:
    if "$ref" in schema:
        name = schema["$ref"].rsplit("/", 1)[-1]
        return validate(root["components"]["schemas"][name], value, root, path)
    errs: list[str] = []
    typ = schema.get("type")
    if typ and not check_type(value, typ):
        return [f"{path}: expected {typ}, got {type(value).__name__}"]
    if isinstance(value, dict):
        required = schema.get("required", [])
        errs += [f"{path}: missing required {k}" for k in required if k not in value]
        props = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            errs += [f"{path}: unexpected property {k}" for k in value if k not in props]
        for k, v in value.items():
            if k in props:
                errs += validate(props[k], v, root, f"{path}.{k}")
    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            errs.append(f"{path}: shorter than minLength {schema['minLength']}")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errs.append(f"{path}: longer than maxLength {schema['maxLength']}")
    if isinstance(value, int) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errs.append(f"{path}: below minimum {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errs.append(f"{path}: above maximum {schema['maximum']}")
    return errs


def sample_bodies() -> dict[str, dict]:
    return {
        "POST /purchase": {
            "user_id": "sandbox-user-001",
            "idempotency_key": "prep-purchase-001",
            "sku_id": "SANDBOX_SKU",
            "callback_url": "https://your-merchant.example/callback",
        },
        "POST /access": {"user_id": "sandbox-user-001"},
        "POST /consume": {
            "user_id": "sandbox-user-001",
            "idempotency_key": "prep-consume-001",
            "amount": 1,
            "reason": "sandbox prep check",
        },
        "POST /consumption": {
            "user_id": "sandbox-user-001",
            "idempotency_key": "prep-consume-001",
        },
        "POST /purchase/query": {
            "user_id": "sandbox-user-001",
            "idempotency_key": "prep-purchase-001",
        },
        "POST /purchases/list": {"user_id": "sandbox-user-001", "limit": 20},
        "POST /consumptions/list": {"user_id": "sandbox-user-001", "limit": 20},
        "PUT /webhook": {
            "url": "https://your-merchant.example/webhook",
            "enabled": False,
        },
        "POST /events/list": {"limit": 20},
        "POST /transactions/query": {
            "user_id": "sandbox-user-001",
            "idempotency_key": "prep-purchase-001",
        },
    }


def negative_cases() -> dict[str, dict]:
    return {
        "POST /purchase: 非法 amount 不在 body（附加未知字段）": {
            "user_id": "u",
            "idempotency_key": "k",
            "amount": -1,
        },
        "POST /consume: 空 reason（minLength=1 可判定）": {
            "user_id": "u",
            "idempotency_key": "k",
            "amount": 1,
            "reason": "",
        },
        "PUT /webhook: 缺 enabled": {"url": "https://your-merchant.example/webhook"},
        "POST /purchases/list: limit=0": {"limit": 0},
    }


def curl_checklist() -> list[str]:
    return [
        "# 1. 先只读探测，确认鉴权与能力位",
        'curl -sS -H "Authorization: Bearer $OPCPAY_API_KEY" '
        "https://pay.ai6666.com/api/pay/v1/capabilities",
        "",
        "# 2. 目录价，只买测试商户最便宜的次数包；不传客户端价格",
        'curl -sS -H "Authorization: Bearer $OPCPAY_API_KEY" '
        "https://pay.ai6666.com/api/pay/v1/product",
        "",
        "# 3. 购买Intent，idempotency_key 先落盘再调用，重试保持原值",
        'curl -sS -X POST -H "Authorization: Bearer $OPCPAY_API_KEY" '
        '-H "content-type: application/json" '
        "-d '{\"user_id\":\"sandbox-user-001\",\"idempotency_key\":\"REAL_KEY_HERE\"}' "
        "https://pay.ai6666.com/api/pay/v1/purchase",
        "",
        "# 4. 支付后对账三条：服务端价=目录价；UNKNOWN 不发货；退款后 access=DENY",
        "# 真实请求必须来自你自己的测试商户 key；本脚本不发包、不读 key、不记录订单。",
    ]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=HERE / "live_sandbox_prep_report.json")
    ap.add_argument("--strict", action="store_true", help="阴性用例未被拒绝时退出 1")
    args = ap.parse_args()

    spec = load_spec()
    schemas = request_schemas(spec)
    good = []
    for route, body in sample_bodies().items():
        name, schema = schemas[route]
        errs = validate(schema, body, spec)
        good.append({"route": route, "schema": name, "valid": not errs, "errors": errs})

    bad = []
    for label, body in negative_cases().items():
        route = label.split(":")[0]
        _, schema = schemas[route]
        errs = validate(schema, body, spec)
        bad.append({"label": label, "rejected": bool(errs), "errors": errs})

    report = {
        "spec": SPEC_PATH.name,
        "purpose": "local request-body preflight only; no network calls, no key read",
        "positive": good,
        "negative": bad,
        "curl_checklist": curl_checklist(),
        "limits": [
            "本地只校验 JSON Schema 子集；不含 HTTP 头/CSP/服务端状态机",
            "真实支付与退款需要测试商户 yrp_live_ key，会产生小额真实资金",
            "回调地址示例域名为占位符，需替换成控制台已登记官网同域名",
        ],
    }
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    positives_ok = all(x["valid"] for x in good)
    negatives_ok = all(x["rejected"] for x in bad)
    print(f"positive {sum(x['valid'] for x in good)}/{len(good)}; negative {sum(x['rejected'] for x in bad)}/{len(bad)}")
    print(f"report: {args.out}")
    if not positives_ok or (args.strict and not negatives_ok):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
