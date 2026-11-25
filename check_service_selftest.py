#!/usr/bin/env python3
"""check_service 自检：真实 HTTP 体检 hardened/naive mock + SSRF/入参反证。"""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

from check_service import serve
from mock_server import MockServer


def post(port, path, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def get(port, path):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as r:
        return r.status, json.loads(r.read())


def main() -> int:
    checks = []

    # 起 hardened / naive 两个 mock 作为被体检目标
    hs = MockServer("hardened")
    ns = MockServer("naive")
    # MockServer 是上下文管理器，__enter__ 才真正起服务（内部 start 一次）
    hs.__enter__()
    ns.__enter__()
    hbase, nbase = hs.base_url, ns.base_url

    chk = serve("127.0.0.1", 0, allow_loopback=True)
    cport = chk.server_address[1]
    t = threading.Thread(target=chk.serve_forever, daemon=True)
    t.start()

    try:
        # 1) 健康检查
        code, body = get(cport, "/healthz")
        checks.append(("healthz 200", code == 200 and body.get("ok") is True))

        # 2) 体检 hardened mock：应全过，A 级 READY
        code, rep = post(cport, "/check", {"base_url": hbase})
        ok = (code == 200 and rep.get("passed") == rep.get("total") == 20
              and rep.get("grade") == "A" and rep.get("verdict") == "READY")
        checks.append((f"hardened 20/20 A-READY (got {rep.get('passed')}/{rep.get('total')} "
                        f"{rep.get('grade')}/{rep.get('verdict')})", ok))
        if not ok:
            print("  hardened defects:", [d["id"] for d in rep.get("defects", [])])

        # 3) 体检 naive mock：应暴露缺陷，等级 D
        code, rep2 = post(cport, "/check", {"base_url": nbase})
        ok2 = (code == 200 and rep2.get("passed", 20) < 20
               and rep2.get("grade") in ("C", "D") and len(rep2.get("defects", [])) >= 5)
        checks.append((f"naive 检出缺陷 (got {rep2.get('passed')}/{rep2.get('total')} "
                        f"grade={rep2.get('grade')}, {len(rep2.get('defects', []))} defects)", ok2))

        # 4) SSRF：环回地址默认拒绝
        chk.allow_loopback = False
        code, rep3 = post(cport, "/check", {"base_url": "http://127.0.0.1:9999"})
        chk.allow_loopback = True
        checks.append(("SSRF 环回拒绝 400", code == 400 and rep3.get("error") == "invalid_target"))

        # 5) SSRF：云元数据拒绝
        code, rep4 = post(cport, "/check", {"base_url": "http://169.254.169.254/latest"})
        checks.append(("SSRF metadata 拒绝 400", code == 400))

        # 6) 非法 scheme / 空 base_url
        code, _ = post(cport, "/check", {"base_url": "ftp://example.com"})
        checks.append(("ftp scheme 拒绝 400", code == 400))
        code, _ = post(cport, "/check", {})
        checks.append(("空 base_url 拒绝 400", code == 400))

        # 7) 未知路径 404
        code, _ = post(cport, "/nope", {"base_url": hbase})
        checks.append(("未知路径 404", code == 404))
    finally:
        chk.shutdown()
        hs.__exit__(None, None, None)
        ns.__exit__(None, None, None)

    failed = 0
    for name, ok in checks:
        print(f"  {'OK  ' if ok else 'FAIL'}  {name}")
        failed += (not ok)
    print(f"CHECK SELFTEST: {len(checks)-failed}/{len(checks)} passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
