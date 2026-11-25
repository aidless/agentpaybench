#!/usr/bin/env python3
"""收款接入体检 HTTP 服务。

POST /check {"base_url": "http://sandbox.example/api/pay/v1"} -> 20 场景报告。
威胁模型：服务在公网，任何人可提交目标；必须挡住 SSRF 打服务自身内网。
默认拒绝环回/私网/云元数据地址，用 --allow-host 显式放行 sandbox 域名
（本地测试用 --allow-loopback）。
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from runner import run_all

MAX_BODY = 64 * 1024
CLOUD_METADATA = {"169.254.169.254", "metadata.google.internal"}


class CheckError(ValueError):
    """入参不合法（HTTP 400）。"""


def is_private_host(host: str) -> bool:
    if host in ("localhost",) or host.endswith((".local", ".internal")):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False  # 域名交给 DNS；生产应在解析后再次校验，文档已注明
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified)


def validate_base_url(raw, allow_hosts: set[str], allow_loopback: bool) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise CheckError("base_url 必填")
    url = urlparse(raw.strip())
    if url.scheme not in ("http", "https"):
        raise CheckError("base_url 必须是 http(s)")
    host = (url.hostname or "").lower()
    if not host:
        raise CheckError("base_url 缺少主机")
    if host in CLOUD_METADATA:
        raise CheckError("拒绝云元数据地址")
    if is_private_host(host):
        loopback = host in ("localhost", "127.0.0.1", "::1", "0.0.0.0")
        if not (loopback and allow_loopback) and host not in allow_hosts:
            raise CheckError(f"目标主机 {host} 是内网/环回地址，已拒绝；"
                             "本地测试用 --allow-loopback，或 --allow-host 显式放行")
    return raw.strip().rstrip("/")


def grade(results: list) -> dict:
    """把 20 场景结果折成可引用的体检等级。"""
    fails = [r for r in results if not r.ok]
    cats = {r.category for r in fails}
    n = len(fails)
    if not fails:
        letter, verdict, summary = "A", "READY", "20/20 通过；未检出收款逻辑缺陷"
    elif n >= 9 or (n >= 5 and "attack" in cats):
        letter, verdict, summary = "D", "CRITICAL", f"{n} 项未通过；存在高危攻击面，不可上线"
    elif "attack" in cats:
        letter, verdict, summary = "C", "AT_RISK", f"{n} 项未通过；含攻击面缺陷"
    else:
        letter, verdict, summary = "B", "MINOR", f"{n} 项未通过；均为体验/边界问题"
    return {
        "grade": letter,
        "verdict": verdict,
        "summary": summary,
        "passed": len(results) - n,
        "total": len(results),
        "defects": [
            {"id": r.id, "title": r.title, "category": r.category, "detail": r.detail}
            for r in fails
        ],
    }


class CheckHandler(BaseHTTPRequestHandler):
    server_version = "AgentPayBenchCheck/0.3"

    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/healthz", "/health"):
            self._send(200, {"ok": True, "service": "agentpaybench-check"})
        else:
            self._send(404, {"error": "not_found"})

    def do_POST(self):
        if self.path != "/check":
            self._send(404, {"error": "not_found"})
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send(400, {"error": "bad_content_length"})
            return
        if size <= 0 or size > MAX_BODY:
            self._send(400, {"error": "body_size", "limit": MAX_BODY})
            return
        try:
            req = json.loads(self.rfile.read(size))
        except Exception:
            self._send(400, {"error": "invalid_json"})
            return
        if not isinstance(req, dict):
            self._send(400, {"error": "body_must_be_object"})
            return
        try:
            base = validate_base_url(req.get("base_url"),
                                     self.server.allow_hosts,
                                     self.server.allow_loopback)
        except CheckError as exc:
            self._send(400, {"error": "invalid_target", "detail": str(exc)})
            return
        agent = req.get("agent", "safe")
        if agent not in ("safe", "unsafe"):
            self._send(400, {"error": "invalid_agent"})
            return
        # 体检要求目标暴露 admin reset hook（mock 协议已实现），每个场景
        # 从干净账本开始，避免 20 个场景共享 user_id 造成状态污染。
        # 真实支付宝/官方沙箱无此接口，见 README「适用目标」。
        results = run_all(base_url=base, agent_policy=agent, reset=True)
        report = grade(results)
        report["target"] = base
        report["agent"] = agent
        self._send(200, report)

    def log_message(self, fmt, *args):
        pass  # 关闭默认 stderr 噪声；生产接入结构化日志


class CheckServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_hosts: set[str] = set()
    allow_loopback = False


def serve(host: str = "127.0.0.1", port: int = 8099,
          allow_hosts=(), allow_loopback: bool = False) -> CheckServer:
    srv = CheckServer((host, port), CheckHandler)
    srv.allow_hosts = set(allow_hosts)
    srv.allow_loopback = allow_loopback
    return srv


def main() -> int:
    ap = argparse.ArgumentParser(description="AgentPayBench 收款接入体检服务")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--allow-host", action="append", default=[],
                    help="允许体检的 sandbox 域名，可重复；默认只允许公网域名")
    ap.add_argument("--allow-loopback", action="store_true",
                    help="仅本地测试用：允许体检 127.0.0.1 的目标")
    args = ap.parse_args()
    srv = serve(args.host, args.port, args.allow_host, args.allow_loopback)
    print(f"check service: http://{args.host}:{args.port}/check", file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
