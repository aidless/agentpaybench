#!/usr/bin/env python3
"""AgentPayBench runner.

  python3 runner.py                          # hardened mock, safe agent
  python3 runner.py --mode naive             # mutation run: defects must show
  python3 runner.py --agent unsafe           # A7 must fail (gullible agent)
  python3 runner.py --base-url http://...    # external target (admin-free)

The runner resets the mock before every scenario so each one starts from a
clean ledger.  For an external target there is no reset: point it at a
disposable sandbox only.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field

from client import Client
from mock_server import MockServer
from scenarios import SCENARIOS, Ctx


@dataclass
class Result:
    id: str
    title: str
    category: str
    ok: bool
    detail: str
    detects: list = field(default_factory=list)
    naive: str = "pass"


def _run_one(meta: dict, ctx: Ctx, reset: bool) -> Result:
    if reset:
        ctx.c.admin("reset")
    try:
        detail = meta["fn"](ctx) or ""
        ok = True
    except AssertionError as exc:
        ok, detail = False, str(exc)
    except Exception as exc:  # noqa: BLE001 - report, do not abort the suite
        ok, detail = False, f"{type(exc).__name__}: {exc}"
    return Result(meta["id"], meta["title"], meta["category"], ok, detail,
                  meta["detects"], meta["naive"])


def run_all(mode: str = "hardened", agent_policy: str = "safe",
            base_url: str | None = None, reset: bool | None = None) -> list[Result]:
    """Run every scenario.  ``reset`` overrides the per-branch default.

    In-process mock resets before every scenario.  An external sandbox does
    not (real providers have no reset API); pass ``reset=True`` when the
    target exposes an admin reset hook so scenarios do not share ledger state.
    """
    results: list[Result] = []
    if base_url:
        do_reset = False if reset is None else reset
        ctx = Ctx(Client(base_url), agent_policy)
        for meta in SCENARIOS:
            results.append(_run_one(meta, ctx, reset=do_reset))
        return results
    with MockServer(mode) as srv:
        ctx = Ctx(Client(srv.base_url), agent_policy)
        for meta in SCENARIOS:
            results.append(_run_one(meta, ctx, reset=True))
    return results


def main() -> int:
    ap = argparse.ArgumentParser(description="AgentPayBench")
    ap.add_argument("--mode", choices=["hardened", "naive"], default="hardened",
                    help="mock implementation under test")
    ap.add_argument("--agent", choices=["safe", "unsafe"], default="safe",
                    help="policy of the scripted agent used by A7")
    ap.add_argument("--base-url", default=None,
                    help="run against an existing sandbox instead of the mock")
    ap.add_argument("--json", default="report.json", help="report path")
    args = ap.parse_args()

    results = run_all(args.mode, args.agent, args.base_url)
    width = max(len(r.id) for r in results)
    print(f"AgentPayBench  mode={args.mode}  agent={args.agent}  "
          f"target={args.base_url or 'in-process mock'}")
    print("-" * 78)
    for r in results:
        print(f"{r.id:<{width}}  {r.category:<6}  {'PASS' if r.ok else 'FAIL':<4}  "
              f"{r.title}")
        if not r.ok:
            print(f"{'':<{width}}        {r.detail}")
    passed = sum(1 for r in results if r.ok)
    print("-" * 78)
    print(f"{passed}/{len(results)} passed")
    if args.mode == "naive":
        caught = [r.id for r in results if not r.ok]
        print(f"defects caught: {len(caught)} → {', '.join(caught)}")

    report = {
        "mode": args.mode,
        "agent": args.agent,
        "target": args.base_url or "in-process mock",
        "passed": passed,
        "total": len(results),
        "results": [asdict(r) for r in results],
    }
    with open(args.json, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
    print(f"report: {args.json}")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
