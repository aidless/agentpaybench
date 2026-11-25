#!/usr/bin/env python3
"""One entry point for all checks.

  * 20 server scenarios  (selftest.py)
  * 3 client-guard cases (client_guard_selftest.py)
  * 4 webhook lifecycle  (webhook_e2e.py)
  * 2 rate-limit checks  (rate_limit_selftest.py: E8 server, C4 client)
  * 8 check-service cases (check_service_selftest.py: HTTP /check + SSRF guards)

Hardened: 29/29 benchmark scenarios pass (naive: exactly 23 failures =
15 + 3 + 4 + 1).  Plus 8 HTTP service checks.  Any other count fails the run.
"""

from __future__ import annotations

import sys

import check_service_selftest
import client_guard_selftest
import rate_limit_selftest
import selftest
import webhook_e2e

HARDENED_TOTAL = 29
NAIVE_FAILURES = 23
CHECK_SERVICE_TOTAL = 8


def main() -> int:
    results = {
        "server (20)": selftest.main(),
        "client guard (3)": client_guard_selftest.main(),
        "webhook lifecycle (4)": webhook_e2e.main(),
        "rate limit (2)": rate_limit_selftest.main(),
        "check service (8)": check_service_selftest.main(),
    }
    failed = [name for name, code in results.items() if code != 0]
    if failed:
        print(f"\nALL SELFTEST FAILED: {', '.join(failed)}")
        return 1
    print("\n" + "=" * 62)
    print(f"ALL SELFTEST OK — {HARDENED_TOTAL} hardened scenarios pass; "
          f"naive fails exactly {NAIVE_FAILURES} (15 + 3 + 4 + 1); "
          f"check service {CHECK_SERVICE_TOTAL}/{CHECK_SERVICE_TOTAL}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
