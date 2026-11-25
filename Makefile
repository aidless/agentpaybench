.PHONY: all selftest run naive unsafe sdk rate fuzz conformance check-service clean

all:
	python3 all_selftest.py

selftest:
	python3 selftest.py

run:
	python3 runner.py

naive:
	python3 runner.py --mode naive

unsafe:
	python3 runner.py --agent unsafe

conformance:
	python3 openapi_conformance.py

check-service:
	python3 check_service_selftest.py

rate:
	python3 rate_limit_selftest.py

fuzz:
	python3 fuzz_invariants.py --steps 10000

fuzz-naive:
	python3 fuzz_invariants.py --mode naive --steps 10000

sdk:
	@test -n "$(OPCPAY_SDK)" || (echo "set OPCPAY_SDK=/path/to/opcpay/index.mjs"; exit 2)
	@tmp=$$(mktemp -d) && cp sdk_conformance.mjs "$$tmp/" && \
	  (cd "$$tmp" && OPCPAY_SDK="$(OPCPAY_SDK)" node sdk_conformance.mjs); \
	  rc=$$?; rm -rf "$$tmp"; exit $$rc

clean:
	rm -f report.json
