.PHONY: perf-setup perf-report perf-verify

perf-setup:
	bash perf/bench.sh setup

perf-report:
	python3 perf/report.py

perf-verify:
	python3 perf/report.py --check --raw
