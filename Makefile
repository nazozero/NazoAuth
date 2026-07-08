.PHONY: perf perf-capacity perf-capacity-smoke perf-down perf-clean

perf:
	docker compose -f docker-compose.perf.yml up --build --abort-on-container-exit --exit-code-from perf

perf-capacity:
	python perf/capacity.py --duration 30m --instances 1,2,4

perf-capacity-smoke:
	python perf/capacity.py --smoke

perf-down:
	docker compose -f docker-compose.perf.yml down

perf-clean:
	docker compose -f docker-compose.perf.yml down -v --remove-orphans
