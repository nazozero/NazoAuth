.PHONY: perf perf-capacity perf-capacity-smoke perf-down perf-clean

perf:
	docker compose -f docker-compose.perf.yml up --build --abort-on-container-exit --exit-code-from perf

perf-capacity:
	python perf/tools/current_capacity.py --stop-at "$(STOP_AT)" $(CAPACITY_ARGS)

perf-capacity-smoke:
	python perf/tools/current_capacity.py --stop-at "$(STOP_AT)" --smoke $(CAPACITY_ARGS)

perf-down:
	docker compose -f docker-compose.perf.yml down

perf-clean:
	docker compose -f docker-compose.perf.yml down -v --remove-orphans
