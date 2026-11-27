"""Measure host-wide CPU execution time from the scheduler's per-CPU counters."""
import json
from pathlib import Path


def cpu_metrics(directory: Path, start: int, end: int, app_cpus=()):
    first = last = None
    for line in (directory / "pressure.jsonl").read_text().splitlines():
        try:
            sample = json.loads(line)
        except json.JSONDecodeError:
            continue
        if start <= sample["t"] <= end and "version 15" in sample["sched"]:
            last = sample
            if first is None:
                first = sample
    if first is None or last["t"] <= first["t"]:
        return {}

    def runtimes(sample):
        return {
            int(fields[0][3:]): (int(fields[7]), int(fields[8]))
            for line in sample["sched"]
            if (fields := line.split())[0].startswith("cpu") and fields[0][3:].isdigit()
        }

    before, after = runtimes(first), runtimes(last)
    if not before or before.keys() != after.keys() or any(
        after[cpu][field] < before[cpu][field] for cpu in before for field in (0, 1)
    ):
        return {}
    elapsed_ns = (last["t"] - first["t"]) * 1_000_000
    running = sum(after[cpu][0] - before[cpu][0] for cpu in before)
    metrics = {"host_cpu_utilization_pct": 100 * running / (elapsed_ns * len(before))}
    if app_cpus and set(app_cpus) <= before.keys():
        app = set(app_cpus)
        waiting = {cpu: (after[cpu][1] - before[cpu][1]) / elapsed_ns for cpu in before}
        metrics["app_cpu_wait_task_equivalent"] = sum(waiting[cpu] for cpu in app)
        metrics["other_cpu_wait_task_equivalent"] = sum(waiting[cpu] for cpu in before.keys() - app)
    return metrics
