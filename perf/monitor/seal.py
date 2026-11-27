"""Reconcile a timed window with the original resource samplers."""
import json
from collections import defaultdict
import os
from statistics import mean, median
from pathlib import Path
import re
import sys

from observe import sample_resources, sample_cgroup_roles, sample_host_pressure
from host_utilization import cpu_metrics
from summarize import summarize
from memory_window import smaps_peaks

path = Path(sys.argv[1])
peer, flow = sys.argv[2:4]
rate, seconds = map(int, sys.argv[4:6])
window = (path / "window").read_text()
metadata = dict(re.findall(r"(\w+)=(\d+)", window))
warm = int(metadata["warm"])
encoded_schedule = re.search(r"^schedule=([0-9@,]+)$", window, re.MULTILINE)
schedule = [tuple(map(int, phase.split("@"))) for phase in encoded_schedule[1].split(",")] if encoded_schedule else None
data = summarize(path / "arrivals.tsv", rate, warm, seconds, schedule)
anchor = int(metadata["epoch_ns"]) // 10**6
start, end = anchor + warm * 1000, anchor + (warm + seconds) * 1000
resources = sample_resources(path, start, end)
pressure, sample_seconds = sample_host_pressure(path / "pressure.jsonl", start, end)
resource_pressure = {}
for line in (path / "pressure.jsonl").read_text().splitlines():
    try:
        sample = json.loads(line)
    except json.JSONDecodeError:
        continue
    if start <= sample["t"] <= end:
        for kind in ("io", "memory"):
            for entry in sample.get("pressure_" + kind, ()):
                name, *fields = entry.split()
                total = int(fields[-1].removeprefix("total="))
                resource_pressure.setdefault(kind + "_" + name, []).append((sample["t"], total))
host_pressure_pct = {}
for name, series in resource_pressure.items():
    first, last = series[0], series[-1]
    if last[0] > first[0]:
        host_pressure_pct[name] = (last[1] - first[1]) / (last[0] - first[0]) / 10
cgroup = sample_cgroup_roles(path, resources, start, end)
required = {"app", "generator"}
if peer != "kanidm":
    required.add("postgres")
if peer == "nazo":
    required.add("valkey")
valid = required <= resources.keys() and all(
    resources[role]["affinity_mismatches"] == 0 and resources[role].get("sampled_intervals", 0) >= 4
    for role in required
)
a = data["operations"]["all"]
p99 = (a["offered_to_completion_success_ms"] or {}).get("99", float("inf"))
reasons = []
if not valid or sample_seconds < seconds * .65:
    reasons.append("resource_sampling")
if a["outcomes"].get("scheduler_late", 0) > .001 * a["planned"]:
    reasons.append("generator_scheduling")
if a["outcomes"].get("transport_addr_unavailable"):
    reasons.append("generator_source_ports")
if resources.get("generator", {}).get("mean_cpu_cores", 0) >= .8 * int(os.environ.get("BENCH_GO_WORKERS", "15")):
    reasons.append("generator_cpu")
at_capacity = a["outcomes"].get("in_flight_limit", 0)
if at_capacity and not (a["outcomes"].get("timeout") or p99 > 250):
    reasons.append("generator_in_flight_limit")
if flow == "refresh" and a["outcomes"].get("refresh_lane_pending", 0) > .001 * a["planned"] and p99 <= 250:
    reasons.append("refresh_family_pool")
limits = {"machine": 250, "introspect": 100, "exchange": 250, "refresh": 250, "authorize": 1000, "userinfo": 100}
failures = []
for op, row in data["operations"].items():
    if schedule:
        break
    if op == "all" and flow in ("mixed", "mixed-core"):
        continue
    limit = limits[flow if op == "all" else op]
    if flow == "mixed-core" and row["outcomes"].get("scheduler_late", 0) > .001 * row["planned"]:
        reasons.append("generator_scheduling_" + op)
    result_p99 = (row["offered_to_completion_success_ms"] or {}).get("99", float("inf"))
    inflight = row["in_flight_at_second_boundaries"]
    buckets = [median(inflight[i:i+3]) for i in range(0, len(inflight), 3)]
    expected_pending = row["planned"] / seconds * limit / 1000
    accumulates = min(buckets[-3:]) > max(buckets[:3]) and median(buckets[-3:]) - median(buckets[:3]) > expected_pending
    if row["attainment"] < .999 or row["outcomes"].get("protocol_error") or result_p99 > limit or accumulates:
        failures.append(op)
def role_samples(file, start, end):
    samples = defaultdict(dict)
    for line in file.read_text().splitlines():
        at, pid, _, ticks, rss, threads, _, _ = line.split("\t")
        if int(threads):
            samples[int(at)][int(pid)] = (int(ticks), int(rss))
    hz = os.sysconf("SC_CLK_TCK")
    stamps = sorted(samples)
    interval_rates, cpu_seconds, coverage = [], 0, 0
    memory = []
    for t in stamps:
        if start <= t < end:
            memory.append((t, sum(v[1] for v in samples[t].values()) / 1024))
    for a, b in zip(stamps, stamps[1:]):
        span = min(b, end) - max(a, start)
        if span <= 0:
            continue
        common = samples[a].keys() & samples[b].keys()
        if not common:
            continue
        ticks = sum(max(0, samples[b][pid][0]-samples[a][pid][0]) for pid in common)
        use = ticks / hz * 1000 / (b-a)
        interval_rates.append(use)
        coverage += span / 1000
        cpu_seconds += use * span / 1000
    return memory, cpu_seconds, coverage, max(interval_rates, default=0)


memory_roles = {}
for role, row in resources.items():
    memory, cpu_seconds, coverage, peak = role_samples(path / (role + ".cpu.tsv"), start, end)
    if memory:
        memory_roles[role] = memory
        row.update(mean_rss_sum_mib=mean(v for _, v in memory),
                   peak_rss_sum_mib=max(v for _, v in memory))
    if coverage:
        row.update(cpu_seconds=cpu_seconds, cpu_sample_seconds=coverage,
                   mean_cpu_cores=cpu_seconds / coverage, peak_interval_cpu_cores=peak)
if (path / "pss.tsv").is_file():
    samples = (list(map(int, line.split())) for line in (path / "pss.tsv").read_text().splitlines())
    try:
        data.update(smaps_peaks(peer, int(metadata["epoch_ns"]) + warm * 10**9, seconds, samples))
    except ValueError:
        reasons.append("pss_sampling")
server_roles = sorted(required - {"generator"})
total_rss = []
if all(role in memory_roles for role in server_roles):
    for stamp, _ in memory_roles["app"]:
        point = [min(memory_roles[role], key=lambda x: abs(x[0]-stamp)) for role in server_roles]
        if all(abs(t-stamp) <= 1000 for t, _ in point):
            total_rss.append(sum(v for _, v in point))

app = resources.get("app", {})
cpu = app.get("mean_cpu_cores")
cpu_time = app.get("cpu_seconds")
state_path = path / "app-state.json"
state = json.loads(state_path.read_text()) if state_path.exists() else None
if state:
    data.update(app_crashed=not state["Running"], app_oom=state["OOMKilled"])
    if not schedule and (not state["Running"] or state["OOMKilled"]):
        failures.append("app_exit")
if flow == "refresh" and (path / "proof.json").is_file():
    proof = json.loads((path / "proof.json").read_text())
    data["refresh_fixture"] = {
        key: proof[key] for key in ("fixture_contract", "users", "families_per_user", "fixtures")
    }
if schedule:
    limit = limits[flow]

    def meets_slo(sample):
        tail = (sample["offered_to_completion_success_ms"] or {}).get("99", float("inf"))
        return sample["attainment"] >= .999 and not sample["outcomes"].get("protocol_error") and tail <= limit

    phases = data["phases"]
    assert state is not None
    in_flight = a["in_flight_at_second_boundaries"]
    baseline = median(in_flight[:phases["normal"]["seconds"]])
    ceiling = baseline + max(1, rate * limit / 1000)
    recovery = data["recovery_buckets"]
    recovered = [meets_slo(b) and b["total_in_flight"] <= ceiling for b in recovery]
    recovery_time = next((recovery[i]["seconds_after_overload"] for i in range(len(recovered) - 2)
                          if all(recovered[i:i+3])), None)
    peak_in_flight = {}
    begin = start
    for name, row in phases.items():
        duration = row["seconds"]
        finish = begin + duration * 1000
        first = (begin - start) // 1000
        peak_in_flight[name] = max(in_flight[first:first + duration], default=0)
        if row["outcomes"].get("scheduler_late", 0) > .001 * row["planned"]:
            reasons.append("generator_scheduling_" + name)
        if row["outcomes"].get("protocol_error"):
            failures.append("protocol_error_" + name)
        row["resources"] = {}
        for role in resources:
            measured_rss, cpu_s, coverage, peak_cpu = role_samples(path / (role + ".cpu.tsv"), begin, finish)
            if coverage:
                row["resources"][role] = {"cpu_seconds": cpu_s, "mean_cpu_cores": cpu_s / coverage,
                                           "peak_cpu_cores": peak_cpu, "sampled_seconds": coverage,
                                           "peak_rss_mib": max((m for _, m in measured_rss), default=None)}
        begin = finish
    data.update(mode="overload_recovery", recovery_seconds=recovery_time, peak_in_flight_by_phase=peak_in_flight)
    if not meets_slo(phases["normal"]):
        failures.append("normal")
    if meets_slo(phases["overload"]):
        failures.append("overload_not_reached")
    if recovery_time is None or not state["Running"] or state["OOMKilled"]:
        failures.append("recovery")
driver_hash = path / "driver.sha256"
data.update(
    peer=peer, flow=flow, status="INVALID" if reasons else ("FAIL" if failures else "PASS"),
    generator_slots=int(metadata["concurrency"]) if "concurrency" in metadata else None,
    generator_profile=os.environ.get("BENCH_GO_PROFILE", "base"),
    generator_workers=int(os.environ.get("BENCH_GO_WORKERS", "15")),
    postgres_profile=os.environ.get("BENCH_PG_PROFILE", "base"),
    generator_sha256=driver_hash.read_text().split()[0] if driver_hash.is_file() else None,
    invalid_reasons=reasons, slo_failing_operations=failures, resources=resources,
    host_cpu_psi_pct=pressure, shared_cgroup=cgroup, host_cpu_psi_seconds=sample_seconds,
    host_pressure_pct=host_pressure_pct,
    **cpu_metrics(path, start, end, [int(cpu) for cpu in os.environ.get("BENCH_APP_CPUS", "").split(",") if cpu]),
    app_cpu_seconds=cpu_time,
    server_total_cpu_cores=sum(resources.get(r, {}).get("mean_cpu_cores", 0) for r in server_roles),
    server_peak_rss_sum_mib=max(total_rss, default=None),
    tps_per_app_core=a["successful_tps"]/cpu if cpu else None,
    cpu_microseconds_per_success=cpu_time*1e6/a["success"] if cpu_time is not None and a["success"] else None,
)
if flow == "refresh" and (path / "proof.json").is_file():
    proof = json.loads((path / "proof.json").read_bytes())
    if proof.get("fixture_contract") == "rotating-family-pool":
        data["refresh_fixture"] = {key: proof[key] for key in
                                   ("fixture_contract", "users", "families_per_user", "fixtures")}
if peer == "nazo" and os.environ.get("BENCH_NAZO_REVISION"):
    data["product_revision"] = os.environ["BENCH_NAZO_REVISION"]
print(json.dumps(data, indent=2))
