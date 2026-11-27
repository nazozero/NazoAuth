import json, pathlib, statistics

def sample_resources(samples_path, start, end):
    resources = {}
    for path in sorted(samples_path.glob("*.cpu.tsv")):
        lines = path.read_text().splitlines()
        window = []
        mismatches = 0
        for line in lines:
            clock, pid, label, tick, rss, count_threads, mismatched, expected = line.split("\t")
            clock, pid, tick, rss, count_threads, mismatched = map(
                int, (clock, pid, tick, rss, count_threads, mismatched))
            mismatches += mismatched
            if count_threads:
                window.append((clock, pid, label, tick, rss, count_threads))
        role = path.name.removesuffix(".cpu.tsv")
        resources[role] = {
            "thread_observations": sum(x[5] for x in window), "affinity_mismatches": mismatches,
            "max_single_process_rss_mib": round(max((x[4] for x in window if start <= x[0] < end), default=0) / 1024, 2),
        }
        if window:
            ticks = {}
            for clock, pid, label, used, _, _ in window:
                if start <= clock < end:
                    ticks.setdefault(clock, {})[pid] = used
            intervals = []
            for t1, t2 in zip(sorted(ticks), sorted(ticks)[1:]):
                delta = sum(ticks[t2][p] - ticks[t1][p] for p in ticks[t1].keys() & ticks[t2].keys())
                intervals.append(delta * 10 / (t2 - t1))
            if intervals:
                resources[role].update(
                    mean_cpu_cores=round(statistics.mean(intervals), 2),
                    sampled_intervals=len(intervals),
                )
    return resources


def counter_delta(first, last):
    return last - first if 0 <= first <= last else None


def sample_cgroup_roles(samples_path, resources, start, end):
    shared = None
    for role, summary in resources.items():
        path = samples_path / (role + ".cgroup.tsv")
        if not path.is_file():
            continue
        rows = []
        for line in path.read_text().splitlines():
            try:
                row = tuple(map(int, line.split("\t")))
            except ValueError:
                continue
            if len(row) == 11 and start <= row[0] < end:
                rows.append(row)
        if len(rows) < 2:
            continue
        first, last = rows[0], rows[-1]
        seconds = (last[0] - first[0]) / 1000
        summary.update(network_rx_bytes=counter_delta(first[7], last[7]),
                       network_tx_bytes=counter_delta(first[8], last[8]),
                       network_sample_seconds=seconds)
        if role == "app":
            shared = {"peak_memory_bytes": max(row[1] for row in rows),
                      "peak_rss_bytes": max(row[2] for row in rows),
                      "peak_cache_bytes": max(row[3] for row in rows),
                      "cpu_throttled_events": counter_delta(first[5], last[5]),
                      "cpu_throttled_ns": counter_delta(first[6], last[6]),
                      "block_read_bytes": counter_delta(first[9], last[9]),
                      "block_write_bytes": counter_delta(first[10], last[10]),
                      "sample_seconds": seconds}
            shared = {key: value if value is not None and value >= 0 else None for key, value in shared.items()}
    return shared


def sample_host_pressure(path, start, end):
    entries = []
    for line in path.read_text().splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if start <= row["t"] <= end:
            pressure = next((p for p in row.get("pressure_cpu", []) if p.startswith("some ")), None)
            if pressure:
                entries.append((row["t"], int(pressure.rsplit("total=", 1)[1])))
    if len(entries) < 2 or entries[-1][0] <= entries[0][0]:
        return None, 0
    first, last = entries[0], entries[-1]
    elapsed = last[0] - first[0]
    return round((last[1] - first[1]) / elapsed / 10, 2), elapsed / 1000
