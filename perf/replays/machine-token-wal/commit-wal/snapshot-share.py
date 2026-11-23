"""Summarize same-request timings from a diagnostic run, dropping warm-up and drain."""
from datetime import datetime
import json
from pathlib import Path
from statistics import median
import sys

window = json.loads(Path(sys.argv[1]).read_text())
start = window["scenario_started_unix_ms"] + window["workload"]["warm"] * 1000
end = start + window["duration_seconds"] * 1000
samples = []
for line in sys.stdin:
    fields = line.split()
    if len(fields) != 4 or fields[1] != "BENCH_MACHINE_SNAPSHOT":
        continue
    completed = datetime.fromisoformat(fields[0].replace("Z", "+00:00")).timestamp() * 1000
    if start <= completed < end:
        read, total = map(int, fields[2:])
        assert 0 <= read <= total and total > 0
        samples.append((read, total))

def nearest_rank(values, q):
    from math import ceil
    ordered = sorted(values)
    return ordered[ceil(q * len(ordered)) - 1]

if len(samples) < 100:
    raise SystemExit("insufficient timing samples")
limit = nearest_rank([total for _, total in samples], .95)
slow = [(read, total) for read, total in samples if total >= limit]
summary = {
    "n": len(samples),
    "snapshot_p95_ms": nearest_rank([s[0] for s in samples], .95) / 1e6,
    "snapshot_p99_ms": nearest_rank([s[0] for s in samples], .99) / 1e6,
    "request_span_p99_ms": nearest_rank([s[1] for s in samples], .99) / 1e6,
    "slowest_5pct_count": len(slow),
    "slowest_5pct_median_snapshot_share": median(read / total for read, total in slow),
    "slowest_5pct_snapshot_over_half": sum(read * 2 > total for read, total in slow),
}
print(json.dumps(summary, indent=2))
