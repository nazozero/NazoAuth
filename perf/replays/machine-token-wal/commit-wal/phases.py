"""Join the two ends of a COMMIT by TCP port and monotonic time containment."""

from bisect import bisect_right
from collections import defaultdict
from math import ceil
from pathlib import Path
import json, sys

window, client, server = map(Path, sys.argv[1:])
bench = json.loads(window.read_text())
start = (bench["scenario_started_unix_ms"] + 1000 * bench["workload"]["warm"]) * 1000000
end = start + bench["duration_seconds"] * 1000000000
sent, received = defaultdict(list), defaultdict(list)
for line in client.open():
    kind, port, ts = line.split()
    (sent if kind == "A" else received)[int(port)].append(int(ts))
for s in [sent, received]:
    for a in s.values():
        a.sort()
rows = []
candidates = 0
for line in server.open():
    (
        _,
        port,
        first,
        last,
        done,
        sched,
        cpu,
        sync,
        write,
        lock,
        sync_rq,
        write_rq,
        lock_rq,
        epoch,
        mono,
    ) = line.split()
    (
        port,
        first,
        last,
        done,
        sched,
        cpu,
        sync,
        write,
        lock,
        sync_rq,
        write_rq,
        lock_rq,
        epoch,
        mono,
    ) = map(
        int,
        (
            port,
            first,
            last,
            done,
            sched,
            cpu,
            sync,
            write,
            lock,
            sync_rq,
            write_rq,
            lock_rq,
            epoch,
            mono,
        ),
    )
    if not start <= epoch < end:
        continue
    candidates += 1
    a = bisect_right(sent[port], first) - 1
    b = bisect_right(received[port], last)
    if a < 0 or b == len(received[port]):
        continue
    left, right = sent[port][a], received[port][b]
    # Reject an incomplete observation rather than bridging to a different request.
    if (
        b
        and received[port][b - 1] > left
        or a + 1 < len(sent[port])
        and sent[port][a + 1] < right
    ):
        continue
    exclusive_sched = max(0, sched - sync_rq - write_rq - lock_rq)
    rows.append(
        dict(
            total=right - left,
            app_to_pg=first - left,
            pg=last - first,
            pg_to_app=right - last,
            wal_sync=sync,
            wal_write=write,
            wal_group_wait=lock,
            pg_runnable=sched,
            runnable_outside_wal=exclusive_sched,
            pg_cpu=cpu,
            other_pg=last - first - sync - write - lock - exclusive_sched,
        )
    )
if len(rows) < 100 or len(rows) < candidates * 0.90:
    raise SystemExit(
        f"only {len(rows)}/{candidates} matching protocol samples, client ports={len(sent)}/{len(received)}"
    )


def pct(v, p):
    v = sorted(v)
    i = (len(v) - 1) * p
    return round((v[int(i)] + (v[ceil(i)] - v[int(i)]) * (i - int(i))) / 1e6, 4)


def summary(rows):
    return {
        k: {str(p): pct([x[k] for x in rows], p / 100) for p in (50, 95, 99)}
        for k in rows[0]
    }


tail = sorted(rows, key=lambda x: x["total"], reverse=True)[: ceil(0.05 * len(rows))]
result = dict(
    samples=len(rows),
    candidates=candidates,
    phases_ms=summary(rows),
    slowest5_ms=summary(tail),
    slowest5=len(tail),
    wal_majority_slowest5=sum(
        2 * (x["wal_sync"] + x["wal_group_wait"] + x["wal_write"]) > x["total"]
        for x in tail
    ),
    local_sync_samples=sum(x["wal_sync"] > 0 for x in rows),
    group_wait_samples=sum(x["wal_group_wait"] > 0 for x in rows),
)
window.with_suffix(".phases.json").write_text(json.dumps(result, indent=2) + "\n")
print(result["samples"], result["phases_ms"])
