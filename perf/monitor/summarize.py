"""Summarize an arrival ledger. Retain the ledger alongside the result."""
import argparse
from bisect import bisect_right
import csv
import json
import math
from collections import Counter, defaultdict
from pathlib import Path


def latency(ns):
    if not ns:
        return None
    ns.sort()
    return {str(p): ns[math.ceil(p / 100 * len(ns)) - 1] / 1e6
            for p in (50, 95, 99, 99.9, 100)}


def summarize(path, rate, warm, seconds, schedule=None):
    end = (warm + seconds) * 10**9
    start = warm * 10**9
    phases = []
    expected = 0
    phase_start = 0
    for duration, phase_rate in schedule or [(warm + seconds, rate)]:
        phases.append((expected, phase_start, phase_rate, duration))
        expected += duration * phase_rate
        phase_start += duration * 10**9
    assert phase_start == end
    phase_slots = [p[0] for p in phases]
    seen = bytearray(expected)
    data = defaultdict(list)
    phase_data = defaultdict(list)
    with path.open(newline="") as src:
        for row in csv.DictReader(src, delimiter="\t"):
            slot, due = int(row["slot"]), int(row["due_ns"])
            assert 0 <= slot < expected and not seen[slot]
            seen[slot] = 1
            phase = bisect_right(phase_slots, slot) - 1
            phase_first, phase_start, phase_rate, _ = phases[phase]
            assert due == phase_start + (slot - phase_first) * 10**9 // phase_rate
            sent = int(row["sent_ns"]) if row["sent_ns"] else None
            complete = int(row["completed_ns"]) if row["completed_ns"] else None
            assert (sent is None) == (complete is None)
            if sent is not None:
                assert due <= sent <= complete and sent < end
            if due >= start:
                record = (due, sent, complete, row["outcome"], int(row["status"]),
                          int(row.get("http_requests", "1" if sent is not None else "0")))
                data["all"].append(record)
                data[row["operation"]].append(record)
                if schedule:
                    phase_data[phase].append(record)
    assert all(seen)
    assert len(data["all"]) == expected - warm * rate
    result = {"rate": rate, "warm_seconds": warm, "seconds": seconds, "operations": {}}
    for op, records in data.items():
        result["operations"][op] = summarize_records(records, start, seconds)
    if schedule:
        phase_names = ("normal", "overload", "recovery")
        result["phases"] = {}
        for phase, name in enumerate(phase_names, 1):
            _, begin, target, duration = phases[phase]
            result["phases"][name] = dict(summarize_records(phase_data[phase], begin, duration),
                                          target_tps=target, seconds=duration)
        _, begin, target, duration = phases[-1]
        assert duration % 3 == 0
        buckets = [[] for _ in range(duration // 3)]
        for record in phase_data[len(phases) - 1]:
            buckets[(record[0] - begin) // (3 * 10**9)].append(record)
        result["recovery_buckets"] = [
            dict(summarize_records(records, begin + i * 3 * 10**9, 3), seconds_after_overload=i * 3,
                 total_in_flight=result["operations"]["all"]["in_flight_at_second_boundaries"][
                     (begin - start) // 10**9 + i * 3 + 2])
            for i, records in enumerate(buckets)
        ]
    return result


def summarize_records(records, start, seconds):
    end = start + seconds * 10**9
    statuses = Counter(str(r[4]) for r in records if r[1] is not None)
    outcomes = Counter(r[3] for r in records)
    sent = [(d, s, c, o) for d, s, c, o, _, _ in records if s is not None]
    success = [(d, s, c) for d, s, c, o in sent if o == "ok"]
    # Differences produce the number of active operations at each second boundary.
    changes = [0] * (seconds + 1)
    for _, s, c, _ in sent:
        first = (s - start) // 10**9
        last = min(seconds, (c - start) // 10**9)
        if first < seconds:
            changes[first] += 1
            changes[last] -= 1
    pending, outstanding = [], 0
    for change in changes[:-1]:
        outstanding += change
        pending.append(outstanding)
    return dict(
        planned=len(records), sent=len(sent), not_sent=len(records) - len(sent),
        completed_by_cutoff=sum(c < end for _, _, c, _ in sent),
        in_flight_at_cutoff=sum(c >= end for _, _, c, _ in sent),
        success=len(success), failed=len(sent) - len(success),
        successful_tps=len(success) / seconds, attainment=len(success) / len(records),
        outcomes=outcomes, http_status_counts=statuses,
        http_requests=sum(r[5] for r in records), http_rps=sum(r[5] for r in records)/seconds,
        scheduling_ms=latency([s - d for d, s, _, _ in sent]),
        response_all_ms=latency([c - s for _, s, c, _ in sent]),
        response_success_ms=latency([c - s for _, s, c in success]),
        offered_to_completion_success_ms=latency([c - d for d, _, c in success]),
        in_flight_at_second_boundaries=pending,
    )


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("ledger", type=Path)
    p.add_argument("rate", type=int)
    p.add_argument("warm", type=int)
    p.add_argument("seconds", type=int)
    p.add_argument("--schedule", help="warm-up,normal,overload,recovery as duration@TPS")
    a = p.parse_args()
    schedule = [tuple(map(int, p.split("@"))) for p in a.schedule.split(",")] if a.schedule else None
    print(json.dumps(summarize(a.ledger, a.rate, a.warm, a.seconds, schedule), indent=2))
