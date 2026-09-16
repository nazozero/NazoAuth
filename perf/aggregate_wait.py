#!/usr/bin/env python3
"""Aggregate wait-event diagnostic matrix into a structured JSON result.

Reads /workspace/perf-results/waitprobe-matrix/{sampler/point_N.json,
runs/<tag>/capacity-*.summary.json} and emits per-point metrics + cross-point
comparison to perf-results/waitprobe-matrix/aggregate.json.

Snapshot layout: point["baseline"|"final"] =
  {ts, pg_stat_database:[row], pg_stat_wal:[row], pg_stat_io:[rows]}.
PG18: pg_stat_wal has counters only; WAL write/fsync timing lives in
pg_stat_io rows with object='wal'.
"""
import json, glob, os
from collections import defaultdict

BASE = "/workspace/perf-results/waitprobe-matrix"
POINTS = ["cc-c8", "cc-c16", "cc-c32", "cc-c64",
          "refresh-c8", "refresh-c16", "refresh-c32", "refresh-c64"]
MEASURE_S = 60.0
DB_KEYS = ["xact_commit", "xact_rollback", "tup_returned", "tup_fetched",
           "tup_inserted", "tup_updated", "tup_deleted", "blks_read",
           "blks_hit", "blk_read_time", "blk_write_time", "deadlocks",
           "temp_bytes", "numbackends"]
WAL_KEYS = ["wal_records", "wal_fpi", "wal_bytes", "wal_buffers_full"]
IO_DIMS = ("backend_type", "object", "context")
IO_NUMS = ["reads", "read_bytes", "read_time", "writes", "write_bytes",
           "write_time", "writebacks", "writeback_time", "extends",
           "extend_bytes", "extend_time", "hits", "evictions", "reuses",
           "fsyncs", "fsync_time"]


def load_summary(tag):
    fs = glob.glob(f"{BASE}/runs/{tag}/capacity-*.summary.json")
    return json.load(open(fs[0])) if fs else None


def delta(fin, base, keys):
    return {k: (fin.get(k) or 0) - (base.get(k) or 0) for k in keys}


def io_delta(fin, base):
    def key(r):
        return "|".join(str(r.get(c)) for c in IO_DIMS)
    bm = {key(r): r for r in base}
    out = {}
    for r in fin:
        k = key(r)
        b = bm.get(k, {})
        d = {c: round((r.get(c) or 0) - (b.get(c) or 0), 2) for c in IO_NUMS}
        if any(v for v in d.values()):
            out[k] = d
    return out


def wal_io(io_d):
    """Extract client-backend WAL write/fsync rows from io delta map."""
    wal = {"writes": 0, "write_time": 0.0, "fsyncs": 0, "fsync_time": 0.0}
    for k, d in io_d.items():
        if "|wal|" not in k:
            continue
        for f in wal:
            wal[f] += d.get(f, 0)
    return wal


def wait_hist(point):
    act, idle = defaultdict(int), defaultdict(int)
    for k, v in point["wait_hist"].items():
        state, wet, we, qid = k.split("|")
        if state == "active":
            act[f"{wet}|{we}"] += v
        else:
            idle[f"{state}|{wet}|{we}"] += v
    return dict(act), dict(idle), sum(act.values())


def wait_hist_by_qid(point):
    h = defaultdict(int)
    for k, v in point["wait_hist"].items():
        state, wet, we, qid = k.split("|")
        if state == "active":
            h[f"{wet}|{we}|{qid}"] += v
    return dict(h)


def lock_hist(point):
    h = defaultdict(int)
    for k, v in point["lock_hist"].items():
        lt, mode, granted = k.split("|")
        h[f"{lt}|{mode}|{'waiting' if granted == 'False' else 'held'}"] += v
    return dict(h)


def main():
    res = {"points": {}}
    for i, tag in enumerate(POINTS, 1):
        pfile = f"{BASE}/sampler/point_{i}.json"
        if not os.path.exists(pfile):
            res["points"][tag] = {"error": "missing point json"}
            continue
        pt = json.load(open(pfile))
        sm = load_summary(tag) or {}
        meas = (sm.get("k6") or {}).get("measure") or {}
        ops = meas.get("ops") or 0
        dt = pt["final_ts"] - pt["baseline_ts"]

        fdb, bdb = pt["final"]["pg_stat_database"][0], pt["baseline"]["pg_stat_database"][0]
        fwal, bwal = pt["final"]["pg_stat_wal"][0], pt["baseline"]["pg_stat_wal"][0]
        db_d = delta(fdb, bdb, DB_KEYS)
        wal_d = delta(fwal, bwal, WAL_KEYS)
        io_d = io_delta(pt["final"]["pg_stat_io"], pt["baseline"]["pg_stat_io"])
        walio = wal_io(io_d)
        act_h, idle_h, act_n = wait_hist(pt)

        stmts = pt["statements"]
        tot_calls = sum(s["calls"] for s in stmts)
        tot_ms = sum(s["total_exec_time"] for s in stmts)
        top_time = sorted(stmts, key=lambda s: -s["total_exec_time"])[:15]
        top_calls = sorted(stmts, key=lambda s: -s["calls"])[:15]

        res["points"][tag] = {
            "baseline_ts": pt["baseline_ts"],
            "final_ts": pt["final_ts"],
            "window_s": round(dt, 2),
            "ops": ops,
            "ops_per_s": round(ops / MEASURE_S, 2),
            "http_reqs_total": sum(s.get("http_reqs", 0) for s in sm.get("steps", [])),
            "errors": meas.get("errors"),
            "p50": (meas.get("latency_ms") or {}).get("p50"),
            "p95": (meas.get("latency_ms") or {}).get("p95"),
            "p99": (meas.get("latency_ms") or {}).get("p99"),
            "sql_calls_total": tot_calls,
            "sql_calls_per_op": round(tot_calls / ops, 2) if ops else None,
            "sql_exec_ms_total": round(tot_ms, 1),
            "sql_exec_ms_per_op": round(tot_ms / ops, 2) if ops else None,
            "xact_commit_per_s": round(db_d["xact_commit"] / dt, 2),
            "xact_rollback_per_s": round(db_d["xact_rollback"] / dt, 2),
            "commits_per_op": round(db_d["xact_commit"] / ops, 3) if ops else None,
            "db_deltas": {k: round(v, 2) for k, v in db_d.items()},
            "wal_bytes_per_op": round(wal_d["wal_bytes"] / ops, 1) if ops else None,
            "wal_records_per_op": round(wal_d["wal_records"] / ops, 2) if ops else None,
            "wal_fpi_per_op": round(wal_d["wal_fpi"] / ops, 3) if ops else None,
            "wal_deltas": {k: round(v, 2) for k, v in wal_d.items()},
            "wal_writes": walio["writes"],
            "wal_write_time_ms": round(walio["write_time"], 1),
            "wal_fsyncs": walio["fsyncs"],
            "wal_fsync_time_ms": round(walio["fsync_time"], 1),
            "wal_fsync_ms_per_op": round(walio["fsync_time"] / ops, 3) if ops else None,
            "wal_fsyncs_per_op": round(walio["fsyncs"] / ops, 3) if ops else None,
            "data_io": {k: v for k, v in io_d.items() if "|wal|" not in k},
            "wal_io": {k: v for k, v in io_d.items() if "|wal|" in k},
            "wait_active_hist": act_h,
            "wait_active_by_qid": wait_hist_by_qid(pt),
            "wait_idle_hist": idle_h,
            "active_rows": act_n,
            "lock_hist": lock_hist(pt),
            "db_pool_wait_ms_avg": (sm.get("db_pool") or {}).get("wait_ms_avg"),
            "db_pool_acquire": (sm.get("db_pool") or {}).get("acquire_count"),
            "top_sql_by_time": [
                {"calls": s["calls"], "ms": round(s["total_exec_time"], 1),
                 "mean_ms": round(s["mean_exec_time"], 3),
                 "queryid": s.get("queryid"), "q": s["query"][:160]}
                for s in top_time],
            "top_sql_by_calls": [
                {"calls": s["calls"], "ms": round(s["total_exec_time"], 1),
                 "mean_ms": round(s["mean_exec_time"], 3),
                 "queryid": s.get("queryid"), "q": s["query"][:160]}
                for s in top_calls],
        }
    out = f"{BASE}/aggregate.json"
    json.dump(res, open(out, "w"), indent=1)
    print("wrote", out)
    for tag in POINTS:
        p = res["points"].get(tag, {})
        print(f"{tag:12s} ops={p.get('ops')} ops/s={p.get('ops_per_s')} "
              f"sql/op={p.get('sql_calls_per_op')} sqlms/op={p.get('sql_exec_ms_per_op')} "
              f"commit/s={p.get('xact_commit_per_s')} walB/op={p.get('wal_bytes_per_op')} "
              f"fsyncMs/op={p.get('wal_fsync_ms_per_op')} "
              f"p99={p.get('p99')} err={p.get('errors')}")


if __name__ == "__main__":
    main()
