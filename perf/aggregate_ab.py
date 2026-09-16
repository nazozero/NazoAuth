#!/usr/bin/env python3
"""Aggregate A/B wait-event points: toplevel/nested split, SELECT$1/op,
pool acquire/op delta, wait + lock histograms. BASE from env AB_BASE."""
import json, glob, os
from collections import defaultdict

BASE = os.environ.get("AB_BASE", "/workspace/perf-results/waitprobe-ab")
POINTS = ["cc-c8", "cc-c32", "refresh-c8", "refresh-c32"]
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
        d = {c: round((r.get(c) or 0) - (bm.get(k, {}).get(c) or 0), 2) for c in IO_NUMS}
        if any(v for v in d.values()):
            out[k] = d
    return out


def wal_io(io_d):
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


def acquire(pt):
    def get(side):
        m = pt.get(side, {}).get("app_metrics") or {}
        return ((m.get("db_pool") or {}).get("acquire_count"))
    f, b = get("final"), get("baseline")
    return (f - b) if (f is not None and b is not None) else None


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
        tl = [s for s in stmts if s.get("toplevel")]
        nt = [s for s in stmts if s.get("toplevel") is False]
        tot_calls = sum(s["calls"] for s in stmts)
        tl_calls = sum(s["calls"] for s in tl)
        nt_calls = sum(s["calls"] for s in nt)
        tot_ms = sum(s["total_exec_time"] for s in stmts)
        sel1 = next((s for s in stmts if s["query"].strip() == "SELECT $1"), None)
        acq = acquire(pt)

        res["points"][tag] = {
            "window_s": round(dt, 2),
            "ops": ops,
            "ops_per_s": round(ops / MEASURE_S, 2),
            "http_reqs_measure": ops,  # cc/refresh scenarios: 1 HTTP request per business op
            "errors": meas.get("errors"),
            "p50": (meas.get("latency_ms") or {}).get("p50"),
            "p95": (meas.get("latency_ms") or {}).get("p95"),
            "p99": (meas.get("latency_ms") or {}).get("p99"),
            "stmt_calls_total": tot_calls,
            "toplevel_calls_per_op": round(tl_calls / ops, 3) if ops else None,
            "nested_calls_per_op": round(nt_calls / ops, 3) if ops else None,
            "select1_calls": sel1["calls"] if sel1 else 0,
            "select1_per_op": round((sel1["calls"] if sel1 else 0) / ops, 3) if ops else None,
            "pool_acquire_delta": acq,
            "pool_acquire_per_op": round(acq / ops, 3) if (acq and ops) else None,
            "sql_exec_ms_per_op": round(tot_ms / ops, 2) if ops else None,
            "xact_commit_per_s": round(db_d["xact_commit"] / dt, 2),
            "wal_bytes_per_op": round(wal_d["wal_bytes"] / ops, 1) if ops else None,
            "wal_fsync_ms_per_op": round(walio["fsync_time"] / ops, 3) if ops else None,
            "wait_active_hist": act_h,
            "wait_active_by_qid": wait_hist_by_qid(pt),
            "active_rows": act_n,
            "lock_hist": lock_hist(pt),
            "db_pool_wait_ms_avg": (sm.get("db_pool") or {}).get("wait_ms_avg"),
            "top_sql_by_time": [
                {"calls": s["calls"], "ms": round(s["total_exec_time"], 1),
                 "mean_ms": round(s["mean_exec_time"], 3), "toplevel": s.get("toplevel"),
                 "queryid": s.get("queryid"), "q": s["query"][:160]}
                for s in sorted(stmts, key=lambda s: -s["total_exec_time"])[:15]],
            "top_sql_by_calls": [
                {"calls": s["calls"], "ms": round(s["total_exec_time"], 1),
                 "mean_ms": round(s["mean_exec_time"], 3), "toplevel": s.get("toplevel"),
                 "queryid": s.get("queryid"), "q": s["query"][:160]}
                for s in sorted(stmts, key=lambda s: -s["calls"])[:15]],
        }
    out = f"{BASE}/aggregate.json"
    json.dump(res, open(out, "w"), indent=1, default=str)
    print("wrote", out)
    for tag, p in res["points"].items():
        if "error" in p:
            print(tag, p)
            continue
        print("%-10s ops=%7d ops/s=%7.1f tl/op=%5.2f nt/op=%5.2f sel1/op=%5.2f acq/op=%5.2f p50=%s p95=%s p99=%s err=%s" % (
            tag, p["ops"], p["ops_per_s"], p["toplevel_calls_per_op"],
            p["nested_calls_per_op"], p["select1_per_op"], (p["pool_acquire_per_op"] or -1),
            p["p50"], p["p95"], p["p99"], p["errors"]))


main()
