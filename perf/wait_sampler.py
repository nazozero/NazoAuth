#!/usr/bin/env python3
"""Autonomous PG wait-event sampler for isolated measurement windows.

State machine (driven by runtime-role activity):
  idle -> (activity) -> warming -> (idle >= IDLE_S) -> gap: reset+baseline
       -> (activity resumes, then idle >= IDLE_S) -> final snapshot -> point JSON

Writes to /shared:
  point_<seq>.json   per measurement window (baselines, finals, statements, wait agg)
  activity.jsonl     every sample row (point-tagged when inside a window)
  locks.jsonl        every lock aggregate row
"""
import json
import os
import time
from pathlib import Path

import psycopg

DSN = "postgresql://postgres:postgres@postgres:5432/oauth"
APP_USER = "nazoauth_perf_runtime"
POLL_S = 0.3
IDLE_S = 2.5
OUT = Path("/shared")
OUT.mkdir(parents=True, exist_ok=True)

ACT_SQL = """
SELECT state, wait_event_type, wait_event, query_id, count(*) AS n,
       max(EXTRACT(EPOCH FROM clock_timestamp() - query_start)) AS max_qs_age
FROM pg_stat_activity
WHERE usename = %s
GROUP BY 1,2,3,4
"""
LOCK_SQL = """
SELECT locktype, mode, granted, count(*) AS n
FROM pg_locks
WHERE database IS NULL OR database = (SELECT oid FROM pg_database WHERE datname = current_database())
GROUP BY 1,2,3
"""
ACTIVE_SQL = """
SELECT count(*) FROM pg_stat_activity
WHERE usename = %s AND state IN ('active', 'idle in transaction', 'idle in transaction (aborted)')
"""
DB_SQL = "SELECT * FROM pg_stat_database WHERE datname = 'oauth'"
WAL_SQL = "SELECT * FROM pg_stat_wal"
IO_SQL = "SELECT * FROM pg_stat_io"
STMT_SQL = """
SELECT s.queryid, s.toplevel, s.calls, s.total_exec_time, s.mean_exec_time,
       s.min_exec_time, s.max_exec_time, s.rows, s.shared_blks_read,
       s.shared_blks_written, left(s.query, 500) AS query
FROM pg_stat_statements s
WHERE s.userid = (SELECT oid FROM pg_roles WHERE rolname = %s)
ORDER BY s.total_exec_time DESC
LIMIT 60
"""


def rows(cur, sql, params=()):
    cur.execute(sql, params)
    cols = [c.name for c in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


APP_METRICS_URL = os.environ.get("APP_METRICS_URL", "http://nazoauth:8000/__perf/metrics")


def app_metrics():
    try:
        import urllib.request
        req = urllib.request.Request(APP_METRICS_URL, headers={"Host": "127.0.0.1:8000"})
        with urllib.request.urlopen(req, timeout=3) as r:
            return json.loads(r.read().decode())
    except Exception as exc:
        return {"error": str(exc)}


def snap(cur):
    return {
        "ts": time.time(),
        "pg_stat_database": rows(cur, DB_SQL),
        "pg_stat_wal": rows(cur, WAL_SQL),
        "pg_stat_io": rows(cur, IO_SQL),
        "app_metrics": app_metrics(),
    }


def jdefault(o):
    from decimal import Decimal
    import datetime
    if isinstance(o, Decimal):
        return float(o)
    if isinstance(o, (datetime.datetime, datetime.date)):
        return o.isoformat()
    if isinstance(o, bytes):
        return o.hex()
    return str(o)


def main():
    conn = psycopg.connect(DSN, autocommit=True)
    cur = conn.cursor()
    act_log = open(OUT / "activity.jsonl", "a", buffering=1)
    lock_log = open(OUT / "locks.jsonl", "a", buffering=1)
    seq = len(list(OUT.glob("point_*.json")))
    state = "idle"
    idle_since = None
    point = None
    print("wait_sampler: running", flush=True)
    while not (OUT / "STOP").exists():
        t0 = time.time()
        try:
            cur.execute(ACTIVE_SQL, (APP_USER,))
            active = cur.fetchone()[0]
            act = rows(cur, ACT_SQL, (APP_USER,))
            lck = rows(cur, LOCK_SQL)
        except Exception as e:
            print("poll error:", e, flush=True)
            try:
                conn = psycopg.connect(DSN, autocommit=True)
                cur = conn.cursor()
            except Exception:
                pass
            time.sleep(POLL_S)
            continue
        ts = time.time()
        pid = point["seq"] if point else None
        act_log.write(json.dumps({"ts": ts, "point": pid, "rows": act}, default=jdefault) + "\n")
        lock_log.write(json.dumps({"ts": ts, "point": pid, "rows": lck}, default=jdefault) + "\n")
        if point:
            for r in act:
                key = (r["state"], r["wait_event_type"], r["wait_event"], r["query_id"])
                point["wait_hist"][key] = point["wait_hist"].get(key, 0) + r["n"]
                point["wait_samples"] += r["n"] if r["state"] != "idle" else 0
            for r in lck:
                key = (r["locktype"], r["mode"], r["granted"])
                point["lock_hist"][key] = point["lock_hist"].get(key, 0) + r["n"]

        if active == 0:
            idle_since = idle_since or ts
        else:
            idle_since = None
        idle_for = ts - idle_since if idle_since else 0

        if state == "idle":
            if active > 0:
                state = "warming"
        elif state == "warming":
            if idle_for >= IDLE_S:
                cur.execute("SELECT pg_stat_statements_reset()")
                base = snap(cur)
                seq += 1
                point = {
                    "seq": seq, "baseline": base, "baseline_ts": ts,
                    "wait_hist": {}, "lock_hist": {}, "wait_samples": 0,
                }
                state = "measuring"
                resumed = False
                consec_active = 0
                print(f"gap detected -> reset, point {seq} baseline @ {ts:.1f}", flush=True)
        elif state == "measuring":
            # Require sustained activity before arming completion: a single
            # stray-active sample during the gap (background workers) must not
            # let a 5s idle tail close the point before real measurement.
            if active > 0:
                consec_active += 1
            else:
                consec_active = 0
            if consec_active >= 5:
                resumed = True
            if resumed and idle_for >= IDLE_S:
                try:
                    point["final"] = snap(cur)
                    point["final_ts"] = ts
                    point["statements"] = rows(cur, STMT_SQL, (APP_USER,))
                    point["wait_hist"] = {
                        "|".join(str(x) for x in k): v for k, v in point["wait_hist"].items()
                    }
                    point["lock_hist"] = {
                        "|".join(str(x) for x in k): v for k, v in point["lock_hist"].items()
                    }
                    (OUT / f"point_{seq}.json").write_text(
                        json.dumps(point, indent=1, default=jdefault))
                    print(f"point {seq} complete @ {ts:.1f}", flush=True)
                except Exception:
                    import traceback; traceback.print_exc()
                point = None
                state = "idle"
                idle_since = None
        time.sleep(max(0.05, POLL_S - (time.time() - t0)))
    print("wait_sampler: stopped", flush=True)


if __name__ == "__main__":
    main()
