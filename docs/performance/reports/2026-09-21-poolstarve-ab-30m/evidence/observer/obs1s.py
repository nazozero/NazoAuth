#!/usr/bin/env python3
"""1s-granularity observer for pool-starvation diagnosis.

One JSONL row per wall second:
  pool    : app db_pool cumulative counters (acq/wait_ns/wait_max_ns)
  act     : pg_stat_activity dump for runtime role (per-backend array rows)
            + aggregates
  locks   : pg_locks granted=false rows + pg_blocking_pids
  ckpt    : pg_stat_checkpointer row (cumulative)
  wal     : pg_stat_wal row (cumulative)
  io      : pg_stat_io per backend_type (cumulative)
  disk    : /host/proc/diskstats row for md0 (+ per-member vdb..vdu)
  load    : /host/proc/loadavg
Errors are recorded per-section as *_err, never abort the loop.
"""
import json
import os
import sys
import time
import urllib.request

import psycopg

DB = os.environ.get("DB_URL", "postgresql://postgres:postgres@postgres:5432/oauth")
APP = os.environ.get("APP_METRICS", "http://nazoauth:8000/__perf/metrics")
OUT = os.environ.get("OUT_PATH", "/out/obs.jsonl")
ROLE = os.environ.get("RUNTIME_ROLE", "nazoauth_perf_runtime")
DISK_DEVS = os.environ.get("DISK_DEVS", "md0").split()


def read_diskstats(devs):
    res = {}
    try:
        with open("/host/proc/diskstats") as f:
            for l in f:
                p = l.split()
                if len(p) >= 14 and p[2] in devs:
                    res[p[2]] = {
                        "rio": int(p[3]), "rsect": int(p[5]), "ruse_ms": int(p[6]),
                        "wio": int(p[7]), "wsect": int(p[9]), "wuse_ms": int(p[10]),
                        "in_flight": int(p[11]), "io_ms": int(p[12]), "wio_ms": int(p[13]),
                    }
    except OSError as e:
        res["err"] = str(e)[:80]
    return res


def read_load():
    try:
        with open("/host/proc/loadavg") as f:
            return f.read().split()[:4]
    except OSError:
        return None


def main():
    out = open(OUT, "a", buffering=1)
    conn = psycopg.connect(DB, autocommit=True)
    while True:
        t0 = time.time()
        row = {"ts": int(t0), "q_ms": 0}
        try:
            with conn.cursor() as c:
                c.execute(
                    "SELECT pid,state,wait_event_type,wait_event,query_id,"
                    "xact_start,query_start,backend_xid,backend_xmin "
                    "FROM pg_stat_activity WHERE usename=%s ORDER BY pid",
                    (ROLE,))
                rows = c.fetchall()
                row["act"] = {
                    "n": len(rows),
                    "active": sum(1 for r in rows if r[1] == "active"),
                    "idle": sum(1 for r in rows if r[1] == "idle"),
                    "iit": sum(1 for r in rows if r[1] == "idle in transaction"),
                    "waiting": sum(1 for r in rows if r[2]),
                    "xmin": sum(1 for r in rows if r[8] is not None),
                    "rows": [[r[0], r[1], r[2], r[3], r[4],
                              str(r[5]) if r[5] else None,
                              str(r[6]) if r[6] else None,
                              str(r[7]) if r[7] else None,
                              str(r[8]) if r[8] else None] for r in rows],
                }
                c.execute(
                    "SELECT COALESCE(max(extract(epoch FROM now()-xact_start))::bigint,-1),"
                    "COALESCE(max(age(backend_xmin)),-1) "
                    "FROM pg_stat_activity WHERE xact_start IS NOT NULL "
                    "AND pid<>pg_backend_pid()")
                row["xact"] = list(c.fetchone())
                c.execute(
                    "SELECT l.pid,l.locktype,l.mode,"
                    "COALESCE(l.relation::regclass::text,''),pg_blocking_pids(l.pid) "
                    "FROM pg_locks l WHERE NOT l.granted LIMIT 200")
                row["locks"] = [list(r) for r in c.fetchall()]
                c.execute(
                    "SELECT num_timed,num_requested,num_done,write_time,sync_time,"
                    "buffers_written,slru_written FROM pg_stat_checkpointer")
                row["ckpt"] = list(c.fetchone())
                c.execute(
                    "SELECT wal_records,wal_fpi,wal_bytes::float8,"
                    "wal_buffers_full FROM pg_stat_wal")
                row["wal"] = list(c.fetchone())
                c.execute(
                    "SELECT backend_type,reads,read_bytes::float8,read_time,"
                    "writes,write_bytes::float8,write_time,writebacks,fsyncs,"
                    "fsync_time FROM pg_stat_io")
                row["io"] = {r[0]: list(r[1:]) for r in c.fetchall()}
        except Exception as e:
            row["pg_err"] = str(e)[:160]
            try:
                conn = psycopg.connect(DB, autocommit=True)
            except Exception:
                pass
        try:
            req = urllib.request.Request(APP, headers={"Host": "127.0.0.1"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                pm = json.load(resp)
            p = pm["db_pool"]
            row["pool"] = {"acq": p["acquire_count"],
                           "wait_ns": p["wait_nanos_total"],
                           "wait_max_ns": p["wait_nanos_max"]}
        except Exception as e:
            row["app_err"] = str(e)[:120]
        row["disk"] = read_diskstats(DISK_DEVS)
        row["load"] = read_load()
        row["q_ms"] = int((time.time() - t0) * 1000)
        out.write(json.dumps(row) + "\n")
        dt = time.time() - t0
        time.sleep(max(0.0, 1.0 - dt))


if __name__ == "__main__":
    sys.exit(main())
