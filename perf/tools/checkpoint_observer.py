#!/usr/bin/env python3
"""Lightweight 1s PostgreSQL/host observer for checkpoint-jitter diagnostics.

Replaces the dimensional-lossy obs1s.py for diagnostic runs:
  * pg_stat_io rows are kept as an ARRAY keyed by (backend_type, object,
    context) — no overwrite across same-backend_type rows.
  * Persistent autocommit connection, monotonic 1s schedule; each row records
    the actual interval and query latency.
  * Missing/reset/unavailable values are emitted as null/error markers, never
    back-filled to 0.
  * Host disk stats are collected for the caller-provided PGDATA devices
    (DISK_DEVS) — md/DM device plus members are reported separately, never
    summed.
  * app pool counters come from the app metrics endpoint; deltas are computed
    by the analyzer, max gauges are reported as-is (never as per-second max).

Env:
  DB_URL        postgres://... (required)
  APP_METRICS   app metrics URL, e.g. http://nazoauth:8000/__perf/metrics
  APP_METRICS_HOST  optional Host header for tenant-routed app endpoints
  OUT_PATH      JSONL output path (required)
  DISK_DEVS     space-separated device names from /proc/diskstats (e.g.
                "md0 vdb vdc ..."); md0 members reported separately.
  INTERVAL_S    sampling interval, default 1.0
  HOST_PROC     /proc mount point, default /proc
  HOST_SYS      /sys mount point, default /sys
  OBSERVER_LABEL  label recorded in meta row
  APP_IDENTITY  app process identity string for pool rows
"""
import json
import os
import re
import sys
import time
import urllib.request
from datetime import datetime, timezone

try:
    import resource
except ImportError:  # non-POSIX hosts; container has it
    resource = None

try:
    import psycopg
except ImportError:  # required only in main(); tests import helpers offline
    psycopg = None

INTERVAL_S = float(os.environ.get("INTERVAL_S", "1.0"))
DB_URL = os.environ.get("DB_URL", "")
APP_METRICS = os.environ.get("APP_METRICS", "")
APP_METRICS_HOST = os.environ.get("APP_METRICS_HOST", "")
OUT_PATH = os.environ.get("OUT_PATH", "")
DISK_DEVS = [d for d in os.environ.get("DISK_DEVS", "").split() if d]
HOST_PROC = os.environ.get("HOST_PROC", "/proc")
HOST_SYS = os.environ.get("HOST_SYS", "/sys")
OBSERVER_LABEL = os.environ.get("OBSERVER_LABEL", "checkpoint-observer")
APP_IDENTITY = os.environ.get("APP_IDENTITY", "")



QUERIES = {
    "ckpt": "SELECT * FROM pg_stat_checkpointer",
    "wal": "SELECT * FROM pg_stat_wal",
    "io": "SELECT * FROM pg_stat_io",
    "act": """
        SELECT COALESCE(usename::text, 'bg:' || backend_type) AS who,
               backend_type, state, wait_event_type, wait_event, query_id,
               count(*)::int AS n
        FROM pg_stat_activity
        WHERE pid <> pg_backend_pid()
        GROUP BY 1, 2, 3, 4, 5, 6
    """,
    "db": "SELECT * FROM pg_stat_database WHERE datname = current_database()",
}


def utc_iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def dec_default(obj):
    # psycopg returns Decimal for numeric columns (wal_bytes, timings).
    # int() keeps full integer precision; float for fractional values.
    try:
        import decimal
        if isinstance(obj, decimal.Decimal):
            return int(obj) if obj == obj.to_integral_value() else float(obj)
    except ImportError:
        pass
    return str(obj)


def fetch_pg(conn):
    """Run all stat queries; each returns rows+cols. Errors are per-query."""
    out = {}
    for name, sql in QUERIES.items():
        t0 = time.monotonic()
        try:
            cur = conn.execute(sql)
            cols = [d.name for d in cur.description]
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]
            if name == "io":
                # Fixed dimensional key — never keyed by backend_type alone.
                out[name] = {
                    "key": "backend_type+object+context",
                    "rows": rows,
                    "query_ms": round((time.monotonic() - t0) * 1000, 2),
                }
            elif name == "act":
                out[name] = {
                    "grouping": "who+backend_type+state+wait_event_type+wait_event+query_id",
                    "rows": rows,
                    "query_ms": round((time.monotonic() - t0) * 1000, 2),
                }
            else:
                out[name] = {
                    "row": rows[0] if rows else None,
                    "row_count": len(rows),
                    "query_ms": round((time.monotonic() - t0) * 1000, 2),
                }
        except Exception as e:  # noqa: BLE001
            out[name] = {"error": f"{type(e).__name__}: {e}",
                         "query_ms": round((time.monotonic() - t0) * 1000, 2)}
            try:
                conn.rollback()
            except Exception:
                pass
    return out


def fetch_pool():
    """App /__perf/metrics JSON endpoint -> db_pool counters. Cumulative
    acquire/wait are emitted raw; the analyzer computes per-second deltas.
    wait_nanos_max is a process-lifetime max, never a per-second value."""
    if not APP_METRICS:
        return None
    t0 = time.monotonic()
    try:
        req = urllib.request.Request(APP_METRICS)
        if APP_METRICS_HOST:
            req.add_header("Host", APP_METRICS_HOST)
        with urllib.request.urlopen(req, timeout=0.8) as resp:
            doc = json.loads(resp.read().decode("utf-8", "replace"))
        pool = doc.get("db_pool") or {}
        return {"identity": APP_IDENTITY,
                "acquire_count": pool.get("acquire_count"),
                "wait_nanos_total": pool.get("wait_nanos_total"),
                "wait_nanos_max_lifetime": pool.get("wait_nanos_max"),
                "query_ms": round((time.monotonic() - t0) * 1000, 2)}
    except Exception as e:  # noqa: BLE001
        return {"identity": APP_IDENTITY,
                "error": f"{type(e).__name__}: {e}",
                "query_ms": round((time.monotonic() - t0) * 1000, 2)}


def read_diskstats():
    found = {}
    try:
        with open(f"{HOST_PROC}/diskstats", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 14 or parts[2] not in DISK_DEVS:
                    continue
                f = [int(x) for x in parts[3:14]]
                found[parts[2]] = {
                    "reads": f[0], "reads_merged": f[1], "sectors_read": f[2],
                    "ms_reading": f[3], "writes": f[4], "writes_merged": f[5],
                    "sectors_written": f[6], "ms_writing": f[7],
                    "ios_in_progress": f[8], "ms_doing_io": f[9],
                    "weighted_ms_doing_io": f[10],
                }
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}
    return {d: found.get(d) for d in DISK_DEVS}


def read_cpu():
    try:
        with open(f"{HOST_PROC}/stat", encoding="utf-8") as fh:
            parts = fh.readline().split()
        v = [int(x) for x in parts[1:9]]
        return {"user": v[0], "nice": v[1], "system": v[2], "idle": v[3],
                "iowait": v[4], "irq": v[5], "softirq": v[6], "steal": v[7]}
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}


def read_mem():
    keys = ("Dirty", "Writeback", "MemAvailable", "Buffers", "Cached")
    out = {}
    try:
        with open(f"{HOST_PROC}/meminfo", encoding="utf-8") as fh:
            for line in fh:
                m = re.match(r"^(\w+):\s+(\d+) kB", line)
                if m and m.group(1) in keys:
                    out[m.group(1).lower() + "_kb"] = int(m.group(2))
        return out
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}


def read_load():
    try:
        with open(f"{HOST_PROC}/loadavg", encoding="utf-8") as fh:
            p = fh.read().split()
        return {"load1": float(p[0]), "load5": float(p[1]),
                "load15": float(p[2]), "running": p[3]}
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}


def read_pressure():
    out = {}
    for kind in ("cpu", "io", "memory"):
        try:
            with open(f"{HOST_PROC}/pressure/{kind}", encoding="utf-8") as fh:
                out[kind] = fh.read().strip()
        except Exception:
            out[kind] = None
    return out


def read_cgroup():
    out = {}
    paths = {
        "cpu.cfs_quota_us": f"{HOST_SYS}/fs/cgroup/cpu/cpu.cfs_quota_us",
        "cpu.cfs_period_us": f"{HOST_SYS}/fs/cgroup/cpu/cpu.cfs_period_us",
        "cpu.stat": f"{HOST_SYS}/fs/cgroup/cpu/cpu.stat",
        "cpuset.cpus": f"{HOST_SYS}/fs/cgroup/cpuset/cpuset.cpus",
        "memory.limit_in_bytes": f"{HOST_SYS}/fs/cgroup/memory/memory.limit_in_bytes",
        "memory.usage_in_bytes": f"{HOST_SYS}/fs/cgroup/memory/memory.usage_in_bytes",
        "cpu.max": f"{HOST_SYS}/fs/cgroup/cpu.max",
        "cpu.stat.v2": f"{HOST_SYS}/fs/cgroup/cpu.stat",
        "memory.max": f"{HOST_SYS}/fs/cgroup/memory.max",
        "memory.current": f"{HOST_SYS}/fs/cgroup/memory.current",
    }
    for key, path in paths.items():
        try:
            with open(path, encoding="utf-8") as fh:
                out[key] = fh.read().strip()[:512]
        except Exception:
            pass
    return out


def self_stats():
    if resource is None:
        return {"cpu_s": None, "rss_kb": None}
    ru = resource.getrusage(resource.RUSAGE_SELF)
    return {"cpu_s": round(ru.ru_utime + ru.ru_stime, 3),
            "rss_kb": ru.ru_maxrss}


def main():
    if psycopg is None:
        sys.stderr.write("checkpoint_observer: psycopg is required\n")
        sys.exit(2)
    if not DB_URL or not OUT_PATH:
        sys.stderr.write(
            "checkpoint_observer: DB_URL and OUT_PATH are required\n")
        sys.exit(2)
    conn = psycopg.connect(DB_URL, autocommit=True,
                           options="-c statement_timeout=900")
    meta = {
        "type": "meta", "label": OBSERVER_LABEL,
        "started_utc": utc_iso(time.time()), "pid": os.getpid(),
        "hostname": os.uname().nodename if hasattr(os, "uname") else "?",
        "interval_s": INTERVAL_S, "disk_devs": DISK_DEVS,
        "app_identity": APP_IDENTITY,
    }
    seq = 0
    next_at = time.monotonic()
    last_ts = None
    with open(OUT_PATH, "w", encoding="utf-8", buffering=1) as out:
        out.write(json.dumps(meta, default=dec_default) + "\n")
        while True:
            now = time.monotonic()
            if now < next_at:
                time.sleep(next_at - now)
            ts = time.time()
            sched_late_ms = (time.monotonic() - next_at) * 1000
            pg = fetch_pg(conn)
            row = {
                "type": "sample", "seq": seq, "ts": round(ts, 3),
                "ts_utc": utc_iso(ts),
                "interval_ms": round((ts - last_ts) * 1000, 1) if last_ts else None,
                "sched_late_ms": round(sched_late_ms, 1),
                "pg": pg, "pool": fetch_pool(), "disk": read_diskstats(),
                "cpu": read_cpu(), "mem": read_mem(), "load": read_load(),
                "pressure": read_pressure(), "self": self_stats(),
            }
            out.write(json.dumps(row, default=dec_default) + "\n")
            last_ts = ts
            seq += 1
            next_at += INTERVAL_S
            if time.monotonic() - next_at > INTERVAL_S:
                # Fell behind: resync rather than burst-catch-up.
                next_at = time.monotonic() + INTERVAL_S


if __name__ == "__main__":
    main()
