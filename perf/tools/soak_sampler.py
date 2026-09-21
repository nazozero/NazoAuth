#!/usr/bin/env python3
"""In-network state sampler for soak runs.

Writes one JSONL META row (run_id, script sha256, start time) then one data
row per interval. Any dependency error is recorded as a *_err field — the
ledger_check.py `sampler` mode treats every *_err as a validation failure,
so a metrics 404 or a SQL error can never pass silently.

Env: RUN_ID (required), DB_URL, VK_URL, APP_METRICS, OUT_PATH, INTERVAL_S.
"""
import hashlib
import json
import os
import sys
import time
import urllib.request

import psycopg
import redis

DB = os.environ.get("DB_URL", "postgresql://postgres:postgres@postgres:5432/oauth")
VK = os.environ.get("VK_URL", "redis://valkey:6379/0")
APP = os.environ.get("APP_METRICS", "http://nazoauth:8000/__perf/metrics")
OUT = os.environ.get("OUT_PATH", "/perf-state/soak-metrics.jsonl")
INTERVAL = float(os.environ.get("INTERVAL_S", "10"))
RUN_ID = os.environ.get("RUN_ID", "unset")


def self_sha256():
    try:
        with open(__file__, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return "unavailable"


def main():
    out = open(OUT, "a", buffering=1)
    r = redis.Redis.from_url(VK, decode_responses=True)
    out.write(json.dumps({
        "kind": "meta", "run_id": RUN_ID, "script_sha256": self_sha256(),
        "db": DB.split("@")[-1], "app_metrics": APP,
        "started_at": int(time.time()),
    }) + "\n")
    while True:
        row = {"ts": int(time.time())}
        try:
            with psycopg.connect(DB) as c:
                row["pg"] = dict(zip(
                    ["backends", "active", "idle_in_tx"],
                    c.execute(
                        "SELECT count(*),"
                        "count(*) FILTER(WHERE state=%s),"
                        "count(*) FILTER(WHERE state=%s) "
                        "FROM pg_stat_activity",
                        ("active", "idle in transaction")).fetchone()))
                row["xact"] = dict(zip(
                    ["oldest_xact_age_s", "xmin_lag_xids",
                     "xacts_over_60s", "xacts_over_300s"],
                    c.execute(
                        "SELECT COALESCE(max(extract(epoch FROM now()"
                        "-xact_start))::bigint,-1),"
                        "COALESCE(max(age(backend_xmin)),-1),"
                        "count(*) FILTER(WHERE xact_start<now()"
                        "-interval '60 seconds'),"
                        "count(*) FILTER(WHERE xact_start<now()"
                        "-interval '300 seconds') "
                        "FROM pg_stat_activity WHERE xact_start IS NOT NULL"
                        " AND pid<>pg_backend_pid()").fetchone()))
                row["pg_db"] = dict(zip(
                    ["xact_commit", "xact_rollback", "blks_read", "blks_hit",
                     "tup_ret", "tup_ins", "tup_upd", "tup_del",
                     "deadlocks", "temp_bytes"],
                    c.execute(
                        "SELECT xact_commit,xact_rollback,blks_read,blks_hit,"
                        "tup_returned,tup_inserted,tup_updated,tup_deleted,"
                        "deadlocks,temp_bytes "
                        "FROM pg_stat_database WHERE datname=%s",
                        ("oauth",)).fetchone()))
        except Exception as e:
            row["pg_err"] = str(e)[:120]
        try:
            i = r.info("stats")
            m = r.info("memory")
            cl = r.info("clients")
            ks = r.info("keyspace")
            row["vk"] = {
                "cmd": i.get("total_commands_processed"),
                "hits": i.get("keyspace_hits"),
                "miss": i.get("keyspace_misses"),
                "exp": i.get("expired_keys"),
                "mem": m.get("used_memory"),
                "clients": cl.get("connected_clients"),
                "keys": (ks.get("db0") or {}).get("keys", 0),
            }
        except Exception as e:
            row["vk_err"] = str(e)[:120]
        try:
            req = urllib.request.Request(APP, headers={"Host": "127.0.0.1"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"metrics status {resp.status}")
                pm = json.load(resp)
            p = pm["db_pool"]
            row["pool"] = {
                "acq": p["acquire_count"],
                "wait_ns": p["wait_nanos_total"],
                "wait_max_ns": p["wait_nanos_max"],
            }
        except Exception as e:
            row["app_err"] = str(e)[:120]
        out.write(json.dumps(row) + "\n")
        time.sleep(INTERVAL)


if __name__ == "__main__":
    sys.exit(main())
