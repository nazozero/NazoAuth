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
                # ---- refresh-state model counters (bounded tables: exact
                # counts; spent/issuance volume: pg_stat counters) -----------
                row["refresh"] = dict(zip(
                    ["families_total", "families_live", "families_revoked",
                     "families_compromised", "families_machine",
                     "max_active_per_scope", "spent_live_est",
                     "spent_ins_cum", "spent_del_cum", "spent_expired_backlog",
                     "contracts_total", "contracts_referenced",
                     "families_ins_cum", "families_del_cum",
                     "spent_max_per_family"],
                    c.execute(
                        "SELECT "
                        "(SELECT count(*) FROM oauth_refresh_families),"
                        "(SELECT count(*) FROM oauth_refresh_families WHERE "
                        " revoked_at IS NULL AND reuse_detected_at IS NULL"
                        " AND current_expires_at > now()),"
                        "(SELECT count(*) FROM oauth_refresh_families WHERE "
                        " revoked_at IS NOT NULL),"
                        "(SELECT count(*) FROM oauth_refresh_families WHERE "
                        " reuse_detected_at IS NOT NULL),"
                        "(SELECT count(*) FROM oauth_refresh_families WHERE "
                        " user_id IS NULL),"
                        "(SELECT COALESCE(max(cnt),0) FROM (SELECT count(*) cnt"
                        "  FROM oauth_refresh_families WHERE user_id IS NOT NULL"
                        "  AND revoked_at IS NULL AND reuse_detected_at IS NULL"
                        "  AND current_expires_at > now()"
                        "  GROUP BY tenant_id,user_id,client_id) s),"
                        "(SELECT n_live_tup FROM pg_stat_user_tables WHERE "
                        " relname='oauth_refresh_spent_tokens'),"
                        "(SELECT n_tup_ins FROM pg_stat_user_tables WHERE "
                        " relname='oauth_refresh_spent_tokens'),"
                        "(SELECT n_tup_del FROM pg_stat_user_tables WHERE "
                        " relname='oauth_refresh_spent_tokens'),"
                        "(SELECT count(*) FROM oauth_refresh_spent_tokens WHERE "
                        " expires_at <= now()),"
                        "(SELECT count(*) FROM oauth_refresh_contracts),"
                        "(SELECT count(*) FROM oauth_refresh_contracts c WHERE "
                        " EXISTS (SELECT 1 FROM oauth_refresh_families f WHERE "
                        "  f.tenant_id=c.tenant_id AND "
                        "  f.contract_blake3=c.contract_blake3)),"
                        "(SELECT n_tup_ins FROM pg_stat_user_tables WHERE "
                        " relname='oauth_refresh_families'),"
                        "(SELECT n_tup_del FROM pg_stat_user_tables WHERE "
                        " relname='oauth_refresh_families'),"
                        "(SELECT COALESCE(max(cnt),0) FROM (SELECT count(*) cnt"
                        "  FROM oauth_refresh_spent_tokens"
                        "  GROUP BY tenant_id,token_family_id) s)"
                    ).fetchone()))
                # ---- storage: db total + per-relation bytes ----------------
                row["db_bytes"] = c.execute(
                    "SELECT pg_database_size(current_database())").fetchone()[0]
                row["wal_bytes"] = c.execute(
                    "SELECT wal_bytes::bigint FROM pg_stat_wal").fetchone()[0]
                # PG18 WAL flush accounting lives in pg_stat_io (the old
                # pg_stat_wal.wal_sync time fields are gone). Summed across
                # backend_type/context for the same-window delta series;
                # full dimensions stay in the wal_snapshot evidence.
                row["wal_io"] = dict(zip(
                    ["writes", "write_bytes", "write_time_ms", "fsyncs",
                     "fsync_time_ms"],
                    c.execute(
                        "SELECT COALESCE(sum(writes),0)::bigint,"
                        " COALESCE(sum(write_bytes),0)::bigint,"
                        " COALESCE(sum(write_time),0)::float8,"
                        " COALESCE(sum(fsyncs),0)::bigint,"
                        " COALESCE(sum(fsync_time),0)::float8"
                        " FROM pg_stat_io WHERE object='wal'").fetchone()))
                try:
                    # PG18: cumulative checkpointer counters — per-60s
                    # deltas of write/sync time and buffers_written
                    # correlate load cliffs with checkpoint activity
                    # without resetting any stats.
                    row["checkpoints"] = dict(zip(
                        ["timed", "requested", "done",
                         "write_time_ms", "sync_time_ms",
                         "buffers_written"],
                        c.execute(
                            "SELECT num_timed, num_requested, num_done,"
                            " write_time, sync_time, buffers_written "
                            "FROM pg_stat_checkpointer").fetchone()))
                except Exception:
                    try:
                        row["checkpoints"] = dict(zip(
                            ["timed", "requested"],
                            c.execute(
                                "SELECT num_timed, num_requested "
                                "FROM pg_stat_checkpointer").fetchone()))
                    except Exception:
                        row["checkpoints"] = dict(zip(
                            ["timed", "requested"],
                            c.execute(
                                "SELECT checkpoints_timed, checkpoints_req"
                                " FROM pg_stat_bgwriter").fetchone()))
                row["rel_bytes"] = {
                    r[0]: {"total": r[1], "heap": r[2], "idx": r[3],
                           "toast": r[4], "ins": r[5], "upd": r[6],
                           "del": r[7], "dead": r[8], "autovac": r[9]}
                    for r in c.execute(
                        "SELECT c.relname, pg_total_relation_size(c.oid),"
                        " pg_relation_size(c.oid,'main'),"
                        " pg_indexes_size(c.oid),"
                        " CASE WHEN c.reltoastrelid<>0 THEN"
                        "   pg_total_relation_size(c.reltoastrelid) ELSE 0 END,"
                        " COALESCE(st.n_tup_ins,0),COALESCE(st.n_tup_upd,0),"
                        " COALESCE(st.n_tup_del,0),COALESCE(st.n_dead_tup,0),"
                        " COALESCE(st.autovacuum_count,0)"
                        " FROM pg_class c"
                        " LEFT JOIN pg_stat_user_tables st ON st.relid=c.oid"
                        " WHERE c.relnamespace='public'::regnamespace"
                        "  AND c.relname IN ("
                        "   'oauth_refresh_families','oauth_refresh_spent_tokens',"
                        "   'oauth_refresh_contracts','oauth_token_issuances',"
                        "   'access_token_revocations','security_audit_events',"
                        "   'security_audit_event_outbox',"
                        "   'security_audit_chain_entries')"
                    ).fetchall()}
                row["audit"] = dict(zip(
                    ["pending", "chain_head", "anchor"],
                    c.execute(
                        "SELECT (SELECT count(*) FROM "
                        " security_audit_event_outbox),"
                        " last_sequence, anchor_sequence "
                        "FROM security_audit_chain_state").fetchone()))
                # PG wait-event distribution by type: distinguishes
                # connection-hold vs in-server wait when pool wait is high.
                row["pg_waits"] = {
                    r[0]: r[1] for r in c.execute(
                        "SELECT wait_event_type, count(*) "
                        "FROM pg_stat_activity "
                        "WHERE wait_event IS NOT NULL "
                        "GROUP BY wait_event_type").fetchall()}
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
                "waiting": p.get("waiting_acquisitions"),
                "size": p.get("connections"),
                "idle": p.get("idle_connections"),
            }
            if "audit_queue" in pm:
                row["audit_queue"] = pm["audit_queue"]
        except Exception as e:
            row["app_err"] = str(e)[:120]
        out.write(json.dumps(row) + "\n")
        time.sleep(INTERVAL)


if __name__ == "__main__":
    sys.exit(main())
