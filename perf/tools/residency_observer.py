#!/usr/bin/env python3
"""High-frequency business-pool residency observer.

Attribution-only diagnostic: samples the app `/__perf/metrics` pool
snapshot and per-backend `pg_stat_activity` rows scoped to the *business
runtime role* on the oauth database, at ~250ms. Every row carries a
unified `ts` plus `t_pre`/`t_post` so the observer's own collection span
is measurable.

Writes JSONL:
  * one `meta` row (script sha256, interval, runtime role, db target)
  * `sample` rows at each tick
  * `pgss` rows every PGSS_EVERY ticks (queryid -> normalized query text
    + calls/exec_time identity map, for offline classification)
  * `lockblock` rows are folded into samples: when a runtime-role backend
    reports wait_event_type='Lock' a minimal pg_blocking_pids probe runs
    for that pid only — never a full lock-table scan.

No payloads, tokens, secrets or bind values are read. The observer uses
its own direct connection (not the business pool); its backend is
excluded from statistics by the usename filter.

Env: RUN_ID (required), DB_URL, APP_METRICS, OUT_PATH, INTERVAL_S,
     RUNTIME_ROLE, PGSS_EVERY.
"""
import hashlib
import json
import os
import resource
import sys
import time
import urllib.request

import psycopg

DB = os.environ.get("DB_URL",
                    "postgresql://postgres:postgres@postgres:5432/oauth")
APP = os.environ.get("APP_METRICS", "http://nazoauth:8000/__perf/metrics")
OUT = os.environ.get("OUT_PATH", "/out/residency.jsonl")
INTERVAL = float(os.environ.get("INTERVAL_S", "0.25"))
PGSS_EVERY = int(os.environ.get("PGSS_EVERY", "40"))
RUN_ID = os.environ.get("RUN_ID", "unset")
RUNTIME_ROLE = os.environ.get("RUNTIME_ROLE", "")

ACTIVITY_SQL = """
SELECT pid, application_name, client_addr::text, state,
       wait_event_type, wait_event, query_id,
       extract(epoch from xact_start)::float8,
       extract(epoch from query_start)::float8,
       extract(epoch from state_change)::float8,
       extract(epoch from backend_start)::float8,
       backend_xid::text, age(backend_xmin)
FROM pg_stat_activity
WHERE datname = 'oauth' AND usename = %s AND backend_type = 'client backend'
ORDER BY pid
"""

BLOCKING_SQL = """
SELECT pg_blocking_pids(%s) AS blockers
"""

BLOCKER_QID_SQL = """
SELECT pid, query_id, state, wait_event_type, wait_event
FROM pg_stat_activity WHERE pid = ANY(%s)
"""

PGSS_SQL = """
SELECT s.dbid, r.rolname, s.toplevel, s.queryid, s.calls,
       s.total_exec_time, left(s.query, 200)
FROM pg_stat_statements s
JOIN pg_roles r ON r.oid = s.userid
JOIN pg_database d ON d.oid = s.dbid
WHERE d.datname = 'oauth'
ORDER BY s.calls DESC LIMIT 400
"""

ROLE_CHECK_SQL = """
SELECT usename, count(*) FROM pg_stat_activity
WHERE datname = 'oauth' AND backend_type = 'client backend'
GROUP BY usename ORDER BY 2 DESC
"""


def self_sha256() -> str:
    try:
        with open(__file__, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return "unavailable"


def _self_rusage() -> dict:
    ru = resource.getrusage(resource.RUSAGE_SELF)
    return {"utime_s": round(ru.ru_utime, 4), "stime_s": round(ru.ru_stime, 4)}


def main() -> int:
    if not RUNTIME_ROLE:
        print("RUNTIME_ROLE is required", file=sys.stderr)
        return 2
    out = open(OUT, "a", buffering=1)

    def connect():
        return psycopg.connect(DB, autocommit=True,
                               application_name="residency_observer",
                               connect_timeout=5)

    conn = None
    out.write(json.dumps({
        "kind": "meta", "run_id": RUN_ID, "script_sha256": self_sha256(),
        "interval_s": INTERVAL, "runtime_role": RUNTIME_ROLE,
        "db": DB.split("@")[-1], "app_metrics": APP,
        "started_at": time.time(),
    }) + "\n")

    def emit_role_check() -> None:
        # Live usename distribution on the oauth DB — the analyzer uses it
        # to prove the scoped role really is the business pool and that no
        # unidentifiable runtime-role sessions are mixed in. Emitted on the
        # first successful tick and then periodically with the pgss dump.
        if conn is None:
            return
        try:
            roles = conn.execute(ROLE_CHECK_SQL).fetchall()
            out.write(json.dumps({
                "kind": "role_check", "ts": time.time(),
                "roles": [[r[0], r[1]] for r in roles]}) + "\n")
        except Exception as e:  # noqa: BLE001 - recorded, not fatal
            out.write(json.dumps({
                "kind": "role_check", "ts": time.time(),
                "error": str(e)[:200]}) + "\n")

    tick = 0
    role_check_done = False
    while True:
        tick += 1
        t_pre = time.time()
        row = {"kind": "sample", "ts": t_pre, "t_pre": t_pre}
        # ---- app pool snapshot ------------------------------------------
        try:
            req = urllib.request.Request(APP, headers={"Host": "127.0.0.1"})
            with urllib.request.urlopen(req, timeout=2) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"metrics status {resp.status}")
                pm = json.load(resp)
            p = pm.get("db_pool") or {}
            row["pool"] = {
                "con": p.get("connections"),
                "idle": p.get("idle_connections"),
                "waiting": p.get("waiting_acquisitions"),
                "acq": p.get("acquire_count"),
                "wait_ns": p.get("wait_nanos_total"),
                "wait_max_ns": p.get("wait_nanos_max"),
            }
            aq = pm.get("audit_queue")
            if isinstance(aq, dict):
                row["audit_queue"] = {
                    k: aq.get(k) for k in
                    ("enqueued", "persisted", "dropped", "dropped_required",
                     "pending_in_process", "persist_max_batch")
                }
        except Exception as e:  # noqa: BLE001 - per-sample error field
            row["app_err"] = str(e)[:160]
        # ---- runtime-role backends --------------------------------------
        if conn is None:
            try:
                conn = connect()
            except Exception as e:  # noqa: BLE001 - stack may still be down
                row["pg_err"] = f"connect: {e}"[:160]
        if conn is not None and "pg_err" not in row:
            try:
                backends = []
                for r in conn.execute(ACTIVITY_SQL,
                                      (RUNTIME_ROLE,)).fetchall():
                    backends.append({
                        "pid": r[0], "app": r[1], "caddr": r[2],
                        "state": r[3], "wet": r[4], "we": r[5],
                        "qid": r[6], "xs": r[7], "qs": r[8], "sc": r[9],
                        "bs": r[10], "xid": r[11], "xmin_age": r[12],
                    })
                row["backends"] = backends
                # Minimal blocking probe only for Lock-waiting backends.
                lock_pids = [b["pid"] for b in backends
                             if b["wet"] == "Lock"]
                if lock_pids:
                    blocks = {}
                    for pid in lock_pids:
                        try:
                            bl = conn.execute(
                                BLOCKING_SQL, (pid,)).fetchone()
                            blockers = (bl[0] if bl else None) or []
                            info = conn.execute(
                                BLOCKER_QID_SQL, (blockers,)).fetchall()
                            blocks[str(pid)] = [
                                {"pid": x[0], "qid": x[1], "state": x[2],
                                 "wet": x[3], "we": x[4]} for x in info]
                        except Exception as e:  # noqa: BLE001
                            blocks[str(pid)] = {"error": str(e)[:120]}
                    row["lock_blocks"] = blocks
            except Exception as e:  # noqa: BLE001
                row["pg_err"] = str(e)[:160]
                try:
                    conn.close()
                except Exception:  # noqa: BLE001
                    pass
                conn = None  # next tick reconnects
        if "backends" in row and not role_check_done:
            emit_role_check()
            role_check_done = True
        # ---- pgss identity map -------------------------------------------
        if conn is not None and tick % PGSS_EVERY == 0:
            try:
                rows = conn.execute(PGSS_SQL).fetchall()
                out.write(json.dumps({
                    "kind": "pgss", "ts": time.time(), "run_id": RUN_ID,
                    "rows": [list(r) for r in rows]}) + "\n")
                emit_role_check()
            except Exception as e:  # noqa: BLE001
                out.write(json.dumps({
                    "kind": "pgss", "ts": time.time(), "run_id": RUN_ID,
                    "error": str(e)[:160]}) + "\n")
        t_post = time.time()
        row["t_post"] = t_post
        row["span_ms"] = round((t_post - t_pre) * 1000, 3)
        row["self"] = _self_rusage()
        out.write(json.dumps(row) + "\n")
        delay = INTERVAL - (time.time() - t_pre)
        if delay > 0:
            time.sleep(delay)


if __name__ == "__main__":
    sys.exit(main())
