#!/usr/bin/env python3
"""Ledger/sampler output validator + pre/post differ + selftest.

Ledger row shapes (psql -a -t, pipe-separated, no headers):
  KV :  SECTION | kind | key | value
  REL :  RELATION_BYTES | relid | relation | heap_main | heap_aux |
         user_indexes_total | toast_total | total | live_est | dead_est |
         ins | upd | hot_upd | del | vac | autovac | component_check
  IDX :  INDEX_DETAIL | index_oid | relation | index_name | bytes |
         idx_scan | index_def
  ROW :  ROW_COUNTS | table | count
  BKL :  EXPIRED_BACKLOG | name | count | oldest
  DONE:  DONE | complete | ts

Usage:
  ledger_check.py check <file> --run-id RUN [--require-relation REL ...]
  ledger_check.py diff  <pre> <post>
  ledger_check.py sampler <file.jsonl> --run-id RUN
  ledger_check.py selftest
"""
import json
import re
import sys

REQUIRED_SECTIONS = [
    "META", "RELATION_BYTES", "INDEX_DETAIL", "ROW_COUNTS",
    "EXPIRED_BACKLOG", "AUDIT", "WAL", "BGWRITER", "CHECKPOINTER",
    "IO", "DB_TOTAL", "ACTIVITY", "TOP_STATEMENTS", "DONE",
]
BASE_RELATIONS = [
    "public.oauth_tokens",
    "public.oauth_token_issuances",
    "public.security_audit_events",
    "public.security_audit_event_outbox",
    "public.security_audit_chain_entries",
]
REL_COLS = ["relid", "relation", "heap_main", "heap_aux", "user_indexes_total",
            "toast_total", "total", "live_est", "dead_est", "ins", "upd",
            "hot_upd", "del", "vac", "autovac", "component_check"]
IDX_COLS = ["index_oid", "relation", "index_name", "index_bytes",
            "idx_scan", "index_def"]
REL_COUNTERS = {"ins", "upd", "hot_upd", "del", "vac", "autovac"}
IDX_COUNTERS = {"idx_scan"}
# KV keys treated as monotonic counters in diff mode.
COUNTER_KEYS = {
    "wal_records", "wal_fpi", "wal_bytes", "wal_buffers_full", "wal_write",
    "wal_sync", "wal_write_time", "wal_sync_time",
    "archived_count", "failed_count",
    "buffers_clean", "maxwritten_clean", "buffers_alloc",
    "num_timed", "num_requested", "restartpoints_timed", "restartpoints_req",
    "restartpoints_done", "write_time", "sync_time", "buffers_written",
    "checkpoints_timed", "checkpoints_req", "checkpoint_write_time",
    "checkpoint_sync_time", "buffers_checkpoint",
    "temp_bytes", "temp_files", "xact_commit", "xact_rollback",
    "tup_returned", "tup_fetched", "tup_inserted", "tup_updated",
    "tup_deleted", "deadlocks", "blk_read_time", "blk_write_time",
    "calls", "rows", "total_exec_time", "shared_blks_read",
    "shared_blks_written", "temp_blks_read", "temp_blks_written",
    "reads", "read_time", "writes", "write_time", "writebacks",
    "writeback_time", "extends", "extend_time", "hits", "evictions",
    "reuses", "fsyncs", "fsync_time",
}
ERR_RE = re.compile(
    r"(ERROR|FATAL|psql:.*error|does not exist|ON_ERROR_STOP)", re.I)


def _num(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        try:
            return float(v)
        except (TypeError, ValueError):
            return None


def parse_ledger(path, failures):
    """Return {section: [rowdict,...]} from unaligned psql output."""
    secs = {}
    try:
        lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    except OSError as e:
        failures.append(f"cannot read {path}: {e}")
        return secs
    if not lines:
        failures.append("empty file")
        return secs
    for ln in lines:
        if ERR_RE.search(ln):
            failures.append(f"SQL error line: {ln.strip()[:140]}")
            continue
        cols = [c.strip() for c in ln.split("|")]
        sec = cols[0]
        if sec == "META":
            secs.setdefault("META", []).append(
                {"key": cols[1] if len(cols) > 1 else "?",
                 "value": cols[2] if len(cols) > 2 else ""})
        elif sec == "RELATION_BYTES":
            if len(cols) - 1 != len(REL_COLS):
                failures.append(f"RELATION_BYTES malformed row ({len(cols)} cols)")
                continue
            secs.setdefault(sec, []).append(dict(zip(REL_COLS, cols[1:])))
        elif sec == "INDEX_DETAIL":
            if len(cols) - 1 != len(IDX_COLS):
                failures.append(f"INDEX_DETAIL malformed row ({len(cols)} cols)")
                continue
            secs.setdefault(sec, []).append(dict(zip(IDX_COLS, cols[1:])))
        elif sec == "ROW_COUNTS":
            secs.setdefault(sec, []).append({"t": cols[1], "v": cols[2]})
        elif sec == "EXPIRED_BACKLOG":
            secs.setdefault(sec, []).append(
                {"t": cols[1], "v": cols[2],
                 "oldest": cols[3] if len(cols) > 3 else "-"})
        elif sec == "PARTITION_ROLLUP":
            secs.setdefault(sec, []).append(
                {"relation": cols[1], "leaves": cols[2], "total": cols[3]})
        elif sec == "DONE":
            secs.setdefault(sec, []).append(
                {"status": cols[1] if len(cols) > 1 else "?",
                 "ts": cols[2] if len(cols) > 2 else "?"})
        elif sec in ("WAL", "BGWRITER", "CHECKPOINTER", "IO", "DB_TOTAL",
                     "ACTIVITY", "AUDIT", "TOP_STATEMENTS"):
            if len(cols) >= 4:
                secs.setdefault(sec, []).append(
                    {"kind": cols[1], "key": cols[2], "value": cols[3]})
            elif len(cols) == 3:
                secs.setdefault(sec, []).append(
                    {"kind": cols[1], "key": "value", "value": cols[2]})
        else:
            failures.append(f"unknown section line: {ln.strip()[:120]}")
    return secs


def meta_of(secs):
    return {r["key"]: r["value"] for r in secs.get("META", [])}


def check(path, run_id, require_rel):
    failures = []
    secs = parse_ledger(path, failures)
    for s in REQUIRED_SECTIONS:
        if s not in secs or not secs[s]:
            failures.append(f"missing/empty section: {s}")
    m = meta_of(secs)
    if run_id and m.get("run_id") != run_id:
        failures.append(f"run_id mismatch: expected {run_id} got {m.get('run_id')!r}")
    for k in ("sampled_at", "server_version_num", "schema_version", "phase"):
        if not m.get(k):
            failures.append(f"META missing {k}")
    for r in secs.get("RELATION_BYTES", []):
        cc, tot = _num(r.get("component_check")), _num(r.get("total"))
        if cc is None or tot is None or cc != tot:
            failures.append(
                f"byte components != total for {r.get('relation')}")
    for sec, rows in secs.items():
        for r in rows:
            if isinstance(r, dict) and r.get("kind") == "unavailable":
                failures.append(
                    f"{sec} unavailable: {r.get('value', r.get('key'))}")
    have_rel = {r.get("relation") for r in secs.get("RELATION_BYTES", [])}
    for rel in set(BASE_RELATIONS) | set(require_rel):
        if rel not in have_rel:
            failures.append(f"required relation missing: {rel}")
    done = secs.get("DONE", [])
    if not done or done[0].get("status") != "complete":
        failures.append("no DONE/complete marker")
    if failures:
        print(f"check {path}: FAIL ({len(failures)} problems)")
        for f in failures:
            print("  -", f)
        return 2
    print(f"check {path}: PASS")
    return 0


def _kv(rows):
    return {(r["kind"], r["key"]): r["value"] for r in rows}


def diff(pre_path, post_path):
    failures = []
    pre = parse_ledger(pre_path, failures)
    post = parse_ledger(post_path, failures)
    if failures:
        for f in failures:
            print("  -", f)
        return 2
    problems = []

    def emit(sec, rid, col, a, b, verdict):
        print(f"{sec:<16} {rid[:44]:<44} {col:<22} {a}→{b}  {verdict}")

    # --- KV sections -------------------------------------------------------
    for sec in ("WAL", "BGWRITER", "CHECKPOINTER", "IO", "DB_TOTAL",
                "AUDIT", "ACTIVITY"):
        pk, qk = _kv(pre.get(sec, [])), _kv(post.get(sec, []))
        reset_changed = (
            pk.get((next(iter(pk), ("",))[0], "stats_reset"), None)
            != qk.get((next(iter(qk), ("",))[0], "stats_reset"), None)
        ) and ("stats_reset" in {k for _, k in qk})
        for (kind, key), nv in qk.items():
            if (kind, key) not in pk:
                continue
            a, b = _num(pk[(kind, key)]), _num(nv)
            if a is None or b is None or key == "stats_reset":
                continue
            d = b - a
            if key in COUNTER_KEYS:
                if reset_changed:
                    emit(sec, f"{kind}/{key}", "delta", a, b, "RESET→INVALID")
                    problems.append(f"{sec}/{kind}/{key}: stats_reset changed")
                elif d < 0:
                    emit(sec, f"{kind}/{key}", "delta", a, b, "NEGATIVE→INVALID")
                    problems.append(f"{sec}/{kind}/{key}: counter {a}→{b}")
                elif d:
                    emit(sec, f"{kind}/{key}", "delta", a, b, f"+{d}")
            elif d:
                emit(sec, f"{kind}/{key}", "delta", a, b, f"{d:+d} (gauge)")

    # --- RELATION_BYTES / INDEX_DETAIL --------------------------------------
    for sec, cols, counters in (
        ("RELATION_BYTES", REL_COLS, REL_COUNTERS),
        ("INDEX_DETAIL", IDX_COLS, IDX_COUNTERS),
    ):
        keycol = "relation" if sec == "RELATION_BYTES" else "index_name"
        pm = {r[keycol]: r for r in pre.get(sec, [])}
        for r in post.get(sec, []):
            p = pm.get(r[keycol])
            if p is None:
                continue
            for col in counters:
                a, b = _num(p.get(col)), _num(r.get(col))
                if a is None or b is None:
                    continue
                d = b - a
                if d < 0:
                    emit(sec, f"{r[keycol]}/{col}", "delta", a, b, "NEGATIVE→INVALID")
                    problems.append(f"{sec}/{r[keycol]}/{col}: {a}→{b}")
                elif d:
                    emit(sec, f"{r[keycol]}/{col}", "delta", a, b, f"+{d}")
            for col in set(cols) - counters - {"relid", "index_oid", "index_def",
                                               "relation", "index_name",
                                               "component_check"}:
                a, b = _num(p.get(col)), _num(r.get(col))
                if a is not None and b is not None and b - a:
                    emit(sec, f"{r[keycol]}/{col}", "delta", a, b,
                         f"{b - a:+d} (gauge)")

    if problems:
        print(f"diff: INVALID — {len(problems)} counter problem(s)")
        for p in problems[:30]:
            print("  -", p)
        return 2
    print("diff: PASS (no counter regressions)")
    return 0


def check_sampler(path, run_id):
    failures = []
    meta = None
    rows = 0
    try:
        for ln in open(path, encoding="utf-8", errors="replace"):
            s = ln.strip()
            if not s:
                continue
            try:
                rec = json.loads(s)
            except json.JSONDecodeError:
                failures.append(f"unparseable line: {s[:100]}")
                continue
            if rec.get("kind") == "meta":
                meta = rec
                continue
            rows += 1
            for k in ("pg_err", "vk_err", "app_err"):
                if rec.get(k):
                    failures.append(f"sampler row {k}: {rec[k][:100]}")
            for k in ("pg", "pg_db", "vk", "pool"):
                if k not in rec:
                    failures.append(f"sampler row missing {k}")
    except OSError as e:
        failures.append(f"cannot read {path}: {e}")
    if meta is None:
        failures.append("no META row")
    else:
        if run_id and meta.get("run_id") != run_id:
            failures.append(f"sampler run_id {meta.get('run_id')!r} != {run_id!r}")
        if not meta.get("script_sha256"):
            failures.append("sampler meta missing script_sha256")
    if rows == 0:
        failures.append("no data rows")
    if failures:
        print(f"sampler {path}: FAIL ({len(failures)})")
        for f in failures[:20]:
            print("  -", f)
        return 2
    print(f"sampler {path}: PASS ({rows} rows)")
    return 0


def selftest():
    import os
    import tempfile
    d = tempfile.mkdtemp(prefix="ledger-selftest-")
    ok = total = 0

    kv = lambda sec, kind, *pairs: "\n".join(
        f" {sec} | {kind} | {k} | {v}" for k, v in pairs)

    good_ledger = "\n".join([
        " META | run_id | RUN1",
        " META | phase | pre",
        " META | sampled_at | 2026-09-19",
        " META | server_version_num | 180000",
        " META | schema_version | 20260919000200",
        " RELATION_BYTES | 1 | public.oauth_tokens | 10 | 1 | 2 | 3 | 16 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 16",
        " RELATION_BYTES | 2 | public.oauth_token_issuances | 10 | 1 | 2 | 3 | 16 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 16",
        " RELATION_BYTES | 3 | public.security_audit_events | 10 | 1 | 2 | 3 | 16 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 16",
        " RELATION_BYTES | 4 | public.security_audit_event_outbox | 10 | 1 | 2 | 3 | 16 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 16",
        " RELATION_BYTES | 5 | public.security_audit_chain_entries | 10 | 1 | 2 | 3 | 16 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 16",
        " INDEX_DETAIL | 9 | public.x | x_idx | 8 | 0 | CREATE INDEX",
        " ROW_COUNTS | x | 1",
        " EXPIRED_BACKLOG | x | 0 | -",
        kv("AUDIT", "ledger", ("pending_export", 0), ("events", 1),
           ("chain_entries", 1), ("anchor_sequence", 1), ("chain_head", 1)),
        kv("WAL", "stats", ("wal_records", 1), ("wal_bytes", 10),
           ("stats_reset", "-")),
        kv("WAL", "position", ("lsn", "0/1"), ("sampled_at", "-")),
        kv("WAL", "waldir", ("files", 1), ("bytes", 10)),
        kv("WAL", "archiver", ("archived_count", 0), ("stats_reset", "-")),
        kv("WAL", "replication_slots", ("count", 0)),
        kv("BGWRITER", "bgwriter", ("buffers_clean", 0), ("stats_reset", "-")),
        kv("CHECKPOINTER", "checkpointer", ("num_timed", 0), ("stats_reset", "-")),
        kv("IO", "bgworker", ("reads", 0), ("writes", 0)),
        kv("DB_TOTAL", "db", ("db_bytes", 100), ("xact_commit", 5),
           ("stats_reset", "-")),
        kv("ACTIVITY", "backends", ("total", 1)),
        kv("TOP_STATEMENTS", "1", ("calls", 1), ("rows", 1),
           ("query_head", "q")),
        " DONE | complete | 2026-09-19",
        "",
    ])

    def run(name, content, expect_rc):
        nonlocal ok, total
        total += 1
        p = os.path.join(d, name)
        open(p, "w").write(content)
        rc = check(p, "RUN1", [])
        good = rc == expect_rc
        ok += good
        print(f"selftest {name}: rc={rc} expect={expect_rc} {'PASS' if good else 'FAIL'}")

    run("good.txt", good_ledger, 0)
    run("sqlerr.txt", good_ledger + "\npsql:ledger.sql:5: ERROR:  column \"x\" does not exist\n", 2)
    run("wrongrun.txt", good_ledger.replace("META | run_id | RUN1", "META | run_id | OTHER"), 2)
    run("nosection.txt", "\n".join(
        ln for ln in good_ledger.splitlines() if not ln.startswith(" WAL |")), 2)
    run("nodone.txt", good_ledger.replace(" DONE | complete | 2026-09-19\n", ""), 2)
    run("badrel.txt", good_ledger.replace("public.oauth_tokens", "public.renamed_thing"), 2)

    total += 1
    pre = os.path.join(d, "pre.txt")
    post = os.path.join(d, "post.txt")
    open(pre, "w").write(good_ledger)
    open(post, "w").write(good_ledger.replace(
        " DB_TOTAL | db | xact_commit | 5",
        " DB_TOTAL | db | xact_commit | 3"))
    rc = diff(pre, post)
    good = rc == 2
    ok += good
    print(f"selftest diff-negative: rc={rc} {'PASS' if good else 'FAIL'}")

    total += 1
    sp = os.path.join(d, "s.jsonl")
    open(sp, "w").write(
        '{"kind":"meta","run_id":"RUN1","script_sha256":"abc"}\n'
        '{"ts":2,"pg":{},"pg_db":{},"vk":{},"pool":{}}\n')
    rc = check_sampler(sp, "RUN1")
    good = rc == 0
    ok += good
    print(f"selftest sampler-good: rc={rc} {'PASS' if good else 'FAIL'}")

    total += 1
    open(sp, "w").write(
        '{"kind":"meta","run_id":"RUN1","script_sha256":"abc"}\n'
        '{"ts":2,"pg":{},"pg_db":{},"vk":{},"pool":{},"app_err":"HTTP Error 404: Not Found"}\n')
    rc = check_sampler(sp, "RUN1")
    good = rc == 2
    ok += good
    print(f"selftest sampler-404: rc={rc} {'PASS' if good else 'FAIL'}")

    print(f"selftest: {ok}/{total} detected correctly")
    return 0 if ok == total else 2


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 64
    cmd = sys.argv[1]
    args = sys.argv[2:]
    run_id = None
    req = []
    rest = []
    i = 0
    while i < len(args):
        if args[i] == "--run-id":
            run_id = args[i + 1]
            i += 2
        elif args[i] == "--require-relation":
            req.append(args[i + 1])
            i += 2
        else:
            rest.append(args[i])
            i += 1
    if cmd == "selftest":
        return selftest()
    if cmd == "check" and rest:
        return check(rest[0], run_id, req)
    if cmd == "diff" and len(rest) >= 2:
        return diff(rest[0], rest[1])
    if cmd == "sampler" and rest:
        return check_sampler(rest[0], run_id)
    print(__doc__)
    return 64


if __name__ == "__main__":
    sys.exit(main())
