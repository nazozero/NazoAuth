#!/usr/bin/env python3
"""Offline attribution analysis for residency_observer.py output.

Reads a residency JSONL plus the point.json of the same point (for the
k6 measurement window and op counters) and produces the accounting the
task requires:

  * valid-sample ratio and invalid-reason breakdown — HTTP and PG are
    two non-atomic snapshots, so the checked_out/idle estimate is only
    computed where the identity accounting holds;
  * checked_out = connections - idle_connections, runtime-role state
    split (active / idle-in-transaction / pg-idle-estimate), each with
    mean/median/p95/max and share of valid samples;
  * idle-in-transaction residency: per-backend idle_age = ts -
    state_change, fixed buckets, time-weighted share, top query_ids
    mapped through the same-window pg_stat_statements identity map;
  * active-backend wait distribution by (wait_event_type, wait_event)
    and by query class;
  * conditional stats for samples with waiting_acquisitions > 0;
  * Little's-law cross-check: implied mean checkout residency =
    mean(checked_out) / (delta acquire_count / window seconds).

Usage: residency_analyze.py <residency.jsonl> <point.json> [--json]
"""
from __future__ import annotations

import json
import statistics
import sys
from pathlib import Path

BUCKETS_MS = [1, 5, 20, 100, 500, 1000]
BUCKET_LABELS = ["<1ms", "1-5ms", "5-20ms", "20-100ms", "100-500ms",
                 "500ms-1s", ">=1s"]

# Normalized pgss query text -> coarse statement class. Order matters:
# first match wins. UNKNOWN stays UNKNOWN — never guess.
QUERY_CLASSES = [
    ("SET LOCAL", "set_local"),
    ("BEGIN", "begin_commit"),
    ("COMMIT", "begin_commit"),
    ("pg_try_advisory_lock", "advisory_lock"),
    ("pg_advisory_lock", "advisory_lock"),
    ("nazo_persist_security_audit_event", "audit_append"),
    ("nazo_security_audit", "audit_fn"),
    ("oauth_token_issuances", "issuance_insert"),
    ("oauth_clients", "client"),
    ("oauth_refresh_families", "refresh_family"),
    ("oauth_refresh_spent_tokens", "refresh_spent"),
    ("oauth_refresh_contracts", "refresh_contract"),
    ("security_audit_event_outbox", "audit_outbox"),
    ("security_audit_chain", "audit_chain"),
    ("security_audit_events", "audit_events"),
    ("access_token_revocations", "access_revocation"),
    ("tenant_runtime_directory_state", "directory_state"),
]


def classify_query(query: str) -> str:
    q = (query or "").lower()
    for needle, name in QUERY_CLASSES:
        if needle.lower() in q:
            return name
    return "other"


def _pct(sorted_vals, p: float):
    if not sorted_vals:
        return None
    idx = min(len(sorted_vals) - 1, int(round((p / 100.0) * len(sorted_vals))))
    return sorted_vals[max(0, idx - 1)] if p <= 50 else sorted_vals[idx]


def _stats(vals):
    vals = [v for v in vals if isinstance(v, (int, float))]
    if not vals:
        return None
    s = sorted(vals)
    return {
        "n": len(s),
        "mean": round(statistics.fmean(s), 4),
        "median": round(statistics.median(s), 4),
        "p95": _pct(s, 95),
        "max": s[-1],
    }


def _bucket(ms: float) -> str:
    for limit, label in zip(BUCKETS_MS, BUCKET_LABELS):
        if ms < limit:
            return label
    return BUCKET_LABELS[-1]


def load_rows(path: Path) -> dict:
    meta, samples, pgss_rows, role_checks = None, [], [], []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            kind = row.get("kind")
            if kind == "meta":
                meta = row
            elif kind == "role_check":
                role_checks.append(row)
            elif kind == "pgss":
                pgss_rows.append(row)
            elif kind == "sample":
                samples.append(row)
    return {"meta": meta, "role_checks": role_checks,
            "samples": samples, "pgss": pgss_rows}


def pgss_map(pgss_rows: list[dict]) -> dict:
    """queryid -> {rolname, toplevel, query, class} using the latest dump."""
    m: dict = {}
    for row in pgss_rows:
        for r in row.get("rows") or []:
            dbid, rolname, toplevel, qid, calls, total_t, q = r
            m[str(qid)] = {"rolname": rolname, "toplevel": toplevel,
                           "calls": calls, "total_exec_time": total_t,
                           "query": q, "class": classify_query(q)}
    return m


def analyze_point(residency_path: Path, point_path: Path) -> dict:
    data = load_rows(residency_path)
    point = json.loads(point_path.read_text())
    metrics = point.get("metrics") or {}
    w0 = (metrics.get("window_start_ms") or 0) / 1000.0
    w1 = (metrics.get("window_end_ms") or 0) / 1000.0
    samples = [s for s in data["samples"]
               if w0 <= s.get("ts", 0) <= w1] if w0 and w1 else data["samples"]

    qmap = pgss_map(data["pgss"])
    valid, invalid = [], []
    checked_out_l, active_l, itx_l, idle_l, other_l = [], [], [], [], []
    pgidle_l, waiting_l, con_l = [], [], []
    itx_rows = []           # (idle_age_ms, qid)
    active_wait = {}        # (wet, we) -> count
    active_class = {}       # class -> count
    lock_blocks = []
    wait_pos = {"n": 0, "checked_out": [], "active": [], "itx": [],
                "pgidle": [], "full": 0}

    for s in samples:
        pool = s.get("pool") or {}
        backends = s.get("backends")
        if (s.get("app_err") or s.get("pg_err") or backends is None
                or pool.get("con") is None or pool.get("idle") is None):
            invalid.append("missing_pool_or_pg")
            continue
        con, idle_n = pool["con"], pool["idle"]
        waiting = pool.get("waiting") or 0
        n_back = len(backends)
        if n_back > con:
            # More runtime-role client backends than pool connections:
            # non-pool runtime connections are mixed in and cannot be
            # separated by application_name (the pool sets none).
            invalid.append("extra_runtime_backends")
            continue
        states = {"active": 0, "idle in transaction": 0, "idle": 0}
        other = 0
        for b in backends:
            st = b.get("state")
            if st in states:
                states[st] += 1
            else:
                other += 1
        checked_out = con - idle_n
        pg_idle_est = checked_out - states["active"] - states["idle in transaction"]
        if pg_idle_est < 0:
            invalid.append("negative_idle_estimate")
            continue
        valid.append(s)
        checked_out_l.append(checked_out)
        active_l.append(states["active"])
        itx_l.append(states["idle in transaction"])
        idle_l.append(states["idle"])
        other_l.append(other)
        pgidle_l.append(pg_idle_est)
        waiting_l.append(waiting)
        con_l.append(con)
        ts = s["ts"]
        for b in backends:
            if b.get("state") == "idle in transaction" and b.get("sc"):
                itx_rows.append((max(0.0, (ts - b["sc"]) * 1000.0),
                                 b.get("qid")))
            elif b.get("state") == "active":
                wet = b.get("wet") or "no_wait"
                we = b.get("we") or "-"
                active_wait[(wet, we)] = active_wait.get((wet, we), 0) + 1
                qid = b.get("qid")
                cls = (qmap.get(str(qid)) or {}).get(
                    "class", "unknown" if qid is None else "unmapped")
                active_class[cls] = active_class.get(cls, 0) + 1
        if s.get("lock_blocks"):
            lock_blocks.append({"ts": ts, "blocks": s["lock_blocks"]})
        if waiting and waiting > 0:
            wait_pos["n"] += 1
            wait_pos["checked_out"].append(checked_out)
            wait_pos["active"].append(states["active"])
            wait_pos["itx"].append(states["idle in transaction"])
            wait_pos["pgidle"].append(pg_idle_est)
            if con and checked_out >= con - 1:
                wait_pos["full"] += 1

    # ---- idle-in-transaction residency ----------------------------------
    itx_hist = {label: 0 for label in BUCKET_LABELS}
    itx_time = {label: 0.0 for label in BUCKET_LABELS}
    itx_by_qid: dict[str, list[float]] = {}
    for age_ms, qid in itx_rows:
        label = _bucket(age_ms)
        itx_hist[label] += 1
        itx_time[label] += age_ms
        key = str(qid) if qid is not None else "UNKNOWN"
        itx_by_qid.setdefault(key, []).append(age_ms)
    total_itx_time = sum(itx_time.values()) or 1.0
    itx_by_class: dict[str, dict] = {}
    for qid, ages in itx_by_qid.items():
        cls = ("UNKNOWN" if qid == "UNKNOWN"
               else (qmap.get(qid) or {}).get("class", "unmapped"))
        entry = itx_by_class.setdefault(cls, {"count": 0, "ages": [],
                                              "qids": set()})
        entry["count"] += len(ages)
        entry["ages"].extend(ages)
        entry["qids"].add(qid)
    itx_classes = {
        cls: {"count": e["count"],
              "time_share": round(sum(e["ages"]) / total_itx_time, 4),
              "p50": _pct(sorted(e["ages"]), 50),
              "p95": _pct(sorted(e["ages"]), 95),
              "max": round(max(e["ages"]), 3),
              "queries": sorted(e["qids"]),
              "examples": sorted({
                  (qmap.get(q) or {}).get("query", "?")[:120]
                  for q in e["qids"] if q != "UNKNOWN"})}
        for cls, e in sorted(itx_by_class.items(),
                             key=lambda kv: -sum(kv[1]["ages"]))}

    # ---- Little's law ----------------------------------------------------
    # series order is chronological: first = earliest valid sample
    acq_series = [(s["ts"], s["pool"]["acq"]) for s in valid
                  if (s.get("pool") or {}).get("acq") is not None]
    littles = None
    if len(acq_series) >= 2:
        dt = acq_series[-1][0] - acq_series[0][0]
        dacq = acq_series[-1][1] - acq_series[0][1]
        if dt > 0 and dacq >= 0 and checked_out_l:
            rate = dacq / dt
            mean_co = statistics.fmean(checked_out_l)
            littles = {
                "acquire_rate_per_s": round(rate, 2),
                "mean_checked_out": round(mean_co, 3),
                "implied_residency_ms": (round(mean_co / rate * 1000.0, 3)
                                         if rate > 0 else None),
            }

    span_ms = [s.get("span_ms") for s in samples
               if isinstance(s.get("span_ms"), (int, float))]
    self_first = next((s.get("self") for s in samples if s.get("self")),
                      None)
    self_last = next((s.get("self") for s in reversed(samples)
                      if s.get("self")), None)
    observer = {
        "samples_in_window": len(samples),
        "sample_span_ms": _stats(span_ms),
        "self_cpu": (
            {"utime_delta_s": round(
                self_last["utime_s"] - self_first["utime_s"], 3),
             "stime_delta_s": round(
                 self_last["stime_s"] - self_first["stime_s"], 3)}
            if self_first and self_last else None),
        "errors": {
            "app_err": sum(1 for s in samples if s.get("app_err")),
            "pg_err": sum(1 for s in samples if s.get("pg_err")),
        },
    }

    cond = None
    if valid:
        cond = {
            "p_waiting_gt0": round(wait_pos["n"] / len(valid), 4),
            "p_checked_out_full_given_waiting": (
                round(wait_pos["full"] / wait_pos["n"], 4)
                if wait_pos["n"] else None),
            "active_given_waiting": _stats(wait_pos["active"]),
            "idle_in_tx_given_waiting": _stats(wait_pos["itx"]),
            "pg_idle_est_given_waiting": _stats(wait_pos["pgidle"]),
        }

    return {
        "run_id": point.get("run_id"),
        "scenario": (point.get("point") or {}).get("scenario"),
        "window_s": round(w1 - w0, 2) if w0 and w1 else None,
        "ops": {
            "successful_ops_per_s": metrics.get("successful_ops_per_s"),
            "outcome_success": metrics.get("outcome_success"),
            "op_p99_ms": metrics.get("op_p99_ms"),
            "unexpected": metrics.get("outcome_unexpected"),
        },
        "identity": {
            "runtime_role": (data.get("meta") or {}).get("runtime_role"),
            "observer_sha256": (data.get("meta") or {}).get(
                "script_sha256"),
            "interval_s": (data.get("meta") or {}).get("interval_s"),
            "role_checks_in_window": [
                rc for rc in data["role_checks"]
                if not (w0 and w1) or w0 <= rc.get("ts", 0) <= w1],
        },
        "validity": {
            "samples": len(samples),
            "valid": len(valid),
            "valid_ratio": (round(len(valid) / len(samples), 4)
                            if samples else None),
            "invalid_reasons": {r: invalid.count(r) for r in set(invalid)},
        },
        "pool": {
            "size": _stats(con_l),
            "checked_out": _stats(checked_out_l),
            "waiting_acquisitions": _stats(waiting_l),
        },
        "runtime_state": {
            "active": _stats(active_l),
            "idle_in_transaction": _stats(itx_l),
            "pg_idle": _stats(idle_l),
            "other": _stats(other_l),
            "checked_out_pg_idle_estimate": _stats(pgidle_l),
        },
        "shares_of_checked_out_mean": (
            {k: round(statistics.fmean(v) / statistics.fmean(checked_out_l), 4)
             for k, v in (("active", active_l),
                          ("idle_in_transaction", itx_l),
                          ("checked_out_pg_idle", pgidle_l))}
            if valid and statistics.fmean(checked_out_l) > 0 else None),
        "idle_in_tx": {
            "samples": len(itx_rows),
            "histogram_count": itx_hist,
            "time_weighted_share": {k: round(v / total_itx_time, 4)
                                    for k, v in itx_time.items()},
            "by_class": itx_classes,
        },
        "active_wait": {
            "by_wait_event": {f"{k[0]}:{k[1]}": v for k, v in sorted(
                active_wait.items(), key=lambda kv: -kv[1])},
            "by_query_class": dict(sorted(
                active_class.items(), key=lambda kv: -kv[1])),
        },
        "lock_blocks": lock_blocks[:50],
        "waiting_conditioned": cond,
        "littles_law": littles,
        "observer": observer,
    }


def main() -> int:
    residency = Path(sys.argv[1])
    point = Path(sys.argv[2])
    out = analyze_point(residency, point)
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
