#!/usr/bin/env python3
"""Offline re-analysis of the single-instance scaling raw artifacts.

Reads the *unmodified* raw run directories (point.json, soak-metrics.jsonl,
proc-detail.jsonl, pgss-{pre,post}.json, load/*.summary.json) and produces
window-consistent derived metrics plus evidence-limit annotations.

This script never modifies its inputs. Every output row records the sha256
of each input file it consumed.

Corrections performed vs the original point metrics:
  * WAL/success: the original wal_per_success divided the seed+load+drain
    pg_stat_wal delta by the 105 s measure-cohort success count — a mixed
    window. Here the WAL delta is interpolated from the sampler's
    wal_bytes series at the exact k6 measurement-window edges and divided
    by the same-window success count.
  * acquire/op: the pool acquire counter is app-lifetime; dividing it by
    the post-warmup cohort (2172564/475667 = 4.567 for X8) mixes windows.
    Two honest values are emitted instead: the full-run ratio
    (2172564/542120 = 4.008, background-inclusive) and, where the sampler
    covers the window, the same-window delta ratio (still background-
    inclusive inside the window).
  * pg_stat_statements: old snapshots lack dbid/userid/toplevel and A1's
    stats_reset changed between pre and post — deltas are refused and
    the rows are demoted to since-reset observations.
  * CPU: recomputed from proc-detail jiffies inside the measurement
    window; thread names were not captured so tokio-worker vs blocking
    classification stays 'unknown'.

Usage: python3 reanalyze.py <raw_root> <out_dir>
"""
import hashlib
import json
import sys
from pathlib import Path

POINTS = [
    ("phase1", "X4"), ("phase1", "X8"), ("phase1", "X16"),
    ("phase2", "A1"), ("phase2", "A2"), ("phase2", "B1"), ("phase2", "B2"),
]


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def series_value(ev: dict, field: str):
    cur = ev
    for part in field.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def load_series(path: Path, field: str):
    out = []
    for line in path.read_text(errors="replace").splitlines():
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        val = series_value(ev, field)
        ts = ev.get("ts")
        if isinstance(val, (int, float)) and isinstance(ts, (int, float)):
            out.append((float(ts), float(val)))
    out.sort()
    return out


def windowed_delta(series, t0: float, t1: float):
    """Interpolated counter delta inside [t0, t1]; None when the series
    does not cover an edge (bounded by ~one sampler tick)."""
    if len(series) < 2:
        return None, "insufficient samples"

    def interp(t):
        prev = None
        for ts, val in series:
            if ts <= t:
                prev = (ts, val)
                continue
            if prev is None:
                return val if ts <= t + 6 else None
            if ts == prev[0]:
                return val
            return prev[1] + (val - prev[1]) * (t - prev[0]) / (ts - prev[0])
        return None

    w0, w1 = interp(t0), interp(t1)
    if w0 is None or w1 is None:
        return None, f"window edge outside sampled span {series[0][0]}..{series[-1][0]}"
    return w1 - w0, None


def cpu_window(proc_path: Path, t0: float, t1: float):
    """Mean CPU cores per service inside the window from total jiffies;
    plus pid1 thread count and top threads by in-window jiffy growth."""
    rows = []
    clk = None
    for line in proc_path.read_text(errors="replace").splitlines():
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("kind") == "meta":
            clk = ev.get("clk_tck") or 100
            continue
        if isinstance(ev.get("ts"), (int, float)) and t0 <= ev["ts"] <= t1:
            rows.append(ev)
    if len(rows) < 2:
        return {"status": "insufficient in-window samples",
                "n_samples": len(rows)}
    clk = clk or 100
    span = rows[-1]["ts"] - rows[0]["ts"]
    out = {"window_s": round(span, 1), "n_samples": len(rows),
           "coverage": "partial" if span < (t1 - t0) * 0.8 else "good"}
    for svc in ("app", "postgres", "valkey"):
        a, b = rows[0].get(svc), rows[-1].get(svc)
        if not a or not b:
            out[svc] = {"cores": None, "reason": "service absent"}
            continue
        cores = (b["total_jif"] - a["total_jif"]) / clk / span
        entry = {"cores": round(cores, 3)}
        if svc == "app":
            n_thr = len(b.get("pid1_threads") or [])
            entry["pid1_thread_count"] = n_thr
            entry["thread_roles"] = (
                "unknown — tid names were not captured; cannot split "
                "tokio workers vs blocking threads vs tasks")
            ta = {t["tid"]: t["jif"] for t in (a.get("pid1_threads") or [])}
            top = sorted(
                ((t["tid"], t["jif"] - ta.get(t["tid"], 0))
                 for t in (b.get("pid1_threads") or [])),
                key=lambda x: -x[1])[:8]
            entry["top_threads_jif"] = [
                {"tid": t, "jif_delta": j} for t, j in top]
        out[svc] = entry
    return out


def analyze_point(raw: Path, phase: str, name: str) -> dict:
    d = raw / phase / name
    rec = {"point": name, "phase": phase, "inputs": {}}
    for rel in ("point.json", "soak-metrics.jsonl", "proc-detail.jsonl",
                "pgss-pre.json", "pgss-post.json"):
        p = d / rel
        rec["inputs"][rel] = {"sha256": sha256(p)} if p.exists() else None
    sums = sorted((d / "load").glob("*.summary.json"))
    if sums:
        rec["inputs"][f"load/{sums[0].name}"] = {"sha256": sha256(sums[0])}

    pt = json.loads((d / "point.json").read_text())
    m = pt.get("metrics", {})
    combined = json.loads(sums[0].read_text()) if sums else {}
    k6 = combined.get("k6", {}) or {}
    contract = (k6.get("measure") or {}).get("measurement_contract") or {}
    w0_ms, w1_ms = contract.get("window_start_ms"), contract.get("window_end_ms")
    rec["window"] = {"start_ms": w0_ms, "end_ms": w1_ms,
                     "seconds": contract.get("window_seconds")}
    success = ((k6.get("measure") or {}).get("outcomes") or {}).get("success")
    http = k6.get("http_reqs")
    rec["denominators"] = {"measure_cohort_success": success,
                           "full_run_http_reqs": http,
                           "iterations_completed":
                               k6.get("iterations_completed")}

    soak = d / "soak-metrics.jsonl"
    wal_s = load_series(soak, "wal_bytes")
    acq_s = load_series(soak, "pool.acq")
    t0, t1 = (w0_ms or 0) / 1000.0, (w1_ms or 0) / 1000.0

    wal_d, wal_err = (windowed_delta(wal_s, t0, t1)
                      if w0_ms and w1_ms else (None, "window missing"))
    rec["wal"] = {
        "original_wal_per_success_bytes": m.get("wal_per_success_bytes"),
        "original_numerator": "pg_stat_wal delta over seed+load+drain",
        "original_denominator": "measure-cohort success",
        "original_verdict": "NOT_COMPARABLE — mixed window/population",
        "windowed_delta_bytes": wal_d,
        "windowed_per_success_bytes": (
            round(wal_d / success, 1) if wal_d and success else None),
        "window_error": wal_err,
    }
    acq_d, acq_err = (windowed_delta(acq_s, t0, t1)
                      if w0_ms and w1_ms else (None, "window missing"))
    pool = combined.get("db_pool") or {}
    rec["acquire"] = {
        "lifetime_acquire_count": pool.get("acquire_count"),
        "full_run_per_http": (
            round(pool["acquire_count"] / http, 4)
            if pool.get("acquire_count") and http else None),
        "full_run_note": "app-lifetime counter / full-run HTTP; "
                         "background-inclusive",
        "windowed_delta": acq_d,
        "windowed_per_success": (
            round(acq_d / success, 4) if acq_d and success else None),
        "windowed_note": "same-window ratio still includes background "
                         "acquisitions; they cannot be separated out",
        "window_error": acq_err,
        "rejected_mixed_ratio": (
            round(pool["acquire_count"] / success, 4)
            if pool.get("acquire_count") and success else None),
    }

    pre = json.loads((d / "pgss-pre.json").read_text())
    post = json.loads((d / "pgss-post.json").read_text())
    pre_r, post_r = pre.get("stats_reset"), post.get("stats_reset")
    stmts = post.get("statements", [])
    has_identity = all(
        s.get("dbid") is not None and s.get("userid") is not None
        and s.get("toplevel") is not None and s.get("queryid") is not None
        for s in stmts) if stmts else False
    rec["pgss"] = {
        "pre_stats_reset": pre_r, "post_stats_reset": post_r,
        "delta_valid": bool(pre_r and pre_r == post_r and has_identity),
        "identity_fields_present": has_identity,
        "since_reset_calls_observed": sum(int(s.get("calls", 0))
                                          for s in stmts),
        "verdict": (
            "delta permitted" if (pre_r == post_r and has_identity)
            else "since-reset observation only — no pre/post subtraction "
                 "(reset epoch changed or identity fields absent)"),
    }
    rec["statements_per_req_observed"] = (
        (combined.get("postgres") or {}).get("statements_per_http_request"))
    rec["statements_per_req_semantics"] = (
        "sum of pg_stat_statements calls since scenario reset over all "
        "roles/levels divided by full-run HTTP; it is NOT a count of "
        "serial network round trips per business op")

    if w0_ms and w1_ms and (d / "proc-detail.jsonl").exists():
        rec["cpu"] = cpu_window(d / "proc-detail.jsonl", t0, t1)
        rec["cpu"]["reproducible"] = True
    else:
        rec["cpu"] = {"reproducible": False,
                      "reason": "no window or proc-detail missing"}

    ad = pt.get("audit_drain") or {}
    rec["audit_evidence"] = {
        "db_pending": ad.get("pending"),
        "db_last_sequence": ad.get("last_sequence"),
        "db_anchor_sequence": ad.get("anchor_sequence"),
        "db_drained": ad.get("drained"),
        "receiver_reconciliation": "missing — receiver container logs "
                                   "were not preserved; no end-to-end "
                                   "required-delivery claim is made",
    }
    return rec


def main() -> int:
    raw, out = Path(sys.argv[1]), Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    points = [analyze_point(raw, ph, n) for ph, n in POINTS
              if (raw / ph / n / "point.json").exists()]
    result = {
        "generated_by": "offline-review/reanalyze.py",
        "raw_root": str(raw),
        "raw_modified": False,
        "points": points,
    }
    (out / "corrected-metrics.json").write_text(
        json.dumps(result, indent=2) + "\n")
    print(f"analyzed {len(points)} points -> {out/'corrected-metrics.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
