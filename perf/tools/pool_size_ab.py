#!/usr/bin/env python3
"""Business-pool 24-vs-32 single-variable A/B (mixed only).

A = DATABASE_MAX_CONNECTIONS=24 (current benchmark pin, below the
production default). B = =32 (the production default). Applied per point
via a compose-override environment variable on the nazoauth container —
process env outranks the baked /app/.env.yaml; the image binary is
identical on both sides and verified per point by sha256.

No CC phase: pool=24 already sustains ~6k ops/s there; the question is
whether the mixed 3000/s capacity gap is an artefact of pinning the
benchmark pool below the normal default. Each point: cap_mixed
constant-arrival-rate 3000/s, 120s + 15s warmup, pre 256 / max 1024,
sidecars refresh=600 argon2=8 metadata=200 fapi=30, and the 250ms
runtime-role residency observer.

Verification beyond env strings, per point:
  * max db_pool.connections observed in /__perf/metrics samples
    (residency observer + soak sampler)
  * max runtime-role backend count in pg_stat_activity samples

Gates (pre-registered):
  * A1/A2 ops spread <= 5% else INCONCLUSIVE
  * per-point health (unexpected=0, queue_full=0, dropped=0,
    pending=0, enqueued==persisted, receiver/DB reconcile PASS,
    journal gap=0 dup=0, refresh invariants, sidecars complete,
    no OOM/restart)
  * each B ops >= 1.03 * max(A); mean(B)/mean(A) >= 1.04
  * B p99 not simultaneously >10% and >20ms worse than A ref
  * B drop_fraction - A <= 0.1pp
  * structural: mean waiting_acquisitions -30% OR wait/acquire -30%
  * WAL guardrail: B active WALWrite+WalSync sample share <= A + 10pp

Usage:
  SIS_PROJECT=sis32 SIS_LOAD_BUDGET_S=600 \
  SIS_APP_SHA=<sha> python3 perf/tools/pool_size_ab.py \
      --image tap-b:86b2df16 [--phase run|evaluate]
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
# Workspace binding (harness-repair): this driver runs from a task
# worktree and every file it mounts/executes must come from THAT
# checkout. SIS_WORKSPACE unset -> pin to this file's repo root; set but
# resolving elsewhere -> refuse rather than silently use a stale
# checkout. Must run before importing the shared harness (it resolves
# WORKSPACE/TOOLS/COMPOSE_FILE at import time).
_REPO_ROOT = Path(__file__).resolve().parents[2]
_env_ws = os.environ.get("SIS_WORKSPACE")
if _env_ws is None:
    os.environ["SIS_WORKSPACE"] = str(_REPO_ROOT)
elif os.path.realpath(_env_ws) != os.path.realpath(str(_REPO_ROOT)):
    raise SystemExit(
        "HARNESS_WORKSPACE_MISMATCH: SIS_WORKSPACE="
        f"{_env_ws} resolves outside this checkout {_REPO_ROOT}")

import point_runner as pr  # noqa: E402
import single_instance_scaling as sis  # noqa: E402
from point_runner import (  # noqa: E402
    _health_checks, _proc_cpu, _wal_wait_share, audit_queue_final,
    runtime_role_from_image)

PHASE_DIR = "pool24v32"

SIDECARS_120 = [
    {"name": "argon2", "scenario": "oidc_cold_login_refresh",
     "rate": 8, "duration": "120s", "pre_vus": 8, "max_vus": 16,
     "user_count": 64},
    {"name": "meta", "scenario": "metadata_jwks",
     "rate": 200, "duration": "120s", "pre_vus": 16, "max_vus": 32,
     "user_count": 64},
    {"name": "fapi", "scenario": "fapi2_logged_in_high_security",
     "rate": 30, "duration": "120s", "pre_vus": 32, "max_vus": 64,
     "user_count": 128},
    {"name": "refresh", "scenario": "cap_refresh_token",
     "rate": 600, "duration": "120s", "pre_vus": 64, "max_vus": 256,
     "user_count": 256},
]

# Formal strict-3000 gate (capacity_search.evaluate): measured rate
# >=99.5% of target, drop<=0.1%, unexpected==0, p95<=100ms, p99<=250ms.
STRICT_TARGET = 3000.0


def diagnose_pg() -> dict:
    """Postgres-only boot: confirm restored baseline GUCs and record
    max_connections headroom for 32 app backends + exporter + admin."""
    diag: dict = {"ok": False}
    sis.stack_down()
    try:
        sis.compose("up", "-d", "--no-build", "postgres")
        if not sis.wait_healthy(sis.POSTGRES):
            diag["error"] = "postgres not healthy for diagnostics"
            return diag
        gucs = {}
        for g in ("server_version", "max_connections", "fsync",
                  "synchronous_commit", "full_page_writes",
                  "wal_sync_method", "commit_delay", "commit_siblings",
                  "track_wal_io_timing", "shared_buffers",
                  "max_wal_size", "checkpoint_timeout",
                  "checkpoint_completion_target"):
            gucs[g] = sis.psql(f"SHOW {g}", check=False)
        diag["gucs"] = gucs
        expected = {"commit_delay": "0", "track_wal_io_timing": "off",
                    "fsync": "on", "synchronous_commit": "on",
                    "full_page_writes": "on", "commit_siblings": "5"}
        diag["baseline_mismatches"] = {
            g: (gucs.get(g), want) for g, want in expected.items()
            if gucs.get(g) != want}
        mc = gucs.get("max_connections") or "0"
        diag["max_connections"] = int(mc) if mc.isdigit() else None
        # 32 business + exporter(1) + observer(1) + migrations/admin slack
        diag["headroom_ok"] = (isinstance(diag["max_connections"], int)
                               and diag["max_connections"] >= 40)
        diag["version_ok"] = (gucs.get("server_version") or "") \
            .startswith("18.")
        diag["ok"] = (diag["version_ok"] and not diag[
            "baseline_mismatches"] and diag["headroom_ok"])
        if not diag["ok"]:
            diag["error"] = "baseline GUCs not in expected state"
        return diag
    finally:
        sis.stack_down()


def _pool_backend_observed(point_dir: Path, rec: dict) -> dict:
    """Max observed pool size and runtime-role backend count from the
    250ms residency stream — proof the env override took effect and that
    backends actually exist, not just an env string."""
    m = rec.get("metrics") or {}
    w0 = (m.get("window_start_ms") or 0) / 1000.0
    w1 = (m.get("window_end_ms") or 0) / 1000.0
    path = point_dir / "residency.jsonl"
    out = {"pool_size_max": None, "pool_waiting_max": None,
           "pool_checked_out_max": None, "runtime_backends_max": None,
           "state_means": {}, "window_samples": 0}
    state_sum: dict = {}
    n = 0
    if not path.exists():
        return out
    for line in path.read_text(errors="replace").splitlines():
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if r.get("kind") != "sample" or not (w0 <= r["ts"] <= w1):
            continue
        n += 1
        p = r.get("pool") or {}
        backends = r.get("backends") or []
        size = p.get("con")
        if isinstance(size, (int, float)):
            out["pool_size_max"] = max(out["pool_size_max"] or 0, size)
        waiting = p.get("waiting")
        if isinstance(waiting, (int, float)):
            out["pool_waiting_max"] = max(
                out["pool_waiting_max"] or 0, waiting)
        idle = p.get("idle")
        if isinstance(size, (int, float)) and isinstance(
                idle, (int, float)):
            out["pool_checked_out_max"] = max(
                out["pool_checked_out_max"] or 0, size - idle)
        out["runtime_backends_max"] = max(
            out["runtime_backends_max"] or 0, len(backends))
        for b in backends:
            st = b.get("state") or "?"
            state_sum[st] = state_sum.get(st, 0) + 1
    out["window_samples"] = n
    out["state_means"] = {k: round(v / n, 2)
                          for k, v in sorted(state_sum.items())} if n \
        else {}
    return out


def _residency_pool_means(point_dir: Path, rec: dict) -> dict:
    """Mean waiting_acquisitions + checked_out inside the window."""
    m = rec.get("metrics") or {}
    w0 = (m.get("window_start_ms") or 0) / 1000.0
    w1 = (m.get("window_end_ms") or 0) / 1000.0
    path = point_dir / "residency.jsonl"
    wait_s = co_s = n = 0.0
    if not path.exists():
        return {"waiting_mean": None, "checked_out_mean": None}
    for line in path.read_text(errors="replace").splitlines():
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if r.get("kind") != "sample" or not (w0 <= r["ts"] <= w1):
            continue
        p = r.get("pool") or {}
        if isinstance(p.get("waiting"), (int, float)):
            wait_s += p["waiting"]
        if isinstance(p.get("con"), (int, float)) and isinstance(
                p.get("idle"), (int, float)):
            co_s += p["con"] - p["idle"]
        n += 1
    return {"waiting_mean": round(wait_s / n, 1) if n else None,
            "checked_out_mean": round(co_s / n, 2) if n else None,
            "samples": n}


def point_evidence(rec: dict) -> dict:
    m = rec.get("metrics") or {}
    wal = rec.get("wal_delta") or {}
    classes = (rec.get("pgss_delta") or {}).get("path_classes") or {}
    commits = classes.get("commit_txn")
    fsyncs = wal.get("fsyncs_total")
    point_dir = sis.RESULTS / rec["point"]["phase"] / rec["run_id"]
    pool = _pool_backend_observed(point_dir, rec)
    means = _residency_pool_means(point_dir, rec)
    ops = m.get("successful_ops_per_s")
    attempted = m.get("ops_per_s")
    return {
        "configured_pool": (rec["point"].get("app_env_overrides") or {})
                           .get("DATABASE_MAX_CONNECTIONS"),
        "pool_size_observed": pool["pool_size_max"],
        "runtime_backends_max": pool["runtime_backends_max"],
        "checked_out_max": pool["pool_checked_out_max"],
        "checked_out_mean": means["checked_out_mean"],
        "waiting_mean": means["waiting_mean"],
        "waiting_max": pool["pool_waiting_max"],
        "backend_state_means": pool["state_means"],
        "ops_per_s": ops,
        "attempted_ops_per_s": attempted,
        "attainment": (round(attempted / STRICT_TARGET, 4)
                       if isinstance(attempted, (int, float)) else None),
        "p50_ms": m.get("op_p50_ms"), "p95_ms": m.get("op_p95_ms"),
        "p99_ms": m.get("op_p99_ms"),
        "iter_p95_ms": m.get("iter_p95_ms"),
        "iter_p99_ms": m.get("iter_p99_ms"),
        "drop_fraction": m.get("drop_fraction"),
        "measure_scheduled": m.get("measure_scheduled"),
        "measure_started": m.get("measure_started"),
        "measure_completed": m.get("measure_completed"),
        "measure_dropped": m.get("measure_dropped"),
        "measure_drop_fraction": m.get("measure_drop_fraction"),
        "full_run_drop_fraction": m.get("full_run_drop_fraction"),
        "cohort_valid": m.get("cohort_valid"),
        "outcome_success": m.get("outcome_success"),
        "outcome_unexpected": m.get("outcome_unexpected"),
        "acquire_per_op": m.get("acquire_per_op_windowed"),
        "wait_per_acq_ms": m.get("wait_per_acq_ms"),
        "commits_delta": commits,
        "wal_fsyncs_delta": fsyncs,
        "commits_per_fsync": (round(commits / fsyncs, 4)
                              if isinstance(commits, (int, float))
                              and fsyncs else None),
        "wal_bytes_per_s": m.get("wal_bytes_per_s"),
        "wal_writes_per_s": m.get("wal_writes_per_s"),
        "wal_fsyncs_per_s": m.get("wal_fsyncs_per_s"),
        "wal_wait": _wal_wait_share(point_dir, rec),
        "cpu_cores": _proc_cpu(point_dir, rec),
        "strict_3000_gate": _strict_gate(m, attempted),
        "app_binary_sha256": (rec.get("stack") or {})
                             .get("app_binary_sha256"),
    }


def _strict_gate(m: dict, attempted) -> dict:
    """Formal strict gate for cap_mixed, measurement cohort only:
    measured ops >=99.5% of target, MEASURE drops<=0.1%, measure
    unexpected==0, cap_iter_ms p95<=100ms p99<=250ms. Whole-run
    drop_fraction / http_req_duration are a different population and
    are never gate inputs."""
    mdrop = m.get("measure_drop_fraction")
    # Gate on the provable upper bound: a boundary overshoot of `o`
    # observed starts can mask up to `o` real drops.
    mdrop_upper = m.get("measure_drop_fraction_upper", mdrop)
    ok = (m.get("cohort_valid") is True
          and isinstance(attempted, (int, float))
          and attempted >= STRICT_TARGET * 0.995
          and isinstance(mdrop_upper, (int, float))
          and mdrop_upper <= 0.001
          and m.get("outcome_unexpected") == 0
          and isinstance(m.get("iter_p95_ms"), (int, float))
          and m["iter_p95_ms"] <= 100
          and isinstance(m.get("iter_p99_ms"), (int, float))
          and m["iter_p99_ms"] <= 250)
    return {"pass": bool(ok), "attempted_ops_per_s": attempted,
            "target": STRICT_TARGET,
            "measure_drop_fraction": mdrop,
            "measure_drop_fraction_upper": mdrop_upper,
            "measure_scheduled": m.get("measure_scheduled"),
            "measure_started": m.get("measure_started"),
            "measure_completed": m.get("measure_completed"),
            "population": "measurement_cohort"}


def _num(v):
    return float(v) if isinstance(v, (int, float)) else None


def _sidecar_timing_gate(out_dir: Path, sidecars: list[dict],
                         window_start_ms) -> dict:
    """Every sidecar must have started its k6 scenario before
    measurement_start - 5s, having first validated the perf-state ready
    marker. Missing k6-start provenance is itself a load-model defect —
    a sidecar that joined late is not the registered mixed load."""
    gate = {"ok": True, "detail": {}}
    measure_start_s = (window_start_ms / 1000.0
                       if isinstance(window_start_ms, (int, float))
                       else None)
    for sc in sidecars:
        scn = sc.get("name")
        ks: dict = {}
        kf = out_dir / scn / "k6-started.json"
        try:
            ks = json.loads(kf.read_text()) if kf.is_file() else {}
        except (OSError, json.JSONDecodeError):
            ks = {}
        ts = ks.get("ts")
        ok = (isinstance(ts, (int, float))
              and measure_start_s is not None
              and ts < measure_start_s - 5)
        gate["detail"][scn] = {
            "k6_started_ts": ts,
            "state_ready_ts": ks.get("state_ready_ts"),
            "state_ready_run_id": ks.get("state_ready_run_id"),
            "deadline_s": (round(measure_start_s - 5, 3)
                           if measure_start_s is not None else None),
            "ok": bool(ok)}
        gate["ok"] = gate["ok"] and ok
    return gate


def _report_time_ok(run_end, report_generated_at) -> bool:
    """The verdict file must be generated on the same host clock that ran
    the load: run_end <= generated_at <= run_end + 6h."""
    return (isinstance(run_end, (int, float))
            and isinstance(report_generated_at, (int, float))
            and run_end <= report_generated_at
            and report_generated_at - run_end <= 6 * 3600)


def evaluate(records: dict) -> dict:
    order = ["A1", "B1", "B2", "A2"]
    missing = [n for n in order if n not in records]
    result: dict = {"verdict": "INCOMPLETE", "points": {}}
    if missing:
        result["reason"] = f"aborted before {missing}"
        return result
    for name in order:
        rec = records[name]
        checks = _health_checks(rec, mixed=True)
        ev = point_evidence(rec)
        # pool-size identity: env override must be visible in the actual
        # /__perf/metrics pool size and the runtime-role backend count.
        configured = ev["configured_pool"]
        checks["pool_size_observed"] = (
            configured is not None
            and str(ev["pool_size_observed"]) == str(configured))
        checks["runtime_backends_match"] = (
            configured is not None
            and str(ev["runtime_backends_max"]) == str(configured))
        failed = [k for k, v in checks.items() if v is not True]
        result["points"][name] = {
            "checks": checks, "failed": failed, "evidence": ev,
            "audit_queue": {k: (rec.get("audit_queue_post_drain") or {})
                            .get(k) for k in (
                                "enqueued", "persisted", "dropped",
                                "pending_in_process")},
            "verdict": "PASS" if not failed else "FAIL"}
    health_failed = [n for n in order
                     if result["points"][n]["verdict"] != "PASS"]
    if health_failed:
        result["verdict"] = "FAIL"
        result["reason"] = f"health/identity gates failed on " \
                           f"{health_failed}"
        return result

    ev = {n: result["points"][n]["evidence"] for n in order}
    gates: dict = {}
    a_ops = [_num(ev["A1"]["ops_per_s"]), _num(ev["A2"]["ops_per_s"])]
    if not all(v is not None for v in a_ops):
        result["verdict"] = "INCONCLUSIVE"
        result["reason"] = "A-side ops/s missing"
        return result
    a_max, a_mean = max(a_ops), sum(a_ops) / 2
    spread = (a_max - min(a_ops)) / a_max if a_max else None
    gates["a_spread_le_5pct"] = {"pass": spread is not None
                               and spread <= 0.05,
                               "a_ops": a_ops, "spread": spread}
    if gates["a_spread_le_5pct"]["pass"] is not True:
        result["verdict"] = "INCONCLUSIVE"
        result["reason"] = f"A spread {spread} > 5%"
        result["gates"] = gates
        return result

    b_ops = [_num(ev["B1"]["ops_per_s"]), _num(ev["B2"]["ops_per_s"])]
    b_mean = (sum(b_ops) / 2 if all(v is not None for v in b_ops)
              else None)
    floor = 1.03 * a_max
    gates["throughput_improvement_ge_3pct_each"] = {
        "pass": (b_mean is not None
                 and all(v >= floor for v in b_ops)),
        "a_ref": a_max, "floor_103pct": floor, "b_values": b_ops}
    gates["throughput_improvement_ge_4pct_mean"] = {
        "pass": (b_mean is not None and a_mean
                 and b_mean >= 1.04 * a_mean),
        "a_mean": a_mean, "b_mean": b_mean,
        "ratio": (round(b_mean / a_mean, 4)
                  if b_mean and a_mean else None)}

    a_p99s = [v for v in (ev["A1"]["p99_ms"], ev["A2"]["p99_ms"])
              if isinstance(v, (int, float))]
    a_p99_ref = min(a_p99s) if a_p99s else None
    p99_bad = []
    for n in ("B1", "B2"):
        b = ev[n]["p99_ms"]
        p99_bad.append(
            a_p99_ref is not None and isinstance(b, (int, float))
            and b > a_p99_ref * 1.10 and b - a_p99_ref > 20.0)
    gates["p99_bounded"] = {"pass": a_p99_ref is not None
                           and not any(p99_bad),
                           "a_p99_ref": a_p99_ref,
                           "b_p99": [ev["B1"]["p99_ms"],
                                     ev["B2"]["p99_ms"]]}

    a_drops = [v for v in (ev["A1"]["drop_fraction"],
                           ev["A2"]["drop_fraction"])
               if isinstance(v, (int, float))]
    a_drop = max(a_drops) if a_drops else None
    b_drops = [ev["B1"]["drop_fraction"], ev["B2"]["drop_fraction"]]
    gates["drop_fraction_worsening_le_0_1pp"] = {
        "pass": (a_drop is not None and all(
            isinstance(v, (int, float)) and v - a_drop <= 0.001
            for v in b_drops)),
        "a_max_drop": a_drop, "b_drops": b_drops}

    a_wait_mean = [v for v in (ev["A1"]["waiting_mean"],
                              ev["A2"]["waiting_mean"])
                   if isinstance(v, (int, float))]
    a_wpa = [v for v in (ev["A1"]["wait_per_acq_ms"],
                         ev["A2"]["wait_per_acq_ms"])
             if isinstance(v, (int, float))]
    a_wait = sum(a_wait_mean) / len(a_wait_mean) if a_wait_mean else None
    a_wpa_m = sum(a_wpa) / len(a_wpa) if a_wpa else None
    b_wait = [ev["B1"]["waiting_mean"], ev["B2"]["waiting_mean"]]
    b_wpa = [ev["B1"]["wait_per_acq_ms"], ev["B2"]["wait_per_acq_ms"]]
    wait_ok = (a_wait and all(isinstance(v, (int, float)) for v in b_wait)
               and all(v <= 0.70 * a_wait for v in b_wait))
    wpa_ok = (a_wpa_m and all(isinstance(v, (int, float)) for v in b_wpa)
              and all(v <= 0.70 * a_wpa_m for v in b_wpa))
    gates["structural_pool"] = {
        "pass": bool(wait_ok or wpa_ok),
        "waiting_acquisitions_ge_30pct_down": {
            "pass": bool(wait_ok), "a_mean": a_wait, "b": b_wait},
        "wait_per_acq_ge_30pct_down": {
            "pass": bool(wpa_ok), "a_mean": a_wpa_m, "b": b_wpa},
        "checked_out_vs_configured": {
            n: {"checked_out_max": ev[n]["checked_out_max"],
                "configured": ev[n]["configured_pool"],
                "waiting_max": ev[n]["waiting_max"]}
            for n in order}}

    a_share = [v for v in (ev["A1"]["wal_wait"]["wal_wait_share"],
                           ev["A2"]["wal_wait"]["wal_wait_share"])
               if isinstance(v, (int, float))]
    a_share_m = sum(a_share) / len(a_share) if a_share else None
    b_share = [ev["B1"]["wal_wait"]["wal_wait_share"],
               ev["B2"]["wal_wait"]["wal_wait_share"]]
    gates["wal_guardrail_le_10pp"] = {
        "pass": (a_share_m is not None and all(
            isinstance(v, (int, float)) and v - a_share_m <= 0.10
            for v in b_share)),
        "a_mean_share": a_share_m, "b_share": b_share}

    result["gates"] = gates
    result["strict_3000"] = {n: ev[n]["strict_3000_gate"] for n in order}
    bad = [k for k, v in gates.items() if v.get("pass") is not True]
    result["verdict"] = "PASS" if not bad else "FAIL"
    if bad:
        result["reason"] = f"gates failed: {bad}"
    return result


def _reeval(point_dir: Path) -> int:
    """Offline re-evaluation of a recorded formal point. Replays the
    identical _post_run_verdict analysis over saved evidence — no docker,
    no load, new_real_load_time = 0. Reads point.json (run record) and the
    point directory's raw artifacts only; the recorded verdict is never
    an input."""
    point_dir = Path(point_dir)
    rec = json.loads((point_dir / "point.json").read_text())
    point = rec["point"]
    dur_s = int(str(point.get("duration") or "0").rstrip("s"))
    # Rebind sis.RESULTS so the phase/run_id path contract used by
    # point_evidence resolves to this evidence directory.
    sis.RESULTS = point_dir.parent.parent
    load = rec.get("load") or {}
    spec = {"task": "formal-evidence-contract-repair",
            "name": point["name"], "phase_dir": point["phase"],
            "duration_s": dur_s, "stability": True}
    result = _post_run_verdict(
        rec, point, point_dir, spec, dur_s,
        remote_host_time_start=load.get("started_ts"),
        remote_host_time_end=load.get("ended_ts"),
        verdict_path=sis.RESULTS / f"{point['name']}.reeval-verdict.json",
        enforce_report_time=False)
    result["timestamps"]["offline_reeval"] = True
    result["reeval"] = {"mode": "offline_same_evidence",
                        "evidence_dir": str(point_dir),
                        "new_real_load_time_s": 0}
    sis.jdump(sis.RESULTS / f"{point['name']}.reeval-verdict.json", result)
    print(json.dumps({"verdict": result["verdict"],
                      "fail_class": result.get("fail_class"),
                      "gate": result["capacity_gate"]["status"],
                      "failed": result["failed"]}))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--image")
    ap.add_argument("--app-sha", default=os.environ.get(
        "SIS_APP_SHA", "unknown"))
    ap.add_argument("--phase",
                    choices=["run", "evaluate", "formal", "stability",
                             "preflight"],
                    default="run")
    ap.add_argument("--reeval", metavar="POINT_DIR", default=None,
                    help="offline re-evaluation of a saved formal point "
                         "directory (no docker, no load)")
    args = ap.parse_args()

    if args.reeval:
        return _reeval(Path(args.reeval))
    if not args.image:
        ap.error("--image is required unless --reeval is used")

    sis.require_project()
    sis.RESULTS.mkdir(parents=True, exist_ok=True)

    if args.phase == "preflight":
        return _dry_preflight(args)
    if args.phase == "evaluate":
        records = {}
        for name in ("A1", "B1", "B2", "A2"):
            p = (sis.RESULTS / PHASE_DIR / "mixed" / name
                 / "point.json")
            if p.exists():
                rec = json.loads(p.read_text())
                rec["audit_queue_post_drain"] = audit_queue_final(
                    p.parent)
                records[name] = rec
        v = evaluate(records)
        sis.jdump(sis.RESULTS / "pool24v32-verdict.json", v)
        print(json.dumps({"verdict": v["verdict"],
                          "reason": v.get("reason")}))
        return 0

    if args.phase == "stability":
        return _run_single(args, POINT_STABILITY)
    if args.phase == "formal":
        return _run_formal(args)

    cpus = json.loads(subprocess.run(
        [sys.executable,
         str(Path(__file__).parent / "single_instance_scaling.py"),
         "env-check"], check=True, capture_output=True, text=True).stdout)
    role, role_source = runtime_role_from_image(args.image)
    bin_sha = pr.image_binary_sha(args.image)
    manifest = {
        "task": "business-pool-24-vs-32",
        "protocol": "single variable DATABASE_MAX_CONNECTIONS: "
                    "A=24 (benchmark pin) vs B=32 (production default); "
                    "mixed A1->B1->B2->A2 4x120s 3000/s",
        "app_sha": args.app_sha,
        "app_image": args.image,
        "app_binary_sha256": bin_sha,
        "runtime_role": role,
        "runtime_role_source": role_source,
        "harness_sha": os.environ.get(
            "SIS_HARNESS_SHA",
            subprocess.run(["git", "rev-parse", "HEAD"],
                           capture_output=True, text=True).stdout.strip()
            or "unknown"),
    }
    if not bin_sha:
        print(json.dumps({"error": "binary sha256 unavailable"}))
        return 2
    sis.dc("volume", "create", pr.KEYSET_VOLUME, check=False)

    diag = diagnose_pg()
    manifest["postgres_diag"] = diag
    sis.jdump(sis.RESULTS / "pool24v32-manifest.json", manifest)
    print(json.dumps({"diag_ok": diag.get("ok"),
                      "max_connections": diag.get("max_connections"),
                      "mismatches": diag.get("baseline_mismatches"),
                      "error": diag.get("error")}))
    if not diag.get("ok"):
        return 2

    mixed = dict(scenario="cap_mixed",
                 executor="constant-arrival-rate", rate=3000,
                 duration="120s", pre_vus=256, max_vus=1024,
                 user_count=256, sidecar_delay_s=0,
                 sidecars=[dict(s) for s in SIDECARS_120])
    observer = {"runtime_role": role, "interval_s": "0.25"}
    records: dict = {}
    try:
        for name, pool in (("A1", 24), ("B1", 32),
                           ("B2", 32), ("A2", 24)):
            point = pr._point(name, f"{PHASE_DIR}/mixed", args.image,
                                cpus, **mixed)
            point["app_env_overrides"] = {
                "DATABASE_MAX_CONNECTIONS": str(pool)}
            point["residency_observer"] = dict(observer)
            rec = pr.run_ab_point(point)
            rec["audit_queue_post_drain"] = audit_queue_final(
                sis.RESULTS / point["phase"] / point["name"])
            records[name] = rec
            ev = point_evidence(rec)
            print(json.dumps({
                "point": name, "pool": pool, "ok": rec.get("ok"),
                "error": rec.get("error"),
                "pool_size_observed": ev["pool_size_observed"],
                "runtime_backends_max": ev["runtime_backends_max"],
                "ops": ev["ops_per_s"]}))
            if not rec.get("ok"):
                break
    finally:
        sis.stack_down()
    verdict = evaluate(records)
    sis.jdump(sis.RESULTS / "pool24v32-verdict.json", verdict)
    print(json.dumps({"verdict": verdict["verdict"],
                      "reason": verdict.get("reason")}))
    return 0


POINT_FORMAL = {
    "task": "formal-3000-confirmation", "name": "F3000R2",
    "phase_dir": "formal3000r2", "duration_s": 600,
    "verdict_file": "formal3000-verdict.json",
    "manifest_file": "formal3000-manifest.json",
    "stability": False,
}
_AUDIT_CHECK_KEYS = {
    "queue_full_zero", "dropped_required_zero", "db_outbox_drained",
    "audit_reconciled", "journal_contiguous", "queue_dropped_zero",
    "pending_zero_post_drain", "enqueued_eq_persisted"}
_REFRESH_CHECK_KEYS = {
    "active_per_scope_le_10", "spent_per_family_le_64",
    "expired_backlog_zero"}


def _cliff_fail_class(stab: dict) -> str:
    """Sustained-cliff attribution: CHECKPOINT_CORRELATED_CLIFF only when
    >=2 anomalous buckets fall inside distinct checkpoint write windows;
    SUSTAINED_DB_WAL_CLIFF when the measurement window is WAL-wait
    dominated without that repetition; otherwise correlation-only ->
    UNRESOLVED."""
    anoms = stab.get("anomaly_buckets") or []
    ckpt_assoc = sum(
        1 for a in anoms if a.get("in_checkpoint_write_window"))
    if ckpt_assoc >= 2:
        return "CHECKPOINT_CORRELATED_CLIFF"
    wal = [((b.get("wal") or {}).get("wal_wait_share"))
           for b in stab.get("buckets") or []]
    wal = [w for w in wal if isinstance(w, (int, float))]
    if wal and sum(wal) / len(wal) >= 0.5:
        return "SUSTAINED_DB_WAL_CLIFF"
    return "UNRESOLVED"


def classify_stability(final: str, stab: dict | None,
                       failed: list) -> tuple[str, str | None]:
    """Map the formal point outcome onto the pre-registered stability
    verdict space: verdict in {PASS, FAIL, INVALID} plus a fail_class in
    {SUSTAINED_DB_WAL_CLIFF, CHECKPOINT_CORRELATED_CLIFF,
    LOAD_MODEL_INVALID, GENERATOR_RESOURCE_INVALID,
    EVIDENCE_PIPELINE_INVALID, AUDIT_HEALTH_FAILURE,
    REFRESH_STATE_FAILURE, PROVENANCE_INVALID, UNRESOLVED}."""
    herd = (stab or {}).get("reauth_herd") or {}
    cliff = (stab or {}).get("sustained_cliff") or {}
    stab_missing = stab is None or bool(stab.get("error"))
    if final == "PASS":
        if stab_missing:
            # the sustained-cliff detector could not run -> stability
            # cannot be certified from this evidence
            return "INVALID", "UNRESOLVED"
        if herd.get("herd"):
            # a >500/minute expired_reauth burst is a fixture herd,
            # not SUT capacity evidence
            return "INVALID", "LOAD_MODEL_INVALID"
        if cliff.get("sustained_cliff"):
            # A continuous 5-minute cliff must not be averaged away by
            # the full-window gate.
            return "FAIL", _cliff_fail_class(stab)
        return "PASS", None
    if final == "FAIL":
        fset = set(failed)
        if fset & _AUDIT_CHECK_KEYS:
            return "FAIL", "AUDIT_HEALTH_FAILURE"
        if fset & _REFRESH_CHECK_KEYS:
            return "FAIL", "REFRESH_STATE_FAILURE"
        if cliff.get("sustained_cliff"):
            return "FAIL", _cliff_fail_class(stab)
        return "FAIL", "UNRESOLVED"
    if final == "GENERATOR_RESOURCE_INVALID":
        return "INVALID", "GENERATOR_RESOURCE_INVALID"
    if final == "EVIDENCE_PIPELINE_INVALID":
        return "INVALID", "EVIDENCE_PIPELINE_INVALID"
    if final == "PROVENANCE_INVALID":
        return "INVALID", "PROVENANCE_INVALID"
    # LOAD_MODEL_INVALID / INVALID / INJECTOR_CAP_UNEXPECTED (injector
    # ceiling reached is a load-model property) are all load-model or
    # accounting invalidity, not SUT capacity failures.
    return "INVALID", "LOAD_MODEL_INVALID"


POINT_STABILITY = {
    "task": "formal3000-30m-harness-repair", "name": "F3000-30M-R2",
    "phase_dir": "formal3000-30m-r2", "duration_s": 1800,
    "verdict_file": "stability3000r2-verdict.json",
    "manifest_file": "stability3000r2-manifest.json",
    "stability": True,
}


def _run_formal(args) -> int:
    return _run_single(args, POINT_FORMAL)


def _run_single(args, spec: dict) -> int:
    """Single FORMAL3000 confirmation point (load-model repaired): pool=32,
    cap_mixed constant-arrival 3000/s, 600s scenario (measurement window =
    585s, CAP_WARMUP_MS=15000), preAllocatedVUs=maxVUs=2048 (Little's-law
    headroom: 3000*0.497 ~= 1491 + ~37%), identical sidecar matrix.

    Validity layers resolved in order:
      BLOCKED_LOAD_GENERATOR_MEMORY  preflight MemAvailable < 14 GiB
      INVALID                        point/infrastructure failure
      GENERATOR_RESOURCE_INVALID     independent generator evidence
                                     (OOM/throttle/socket/analyzer/exit)
      LOAD_MODEL_INVALID             late_vu_fraction > 0.1% or a subject
                                     re-bootstrap wave under the gate
      INJECTOR_CAP_UNEXPECTED        vus_max==2048 while every SUT gate
                                     other than arrivals still passes
      PASS / FAIL                    measurement-cohort capacity gate +
                                     health checks
    vus_max reaching the cap is a diagnostic flag
    (injector_vu_cap_reached), never invalidity evidence alone.
    """
    remote_host_time_start = time.time()
    cpus = json.loads(subprocess.run(
        [sys.executable,
         str(Path(__file__).parent / "single_instance_scaling.py"),
         "env-check"], check=True, capture_output=True, text=True).stdout)
    role, role_source = runtime_role_from_image(args.image)
    bin_sha = pr.image_binary_sha(args.image)
    if not bin_sha:
        print(json.dumps({"error": "binary sha256 unavailable"}))
        return 2
    # Fail fast on workspace identity before touching docker — every file
    # the run mounts or executes must live under this checkout.
    ws_prov = sis.workspace_provenance()
    if not ws_prov["ok"]:
        out = {"verdict": "PROVENANCE_INVALID",
               "reason": "HARNESS_WORKSPACE files missing/empty",
               "missing": ws_prov["missing"],
               "workspace": ws_prov["workspace_realpath"]}
        sis.jdump(sis.RESULTS / spec["verdict_file"], out)
        print(json.dumps(out))
        return 2
    sis.dc("volume", "create", pr.KEYSET_VOLUME, check=False)
    diag = diagnose_pg()
    sis.jdump(sis.RESULTS / spec["manifest_file"], {
        "task": spec["task"], "app_sha": args.app_sha,
        "app_image": args.image, "app_binary_sha256": bin_sha,
        "runtime_role": role, "runtime_role_source": role_source,
        "postgres_diag": diag,
        "workspace_provenance": ws_prov,
        "remote_host_time_start": remote_host_time_start,
        "load_model": {"pre_allocated_vus": 2048, "max_vus": 2048,
                       "subject_token": "refresh-adopts-access_token",
                       "generator_mem_min_gib": 14},
        "scenario": {"name": "cap_mixed", "rate": 3000,
                     "duration_s": spec["duration_s"],
                     "warmup_ms": 15000,
                     "measurement_window_s": spec["duration_s"] - 15,
                     "mix": {"userinfo": 30, "client_credentials": 25,
                             "authorization_code": 15, "refresh": 15,
                             "token_exchange": 15},
                     "sidecars": SIDECARS_120,
                     "sidecar_duration_s": spec["duration_s"]}})
    if not diag.get("ok"):
        print(json.dumps({"error": "baseline GUC diag failed",
                          "diag": diag}))
        return 2

    dur_s = spec["duration_s"]
    sidecars = [dict(s, duration=f"{dur_s}s") for s in SIDECARS_120]
    point = pr._point(spec["name"], spec["phase_dir"], args.image, cpus,
                        scenario="cap_mixed",
                        executor="constant-arrival-rate", rate=3000,
                        duration=f"{dur_s}s", pre_vus=2048, max_vus=2048,
                        user_count=256, sidecar_delay_s=0,
                        sidecars=sidecars, warmup_ms=15000)
    point["app_env_overrides"] = {"DATABASE_MAX_CONNECTIONS": "32"}
    point["residency_observer"] = {"runtime_role": role,
                                   "interval_s": "0.25"}
    point["generator_mem_min_gib"] = 14
    point["stream_evidence"] = True
    point["formal_preflight"] = True
    if os.environ.get("SIS_EXPECTED_BINARY_SHA256"):
        point["expected_binary_sha256"] = os.environ[
            "SIS_EXPECTED_BINARY_SHA256"]
    rec = {}
    try:
        rec = pr.run_ab_point(point)
        rec["audit_queue_post_drain"] = audit_queue_final(
            sis.RESULTS / point["phase"] / point["name"])
    finally:
        sis.stack_down()
    remote_host_time_end = time.time()
    if rec.get("blocked") == "BLOCKED_LOAD_GENERATOR_MEMORY":
        out = {"verdict": "BLOCKED_LOAD_GENERATOR_MEMORY",
               "generator_preflight": rec.get("generator_preflight")}
        sis.jdump(sis.RESULTS / spec["verdict_file"], out)
        print(json.dumps(out))
        return 0
    if not rec.get("ok"):
        err = str(rec.get("error") or "")
        verdict = ("PROVENANCE_INVALID"
                   if err.startswith("PROVENANCE_INVALID") else "INVALID")
        sis.jdump(sis.RESULTS / spec["verdict_file"],
                  {"verdict": verdict, "error": rec.get("error"),
                   "workspace_provenance": rec.get("workspace_provenance"),
                   "binary_provenance": rec.get("binary_provenance"),
                   "perf_schema": rec.get("perf_schema"),
                   "sampler_health": rec.get("sampler_health"),
                   "generator_preflight": rec.get("generator_preflight")})
        print(json.dumps({"verdict": verdict,
                          "error": rec.get("error")}))
        return 0

    # Corrected measurement-cohort capacity gate on the raw k6 summary —
    # the whole post-run analysis lives in _post_run_verdict so an
    # offline --reeval over saved evidence runs the SAME code path.
    out_dir = sis.RESULTS / point["phase"] / point["name"]
    result = _post_run_verdict(
        rec, point, out_dir, spec, dur_s,
        remote_host_time_start, remote_host_time_end,
        verdict_path=sis.RESULTS / spec["verdict_file"])
    print(json.dumps({"verdict": result["verdict"],
                      "gate": result["capacity_gate"]["status"],
                      "failed": result["failed"],
                      "measure": (result["capacity_gate"].get("metrics")
                                  or {}).get("measure")}))
    return 0


def _post_run_verdict(rec: dict, point: dict, out_dir: Path,
                      spec: dict, dur_s: int,
                      remote_host_time_start: float,
                      remote_host_time_end: float,
                      verdict_path: Path,
                      report_now: float | None = None,
                      enforce_report_time: bool = True) -> dict:
    """Post-run verdict for a completed formal point, computed entirely
    from recorded evidence under `out_dir` plus the run record `rec`.

    Reused by the live stability path and by `--reeval`, which replays the
    same classification over an extracted evidence directory. Offline
    replay sets enforce_report_time=False: the report-time provenance gate
    exists to catch a verdict published against a fabricated run clock at
    publication time — it must not retroactively fail a re-evaluation that
    legitimately runs long after the original run."""
    import capacity_search as cs
    rec.setdefault("audit_queue_post_drain", audit_queue_final(out_dir))
    summaries = list((out_dir / "load").glob("*.summary.json"))
    os.environ["CAP_MAX_VUS"] = str(point.get("max_vus") or 2048)
    load = rec.get("load") or {}
    gfacts = {"oom_killed": bool(load.get("main_oom_killed")),
              "exit_code": load.get("main_exit_code"),
              "load_status": load.get("load_status")}
    gate = {"status": "no_summary"}
    metrics_raw = {}
    if summaries:
        summary = json.loads(summaries[0].read_text())
        try:
            metrics_raw = (json.loads(next(
                (out_dir / "load").glob("*.k6.json")).read_text())
                .get("metrics") or {})
        except (StopIteration, OSError, json.JSONDecodeError):
            metrics_raw = {}
        verdict, gm = cs.evaluate(summary, summaries[0], 3000,
                                  dur_s, "cap_mixed",
                                  generator_facts=gfacts,
                                  require_stream=True)
        gate = {"status": verdict, "metrics": gm}
    checks = _health_checks(rec, mixed=True)
    ev = point_evidence(rec)
    checks["pool_size_observed"] = str(
        ev["pool_size_observed"]) == "32"
    checks["runtime_backends_match"] = str(
        ev["runtime_backends_max"]) == "32"
    checks["capacity_gate_pass"] = gate["status"] == "PASS"
    failed = [k for k, v in checks.items() if v is not True]

    # Subject re-bootstrap wave: refresh responses now carry subjectAt
    # forward, so a healthy run should have ~zero measure-window
    # expired_reauth. A residual wave (>1% of started) means the fixture
    # still herds into full auth-code bootstraps -> the load model, not
    # the SUT, is the defect.
    def _mc(name: str) -> int:
        e = metrics_raw.get(name, {})
        vals = e.get("values", e) if isinstance(e, dict) else {}
        return int(vals.get("count", 0) or 0)
    measure_reauth = sum(
        _mc(f"cap_m{i}_subject_expired_reauth") for i in range(1, 32))
    started = ((gate.get("metrics") or {}).get("measure") or {}) \
        .get("started")
    reauth_fraction = (measure_reauth / started
                       if isinstance(started, (int, float)) and started
                       else None)
    reauth_wave = (isinstance(reauth_fraction, (int, float))
                   and reauth_fraction > 0.01)

    sidecar_timing = _sidecar_timing_gate(
        out_dir, load.get("sidecars") or [],
        (rec.get("metrics") or {}).get("window_start_ms"))

    injector_cap = (gate.get("metrics") or {}).get(
        "injector_vu_cap_reached")
    gate_reason = (gate.get("metrics") or {}).get("reason")
    if gate["status"] == "LOAD_GENERATOR_RESOURCE_INVALID":
        final = "GENERATOR_RESOURCE_INVALID"
    elif gate["status"] == "LOAD_MODEL_INVALID":
        final = "LOAD_MODEL_INVALID"
    elif (gate["status"] == "INVALID"
          and gate_reason == "evidence_pipeline_invalid"):
        final = "EVIDENCE_PIPELINE_INVALID"
    elif gate["status"] == "INVALID":
        final = "INVALID"
    elif not sidecar_timing["ok"]:
        final = "LOAD_MODEL_INVALID"
    elif gate["status"] == "PASS" and not failed:
        final = "PASS"
    elif reauth_wave:
        final = "LOAD_MODEL_INVALID"
    elif (injector_cap is True and not failed
          and gate["status"] == "FAIL"):
        # VU ceiling hit while every SUT-side gate except arrivals held —
        # unexpected with 37% Little's-law headroom; recorded, not
        # auto-invalidated, and never retried with a larger pool.
        final = "INJECTOR_CAP_UNEXPECTED"
    else:
        final = "FAIL"
    result = {
        "verdict": final,
        "capacity_gate": gate,
        "checks": checks, "failed": failed,
        "evidence": ev,
        "audit_queue": rec.get("audit_queue_post_drain"),
        # Forensic tier status (COMPLETE/TRUNCATED/ABSENT): projected for
        # reporting; authoritative stream validity is computed inside
        # `gate` and never reads this field.
        "forensic_diag": (gate.get("metrics") or {}).get("forensic_diag"),
        "sidecar_timing": sidecar_timing,
        "generator_preflight": rec.get("generator_preflight"),
        "provenance": {
            "workspace": rec.get("workspace_provenance"),
            "binary": rec.get("binary_provenance"),
            "perf_schema": rec.get("perf_schema"),
            "sampler_health": rec.get("sampler_health"),
            "runner": rec.get("provenance"),
            "expected_binary_sha256": point.get(
                "expected_binary_sha256"),
        },
        "generator": {
            "main_oom_killed": load.get("main_oom_killed"),
            "main_exit_code": load.get("main_exit_code"),
            "injector_vu_cap_reached": injector_cap,
            "pre_allocated_vus": point.get("pre_vus"),
            "max_vus": point.get("max_vus"),
        },
        "subject_lifecycle": {
            "measure_expired_reauth": measure_reauth,
            "reauth_fraction_of_started": (
                round(reauth_fraction, 6)
                if isinstance(reauth_fraction, float) else None),
        },
        "timestamps": {
            "remote_host_time_start": remote_host_time_start,
            "remote_host_time_end": remote_host_time_end,
            "run_start_epoch": load.get("started_ts"),
            "run_end_epoch": load.get("ended_ts"),
        },
    }
    if spec["stability"]:
        import stability_analyze as sa
        mrec = rec.get("metrics") or {}
        ws_ms = mrec.get("window_start_ms")
        wsec = mrec.get("window_seconds")
        stab = None
        if isinstance(ws_ms, (int, float)) and wsec:
            try:
                stab = sa.analyze(out_dir, ws_ms / 1000.0,
                                  float(wsec))
            except Exception as exc:  # noqa: BLE001
                stab = {"error": f"stability_analyze failed: {exc}"}
        result["stability"] = stab
        final, fail_class = classify_stability(final, stab, failed)
        result["verdict"] = final
        if fail_class:
            result["fail_class"] = fail_class
    # Report timestamp provenance: generated on the same host clock that
    # ran the load, inside a sane report window — a verdict whose
    # timestamps contradict the run cannot publish PASS.
    report_generated_at = (report_now if report_now is not None
                           else time.time())
    time_ok = _report_time_ok(load.get("ended_ts"), report_generated_at)
    result["timestamps"]["report_generated_at"] = report_generated_at
    result["timestamps"]["report_time_ok"] = (
        time_ok if enforce_report_time else "skipped_offline_reeval")
    if (enforce_report_time and not time_ok
            and result["verdict"] == "PASS"):
        result["verdict"] = "INVALID"
        result["fail_class"] = "PROVENANCE_TIME_INVALID"
    sis.jdump(verdict_path, result)
    return result


def _wait_exit0(cname: str, timeout_s: int = 600) -> bool:
    """Wait for a detached container to exit; True iff exit code 0."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        running = sis.dc("inspect", cname, "--format",
                         "{{.State.Running}}", check=False).stdout.strip()
        if running != "true":
            code = sis.dc("inspect", cname, "--format",
                          "{{.State.ExitCode}}", check=False
                          ).stdout.strip()
            return code == "0"
        time.sleep(3)
    return False


def _dry_preflight(args) -> int:
    """§21 no-real-load preflight: prove workspace identity, compose
    file, samplers on worktree files, app endpoint schema, running
    binary, perf-state seed readiness and the sidecar ready-marker gate
    — then tear down WITHOUT any business k6 load."""
    host_t0 = time.time()
    run_id = "PREFLIGHT-30M"
    out_dir = sis.RESULTS / "preflight" / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    out: dict = {"verdict": "FAIL", "checks": {},
                 "remote_host_time_start": host_t0}
    ws_prov = sis.workspace_provenance()
    out["checks"]["workspace"] = ws_prov
    mounts = sis.verify_mount_sources()
    out["checks"]["mount_sources"] = mounts
    if not ws_prov["ok"] or not all(mounts.values()):
        out["error"] = "workspace/mount-source provenance failed"
        return _finish_preflight(out, host_t0, out_dir)
    cpus = json.loads(subprocess.run(
        [sys.executable,
         str(Path(__file__).parent / "single_instance_scaling.py"),
         "env-check"], check=True, capture_output=True, text=True).stdout)
    role, role_source = runtime_role_from_image(args.image)
    bin_sha = pr.image_binary_sha(args.image)
    out["checks"]["image_binary_sha256"] = bin_sha
    out["checks"]["runtime_role"] = {"role": role, "source": role_source}
    if not bin_sha:
        out["error"] = "image binary sha unavailable"
        return _finish_preflight(out, host_t0, out_dir)
    try:
        diag = diagnose_pg()
        out["checks"]["postgres_diag"] = diag
        if not diag.get("ok"):
            raise RuntimeError("baseline GUC diag failed")
        point = pr._point(run_id, "preflight", args.image, cpus,
                            scenario="cap_mixed",
                            executor="constant-arrival-rate", rate=3000,
                            duration="1800s", pre_vus=2048,
                            max_vus=2048, user_count=256,
                            warmup_ms=15000)
        point["app_env_overrides"] = {"DATABASE_MAX_CONNECTIONS": "32"}
        sis.CURRENT_POINT = point
        sis.stack_down()
        rec_stack = pr.stack_up_pinned(point)
        out["checks"]["stack"] = {
            "healthy": rec_stack.get("healthy"),
            "deployment_id": rec_stack.get("deployment_id")}
        point["deployment_id"] = rec_stack.get("deployment_id")
        bp = sis.runtime_binary_provenance(
            image_sha=bin_sha,
            expected_sha=os.environ.get("SIS_EXPECTED_BINARY_SHA256"))
        out["checks"]["binary_provenance"] = bp
        ps = sis.app_perf_schema(
            out_path=out_dir / "perf-metrics-preflight.json")
        out["checks"]["perf_schema"] = ps
        if not bp["ok"] or not ps["ok"]:
            raise RuntimeError("binary/schema provenance failed")
        # Samplers on the worktree files — health-gated like a real run.
        sis.start_samplers(run_id, str(out_dir))
        obs_name = f"sis-residency-{run_id}"
        sis._remove_owned_by_name(obs_name)
        p = sis.dc(
            "run", "-d", "--name", obs_name, "--network", sis.NETWORK,
            "--label", f"{sis.SIS_LABEL}={sis.PROJECT}",
            "-v", f"{sis.TOOLS}/residency_observer.py:/tmp/obs.py:ro",
            "-v", f"{out_dir}:/out",
            "-e", f"RUN_ID={run_id}",
            "-e", "OUT_PATH=/out/residency.jsonl",
            "-e", "INTERVAL_S=0.25", "-e", f"RUNTIME_ROLE={role}",
            sis.PERF_IMAGE, "python3", "/tmp/obs.py")
        sis._record_extra(p.stdout, obs_name, "residency_observer")
        sh = sis.sampler_health(run_id, out_dir,
                                expect_residency=True, timeout_s=10)
        out["checks"]["sampler_health"] = sh
        if not sh["ok"]:
            raise RuntimeError("sampler health failed")
        # Seed via the real runner path (SEED_ONLY) — identical to the
        # formal load's seed phase, minus k6.
        seed_env = sis.load_env_list(point, run_id) + [
            "-e", "PERF_SEED_ONLY=1"]
        sname = f"sis-seed-{run_id}"
        (out_dir / "seed").mkdir(exist_ok=True)
        sis._remove_owned_by_name(sname)
        p = sis.dc("run", "-d", "--name", sname, "--network", sis.NETWORK,
                   "--label", f"{sis.SIS_LABEL}={sis.PROJECT}",
                   "-v", f"{out_dir}/seed:/out",
                   "-v", f"{sis.PROJECT}_perf_state:/perf-state",
                   *seed_env, sis.PERF_IMAGE)
        sis._record_extra(p.stdout, sname, "seed_preflight")
        ok_seed = _wait_exit0(sname, timeout_s=600)
        out["checks"]["seed_exit0"] = ok_seed
        if not ok_seed:
            raise RuntimeError("seed container failed")
        mk_proc = sis.dc(
            "run", "--rm", "--network", sis.NETWORK,
            "--label", f"{sis.SIS_LABEL}={sis.PROJECT}",
            "-v", f"{sis.PROJECT}_perf_state:/perf-state",
            sis.PERF_IMAGE, "python3", "-c",
            "import json;print(json.dumps(json.load(open("
            "'/perf-state/perf-state-ready.json'))))",
            check=False)
        marker = None
        try:
            marker = json.loads(mk_proc.stdout)
        except (json.JSONDecodeError, ValueError):
            marker = None
        out["checks"]["ready_marker"] = marker
        if not isinstance(marker, dict) \
                or marker.get("run_id") != run_id:
            raise RuntimeError(f"ready marker missing/mismatch: {marker}")
        # Each sidecar validates the marker via its own runner path.
        for sc in SIDECARS_120:
            scn = f"sis-scpre-{sc['name']}-{run_id}"
            sc_env = sis.env_list_without(
                sis.load_env_list(point, run_id),
                ("PERF_SCENARIO", "PERF_RATE", "PERF_VUS",
                 "PERF_PRE_ALLOCATED", "PERF_MAX_VUS", "PERF_DURATION",
                 "PERF_USER_COUNT"))
            sc_env += [
                "-e", f"PERF_SCENARIO={sc['scenario']}",
                "-e", f"PERF_RATE={sc['rate']}",
                "-e", f"PERF_PRE_ALLOCATED_VUS={sc['pre_vus']}",
                "-e", f"PERF_MAX_VUS={sc['max_vus']}",
                "-e", f"PERF_DURATION={sc['duration']}",
                "-e", f"PERF_USER_COUNT={sc.get('user_count', 64)}",
                "-e", "PERF_SKIP_SEED=1",
                "-e", "PERF_PREFLIGHT_ONLY=1",
                "-e", "PERF_STATE_WAIT_S=120",
            ]
            (out_dir / f"sc-{sc['name']}").mkdir(exist_ok=True)
            sis._remove_owned_by_name(scn)
            p = sis.dc("run", "-d", "--name", scn, "--network",
                       sis.NETWORK,
                       "--label", f"{sis.SIS_LABEL}={sis.PROJECT}",
                       "-v", f"{out_dir}/sc-{sc['name']}:/out",
                       "-v", f"{sis.PROJECT}_perf_state:/perf-state",
                       *sc_env, sis.PERF_IMAGE)
            sis._record_extra(p.stdout, scn,
                              f"scpreflight:{sc['name']}")
            ok_sc = _wait_exit0(scn, timeout_s=180)
            out["checks"][f"sidecar_ready_{sc['name']}"] = ok_sc
            if not ok_sc:
                raise RuntimeError(f"sidecar preflight failed: {sc['name']}")
        # Timestamps consistent across the dry run.
        out["verdict"] = "PASS"
    except Exception as e:  # noqa: BLE001
        out["verdict"] = "FAIL"
        out["error"] = f"{type(e).__name__}: {e}"[:400]
    finally:
        for c in (f"sis-seed-{run_id}",
                  *[f"sis-scpre-{s['name']}-{run_id}" for s in SIDECARS_120],
                  f"sis-residency-{run_id}"):
            sis._remove_owned_by_name(c, stop=True)
        sis.stop_samplers(run_id)
        sis.stack_down()
    return _finish_preflight(out, host_t0, out_dir)


def _finish_preflight(out: dict, host_t0: float, out_dir: Path) -> int:
    out["remote_host_time_end"] = time.time()
    out["report_generated_at"] = out["remote_host_time_end"]
    out["report_time_ok"] = True
    sis.jdump(out_dir / "preload-preflight.json", out)
    print(json.dumps({"PRELOAD_PREFLIGHT": out["verdict"],
                      "error": out.get("error")}))
    return 0 if out["verdict"] == "PASS" else 2


if __name__ == "__main__":
    sys.exit(main())
