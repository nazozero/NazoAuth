#!/usr/bin/env python3
"""Adaptive 10-minute capacity point search on the running perf stack.

Finds, per scenario, the highest 10-minute point that still meets the formal
capacity gate (MAX_10M_PASS) and the first failing target above it
(FIRST_FAIL_ABOVE). Points are independent `compose run perf` executions on
the already-running nazoauth-perf stack; cap_mixed points instead delegate to
soak_run.sh so the full sidecar set (refresh/argon2/metadata/fapi + audit
exporter + receiver) is active.

Ladder rule (fixed, no fine-grained search):
  PASS  -> target *= 1.25
  FAIL  -> if a PASS exists, run one midpoint between highest PASS and
           lowest FAIL; if the first point failed, target /= 1.25 until a
           PASS exists.
  stop  -> highest PASS with a FAIL above it, or 6 points consumed.

PASS gate (non-argon2):
  dropped_iterations <= 0.1% of the arrival cohort
  measured rps >= 99.5% of target
  unexpected/business/security error_rate == 0
  p95 <= 100ms, p99 <= 250ms
A point is LOAD_GENERATOR_INVALID when k6 itself saturated (the SUT is not
charged for that point).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from measure_schedule import (  # noqa: E402
    _trend, cohort_accounting, parse_time_unit_ms,
    scheduled_arrivals_in_window)

ROOT = Path("/workspace")
OUT_ROOT = ROOT / "perf-results" / "capacity-search"
COMPOSE = ["docker", "compose", "-f", "docker-compose.perf.yml"]
MAX_POINTS = 6

ISOLATED_DEFAULTS = {
    "cap_client_credentials": 4000,
    "cap_authorization_code": 800,
    "cap_refresh_token": 2000,
    "fapi2_logged_in_high_security": 240,
    "cap_introspect": 4000,
    "cap_revoke": 700,
    "mtls_client_credentials": 2000,
    "par_signed_request_object": 2000,
    "cap_mixed": 2500,
}

SCENARIO_MAP = {name: name for name in ISOLATED_DEFAULTS}


def deployment_id() -> str:
    out = subprocess.run(
        ["docker", "exec", "nazoauth-perf-valkey-1", "valkey-cli", "keys", "nazo:state:v1:*"],
        capture_output=True, text=True, check=True,
    ).stdout.splitlines()
    key = next((k for k in out if k.strip()), "")
    return key.split(":")[3] if key.count(":") >= 4 else "unknown"


def run_isolated(scenario: str, rate: int, out_dir: Path, duration: str) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    # `compose run` only forwards variables declared in the service's
    # environment: block or passed via -e; process env alone is NOT enough.
    overrides = {
        "PERF_RESULTS_DIR": "/out",
        "PERF_REPORT_PATH": "/out/report.md",
        "PERF_TENANT_HOST": "127.0.0.1:8000",
        "PERF_DEPLOYMENT_ID": deployment_id(),
        "PERF_PROFILE": "capacity",
        "PERF_SCENARIO": scenario,
        "PERF_EXECUTOR": "constant-arrival-rate",
        "PERF_RATE": str(rate),
        "PERF_PRE_ALLOCATED_VUS": os.environ.get("CAP_PRE_VUS", "256"),
        "PERF_MAX_VUS": os.environ.get("CAP_MAX_VUS", "1024"),
        "PERF_DURATION": duration,
        "CAP_WARMUP_MS": "15000",
        "PERF_USER_COUNT": str(max(256, min(rate, 4096))),
        "PERF_VECTOR_COUNT": os.environ.get("PERF_VECTOR_COUNT", "2000"),
    }
    cmd = COMPOSE + ["run", "--rm", "--no-deps"]
    for key, value in overrides.items():
        cmd += ["-e", f"{key}={value}"]
    cmd += ["-v", f"{out_dir}:/out", "perf"]
    log = out_dir / "run.log"
    with log.open("w") as handle:
        subprocess.run(cmd, cwd=ROOT, stdout=handle, stderr=subprocess.STDOUT, check=False)
    return out_dir / "latest.json"


def run_mixed(rate: int, run_id: str, duration_s: int) -> Path:
    env = os.environ.copy()
    env.update(
        {
            "RUN_ID": run_id,
            "SOAK_RATE": str(rate),
            "SOAK_DURATION": f"{duration_s}s",
            # Sidecars start ~120s after main; end them ~60s before main does
            # so each writes its summary instead of being docker-stop killed.
            "SOAK_SIDE_DURATION": f"{max(60, duration_s - 180)}s",
            "SOAK_AUDIT": "1",
        }
    )
    log = ROOT / "perf-results" / run_id / "driver.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("w") as handle:
        subprocess.run(
            ["bash", "perf/tools/soak_run.sh"],
            cwd=ROOT, env=env, stdout=handle, stderr=subprocess.STDOUT, check=False,
        )
    return ROOT / "perf-results" / run_id / "main" / "latest.json"


def load_summary(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return None
    if isinstance(data, list) and data:
        return data[0].get("result", data[0])
    if isinstance(data, dict):
        return data.get("result", data)
    return None


def k6_metrics(summary_path: Path) -> tuple[dict, dict]:
    """Load the raw k6 summary export next to latest.json for counters that
    runner.py does not project (err_classified, err_expected_invalid_grant),
    plus the emitted measurement contract. Returns (metrics, contract)."""
    for cand in summary_path.parent.glob("*.k6.json"):
        try:
            data = json.loads(cand.read_text())
        except json.JSONDecodeError:
            continue
        metrics = data.get("metrics", data)
        if isinstance(metrics, dict) and "iterations" in metrics or "cap_measure_ops" in metrics:
            return metrics, (data.get("measurement_contract") or {})
    return {}, {}


def _count(metrics: dict, name: str) -> float:
    entry = metrics.get(name, {})
    values = entry.get("values", entry) if isinstance(entry, dict) else {}
    return float(values.get("count", 0) or 0)


CAP_RUN_MARKERS = ("cap_measure_ops", "cap_iter_begin",
                   "cap_window_measure_start_ms")
CONTRACT_REQUIRED = ("window_start_ms", "window_end_ms",
                     "scenario_start_ms", "duration_ms")


def contract_validity(contract: dict | None) -> list[str]:
    """Strict contract check shared by every evaluator path. Any missing
    bound field, clock_ok != 1, divergent VUs or an empty/inverted window
    makes the contract invalid — no fallback denominator is ever
    substituted."""
    if not contract:
        return ["missing_contract"]
    problems = []
    for f in CONTRACT_REQUIRED:
        if contract.get(f) is None:
            problems.append(f"missing:{f}")
    if contract.get("scenario_clock_ok") != 1:
        problems.append("scenario_clock_ok!=1")
    if contract.get("divergent_vus"):
        problems.append("divergent_vus")
    ws = contract.get("window_start_ms")
    we = contract.get("window_end_ms")
    if ws is not None and we is not None and ws >= we:
        problems.append("window_start>=window_end")
    if contract.get("contract") != "cap-scenario-window-v1":
        problems.append("unknown_contract")
    if contract.get("window_seconds") is None and not problems:
        problems.append("missing:window_seconds")
    return problems


# Evidence tiers for stream artifacts (mirrors checkpoint_analyze):
#   AUTHORITATIVE — formal verdicts depend on series.json (per-second
#   begins/ends/drops/VU/latency aggregates), window.json (window contract,
#   exact measurement cohort, parse/reader validity) and the k6 summary.
#   FORENSIC/OPTIONAL — diag.jsonl.gz, a bounded sampled point log for
#   manual debugging. It is NOT a gate input: truncation records a
#   FORENSIC_DIAG_STATUS caveat, never an INVALID.
# Any missing authoritative piece means the run cannot produce
# stream-authoritative cohort evidence — fail closed, never fall back to
# summary counters in that mode.
STREAM_ARTIFACT_SUFFIXES = (
    "series.json", "window.json", "analyzer-stats.json")
FORENSIC_STREAM_SUFFIX = "diag.jsonl.gz"


def stream_evidence(summary_path: Path) -> dict:
    """Load and validate the stream-side measurement evidence next to a
    runner summary. `measurement_cohort` inside window.json carries the
    exact observed begin/end/drop counts; `valid` aggregates artifact
    presence + analyzer health + window/cohort internal consistency.
    `forensic_diag` reports the optional diag artifact's status — it is
    projected for reporting only and never contributes to `valid`."""
    d = summary_path.parent
    files: dict[str, Path] = {}
    missing: list[str] = []
    for suf in STREAM_ARTIFACT_SUFFIXES:
        matches = sorted(d.glob(f"*{suf}"))
        if matches:
            files[suf] = matches[0]
        else:
            missing.append(suf)
    diag_files = sorted(d.glob(f"*{FORENSIC_STREAM_SUFFIX}"))
    if diag_files:
        files[FORENSIC_STREAM_SUFFIX] = diag_files[0]
    out: dict = {"artifacts_complete": not missing, "missing": missing,
                 "files": {k: str(v) for k, v in files.items()},
                 "problems": [f"missing:{s}" for s in missing],
                 "measurement_cohort": None, "valid": False}
    win: dict = {}
    stats: dict = {}
    if "window.json" in files:
        try:
            win = json.loads(files["window.json"].read_text())
        except (OSError, json.JSONDecodeError) as e:
            out["problems"].append(f"window_unreadable:{e}")
    if "analyzer-stats.json" in files:
        try:
            stats = json.loads(files["analyzer-stats.json"].read_text())
        except (OSError, json.JSONDecodeError) as e:
            out["problems"].append(f"stats_unreadable:{e}")
    if files:
        if win.get("valid") is not True:
            out["problems"].append(
                f"window_invalid:{';'.join(map(str, win.get('problems') or []))}")
        if stats.get("parse_errors"):
            out["problems"].append(f"parse_errors:{stats['parse_errors']}")
        if stats.get("reader_error"):
            out["problems"].append(f"reader_error:{stats['reader_error']}")
        # Evidence-pipeline integrity: the analyzer drains a FIFO that
        # mechanically backpressures k6's writer once it fills. A lagging
        # consumer is therefore evidence-pipeline invalidity — NOT a
        # forensic-artifact caveat and NOT a generator-resource fault.
        if stats.get("lag_over_5s"):
            out["problems"].append(
                f"evidence_pipeline_lag_over_5s:{stats['lag_over_5s']}")
            out["evidence_pipeline_invalid"] = True
        mc = win.get("measurement_cohort") if isinstance(win, dict) else None
        out["measurement_cohort"] = mc
        if "window.json" in files:
            if not isinstance(mc, dict):
                out["problems"].append("measurement_cohort_missing")
            elif mc.get("valid") is not True:
                out["problems"].append(
                    "cohort_invalid:"
                    + ";".join(map(str, mc.get("problems") or [])))
    out["stats"] = stats
    out["window_problems"] = win.get("problems")
    # Forensic tier: diag.jsonl.gz truncation (or absence) is reported,
    # never gated. StreamingSeries counts every authoritative fact before
    # the diag keep decision, so a budget cut cannot alter cohort truth.
    out["forensic_diag"] = {
        "status": ("ABSENT" if not diag_files
                   else ("TRUNCATED" if stats.get("diag_overflow")
                         else "COMPLETE")),
        "truncated": bool(stats.get("diag_overflow")),
        "budget_exceeded_points": stats.get("diag_budget_exceeded"),
        "overflow_dropped_points": stats.get("diag_overflow_dropped"),
        "logical_bytes_cap": stats.get("max_diag_bytes"),
        "file": str(diag_files[0]) if diag_files else None,
    }
    out["valid"] = (out["artifacts_complete"] and not out["problems"])
    return out


# Generator-local failure signatures in the k6 container's run.log. These
# are injector-side resource faults — ephemeral-port/fd exhaustion, OOM,
# k6 panics — never SUT responses (dial timeouts to the SUT are NOT in
# this list: they can equally be SUT overload and are not evidence).
GENERATOR_LOG_SIGNATURES = (
    "cannot assign requested address",
    "too many open files",
    "no buffer space available",
    "out of memory",
    "panic:",
)


def injector_vu_cap_reached(metrics_raw: dict) -> bool | None:
    """Diagnostic: did the k6 VU pool reach the configured maxVUs? This
    fact alone is NOT generator-resource evidence — arrival-rate drops
    also appear when the SUT slows and occupies each VU longer (Little's
    law). True/False when both numbers exist, else None."""
    vmax_entry = metrics_raw.get("vus_max", {})
    vmax = (vmax_entry.get("values", vmax_entry) or {}).get("max")
    cap = int(os.environ.get("CAP_MAX_VUS", "0") or 0)
    if not cap or vmax is None:
        return None
    return float(vmax) >= cap


def generator_resource_evidence(summary_path: Path, metrics_raw: dict,
                                generator_facts: dict | None
                                ) -> list[str]:
    """Independent evidence that the load GENERATOR ran out of resources
    or crashed — required before a point may be classified
    LOAD_GENERATOR_RESOURCE_INVALID. Accepted sources: generator-local
    log signatures and harness-supplied facts (container OOMKilled,
    abnormal exit). vus_max reaching the configured cap is deliberately
    NOT here — see injector_vu_cap_reached. Analyzer findings are also
    excluded by class: a lagging stream consumer is evidence-pipeline
    invalidity (checked in stream_evidence), and a truncated forensic
    diag artifact is a reporting caveat — neither is a generator
    resource fault."""
    ev: list[str] = []
    log = summary_path.parent / "run.log"
    if log.exists():
        try:
            text = log.read_text(errors="replace")
        except OSError:
            text = ""
        for sig in GENERATOR_LOG_SIGNATURES:
            if sig in text:
                ev.append(f"run.log: {sig!r}")
    facts = generator_facts or {}
    if facts.get("oom_killed"):
        ev.append("generator container OOMKilled")
    if facts.get("cpu_throttled"):
        ev.append("generator CPU throttled")
    exit_code = facts.get("exit_code")
    # k6 exits 99 on threshold breach — a *result*, not a generator
    # fault. Any other non-zero exit on a completed run is abnormal.
    if (facts.get("load_status") == "completed"
            and str(exit_code) not in ("None", "0", "99")):
        ev.append(f"k6 abnormal exit_code={exit_code}")
    return ev


def evaluate(summary: dict | None, summary_path: Path, target: int,
             duration_s: int, label: str,
             generator_facts: dict | None = None,
             require_stream: bool = False) -> tuple[str, dict]:
    if summary is None:
        return "FAIL", {"reason": "no_summary"}
    k6 = summary.get("k6", {})
    metrics_raw, contract = k6_metrics(summary_path)
    dropped = int(k6.get("dropped_iterations", 0) or 0)
    completed = int(k6.get("iterations_completed", 0) or 0)
    cohort = completed + dropped
    drop_fraction = dropped / cohort if cohort else 0.0
    latency = k6.get("latency_ms", {})
    p95 = float(latency.get("p95", 0) or 0)
    p99 = float(latency.get("p99", 0) or 0)
    error_rate = float(k6.get("error_rate", 0) or 0)
    status = summary.get("status", "")
    # capRun identity comes from the emitted cap_* markers alone. A
    # measurement_contract shell with all-null bounds (attached to every
    # scenario by older handleSummary code) does NOT make a scenario
    # capRun; the contract only validates a scenario the markers already
    # identified as one.
    is_caprun = any(m in metrics_raw for m in CAP_RUN_MARKERS)
    # When the run produced stream-side measurement evidence, its own
    # integrity is part of validity: an invalid window, reader error or
    # parse errors cannot be waved through just because the summary
    # counters look fine. Scenarios that never ran the evidence mode
    # carry no measurement_evidence and skip this gate.
    mev = summary.get("measurement_evidence")
    if isinstance(mev, dict):
        ev_problems = []
        if mev.get("window_valid") is False:
            ev_problems.append("stream_window_invalid")
        if mev.get("reader_error"):
            ev_problems.append(f"reader_error:{mev['reader_error']}")
        if mev.get("parse_errors"):
            ev_problems.append(f"parse_errors:{mev['parse_errors']}")
        if ev_problems:
            return "INVALID", {
                "reason": "measurement_evidence_invalid",
                "evidence_problems": ev_problems,
                "status": status}
    problems = contract_validity(contract) if is_caprun else []
    acct: dict | None = None
    scohort: dict | None = None
    late_vu_fraction: float | None = None
    if is_caprun:
        if problems:
            return "INVALID", {
                "reason": "missing_or_inconsistent_measurement_contract",
                "contract_problems": problems,
                "contract": contract, "status": status}
        # Stream evidence policy: formal/stability points REQUIRE the
        # analyzer artifacts (require_stream). Whenever complete artifacts
        # exist, their integrity is part of validity and the exact
        # observed cohort replaces counter-derived accounting. Runs that
        # never produced stream artifacts keep the legacy counter path —
        # only when stream evidence is not required.
        sev = stream_evidence(summary_path)
        if sev["artifacts_complete"]:
            if not sev["valid"]:
                return "INVALID", {
                    "reason": ("evidence_pipeline_invalid"
                               if sev.get("evidence_pipeline_invalid")
                               else "stream_evidence_invalid"),
                    "evidence_problems": sev["problems"],
                    "forensic_diag": sev.get("forensic_diag"),
                    "status": status}
            scohort = dict(sev["measurement_cohort"])
        elif require_stream:
            return "INVALID", {
                "reason": "stream_evidence_missing",
                "missing": sev["missing"], "status": status}
        window_s = float(contract["window_seconds"])
        if scohort is not None:
            # Exact stream cohort — the authoritative gate population.
            # started/completed/dropped are observed on the point stream
            # and classified inside [window_start, window_end); the
            # rational arrival plan is diagnostic-only here.
            ws_s = scohort.get("window_start_s")
            we_s = scohort.get("window_end_s")
            if not (isinstance(ws_s, (int, float))
                    and isinstance(we_s, (int, float))):
                return "INVALID", {
                    "reason": "stream_window_bounds_missing",
                    "status": status}
            # Stream bounds and the summary contract derive from the same
            # emitted gauges — disagreement means the two evidence
            # sources conflict; never pick one silently.
            if (abs(ws_s * 1000 - float(contract["window_start_ms"])) > 1
                    or abs(we_s * 1000
                           - float(contract["window_end_ms"])) > 1):
                return "INVALID", {
                    "reason": "stream_contract_window_mismatch",
                    "stream_window_s": [ws_s, we_s],
                    "contract_window_ms": [contract["window_start_ms"],
                                           contract["window_end_ms"]],
                    "status": status}
            started = int(scohort["measure_started_exact"])
            completed = int(scohort["measure_completed_exact"])
            measure_dropped = int(scohort["measure_dropped_exact"])
            scheduled_obs = int(scohort["measure_scheduled_observed"])
            if started != completed:
                return "INVALID", {
                    "reason": "unfinished_measurement",
                    "measure_started": started,
                    "measure_completed": completed,
                    "status": status}
            stream_outcomes = scohort.get("measure_outcomes") or {}
            outcome_sum = int(scohort.get("measure_outcome_sum") or 0)
            if outcome_sum != completed:
                return "INVALID", {
                    "reason": "outcome_sum_mismatch",
                    "outcome_sum": outcome_sum,
                    "completed": completed,
                    "status": status}
            if scheduled_obs <= 0:
                return "INVALID", {"reason": "scheduled_observed_zero",
                                   "status": status}
            measured_ops_s = completed / window_s
            successful_ops_s = (stream_outcomes.get("success", 0)
                                / window_s)
            basis = "scenario_window_stream"
            measure_drop_fraction = measure_dropped / scheduled_obs
            observed_schedule_rate = scheduled_obs / window_s
            # Rational arrival plan: diagnostic only. Its delta vs the
            # observed schedule documents executor behaviour and never
            # feeds any formal gate.
            planned = scheduled_arrivals_in_window(
                contract.get("scenario_start_ms"),
                contract.get("window_start_ms"),
                contract.get("window_end_ms"), target,
                parse_time_unit_ms(
                    (summary.get("load_model") or {}).get("time_unit")
                    or os.environ.get("PERF_TIME_UNIT", "1s")),
                contract.get("duration_ms"))
            scohort["rational_planned_arrivals"] = planned
            scohort["schedule_delta_vs_rational"] = (
                scheduled_obs - planned if planned is not None else None)
            scohort["observed_schedule_rate"] = round(
                observed_schedule_rate, 3)
            # A materially off-target observed schedule means the
            # generator did not run the registered load — INVALID
            # evidence, not an SUT capacity result. The 0.5% bound is a
            # diagnostic guard, not an SUT gate.
            if abs(observed_schedule_rate / target - 1) > 0.005:
                return "INVALID", {
                    "reason": "generator_schedule_anomaly",
                    "observed_schedule_rate": round(
                        observed_schedule_rate, 3),
                    "target": target,
                    "measure_scheduled_observed": scheduled_obs,
                    "status": status}
            # Named outcome counters and the stream's cohort|lw|outcome
            # tags describe the same events — they must agree exactly.
            gate_unexpected = int(
                stream_outcomes.get("unexpected_error", 0))
            named_unexp = int(
                _count(metrics_raw, "cap_measure_unexpected"))
            if gate_unexpected != named_unexp:
                return "INVALID", {
                    "reason": "outcome_counter_mismatch",
                    "stream_unexpected": gate_unexpected,
                    "counter_unexpected": named_unexp,
                    "status": status}
            gate_lat = _trend(metrics_raw, "cap_iter_ms")
            gate_p95 = gate_lat["p95"]
            gate_p99 = gate_lat["p99"]
            late_vu = _count(metrics_raw, "cap_iter_begin_late_vu")
            late_vu_fraction = late_vu / started if started else None
            if (isinstance(late_vu_fraction, float)
                    and late_vu_fraction > 0.001):
                return "LOAD_MODEL_INVALID", {
                    "reason": "late_vu_fraction_over_0.1pct",
                    "late_vu_fraction": round(late_vu_fraction, 6),
                    "late_vu_iterations": int(late_vu),
                    "status": status,
                    "rate_basis": basis,
                    "measurement_contract": contract.get("contract"),
                    "measure": dict(scohort)}
        else:
            ops = _count(metrics_raw, "cap_measure_ops")
            success = _count(metrics_raw, "cap_measure_success")
            # A legitimate zero-arrival window evaluates as 0 ops/s —
            # still on the contract basis, never a fallback denominator.
            measured_ops_s = ops / window_s
            successful_ops_s = success / window_s
            basis = "scenario_window"
            # Legacy counter-path accounting: the theoretical arrival
            # grid remains the drop reference here ONLY because these
            # runs carry no stream evidence. The boundary allowance is a
            # non-gating legacy artifact kept for historical parity.
            acct = cohort_accounting(
                metrics_raw, contract, target,
                parse_time_unit_ms(
                    (summary.get("load_model") or {}).get("time_unit")
                    or os.environ.get("PERF_TIME_UNIT", "1s")))
            if not acct["valid"]:
                m_out = {
                    "reason": "measurement_cohort_invalid",
                    "cohort_problems": acct["problems"],
                    "status": status,
                    "rate_basis": basis,
                    "window_seconds": window_s,
                    "measured_ops_s": round(measured_ops_s, 3),
                    "measurement_contract": contract.get("contract")}
                m_out.update({k: acct[k] for k in (
                    "scheduled", "started", "completed", "unfinished",
                    "dropped", "drop_fraction")})
                return "INVALID", m_out
            measure_drop_fraction = acct["drop_fraction_upper"]
            gate_unexpected = acct["unexpected"]
            gate_lat = acct["iter_latency_ms"]
            gate_p95 = gate_lat["p95"]
            gate_p99 = gate_lat["p99"]
            # Runtime VU bootstrap inside the measurement window is
            # load-model noise, not capacity signal — a fully
            # preallocated run must have essentially none of it.
            late_vu = _count(metrics_raw, "cap_iter_begin_late_vu")
            late_vu_fraction = (late_vu / acct["started"]
                                if acct["started"] else None)
            if (isinstance(late_vu_fraction, float)
                    and late_vu_fraction > 0.001):
                return "LOAD_MODEL_INVALID", {
                    "reason": "late_vu_fraction_over_0.1pct",
                    "late_vu_fraction": round(late_vu_fraction, 6),
                    "late_vu_iterations": int(late_vu),
                    "status": status,
                    "rate_basis": basis,
                    "measurement_contract": contract.get("contract"),
                    "measure": {k: acct[k] for k in (
                        "scheduled", "started", "completed", "dropped",
                        "drop_fraction")}}
    else:
        # Non-capRun scenarios emit no post-warmup cohort counters: only a
        # whole-scenario total is recoverable, so the rate is presented on
        # a full-scenario basis — not as a post-warmup measurement.
        window_s = float(duration_s)
        measured_ops_s = completed / window_s if window_s else None
        successful_ops_s = measured_ops_s
        basis = "full_scenario"
        measure_drop_fraction = None
        gate_p95, gate_p99 = p95, p99
    classified = _count(metrics_raw, "err_classified")
    expected_invalid_grant = _count(metrics_raw, "err_expected_invalid_grant")
    unexpected = (gate_unexpected if is_caprun
                  else classified - expected_invalid_grant)
    metrics = {
        "rps": float(k6.get("rps", 0) or 0),
        "p50": float(latency.get("p50", 0) or 0), "p95": p95,
        "p99": p99, "dropped": dropped, "drop_fraction": drop_fraction,
        "error_rate": error_rate, "status": status,
        "measured_ops_s": (round(measured_ops_s, 3)
                           if measured_ops_s is not None else None),
        "successful_ops_s": (round(successful_ops_s, 3)
                             if successful_ops_s is not None else None),
        "window_seconds": window_s,
        "rate_basis": basis,
        "measurement_contract": contract.get("contract"),
        "classified_errors": int(classified),
        "expected_invalid_grant": int(expected_invalid_grant),
        "unexpected_errors": int(unexpected),
    }
    if is_caprun and scohort is not None:
        metrics["measure"] = dict(scohort)
        metrics["measure"]["cohort_source"] = "k6_stream_exact"
        metrics["measure"]["late_vu_fraction"] = (
            round(late_vu_fraction, 6)
            if isinstance(late_vu_fraction, float) else None)
        metrics["subject_lifecycle"] = {
            k: int(_count(metrics_raw, f"cap_subject_{k}"))
            for k in ("initial_mint", "refresh_update", "expired_reauth")}
        metrics["gate_population"] = "measurement_cohort"
        metrics["gate_p95"] = gate_p95
        metrics["gate_p99"] = gate_p99
    elif is_caprun and acct is not None:
        metrics["measure"] = {k: acct[k] for k in (
            "scheduled", "started", "completed", "unfinished",
            "schedule_delta", "dropped", "drop_fraction",
            "drop_lower_bound", "drop_upper_bound",
            "drop_fraction_upper", "boundary_overshoot",
            "pre_measure_drops_estimate",
            "iter_latency_ms", "outcomes")}
        metrics["measure"]["cohort_source"] = "counter_legacy"
        metrics["measure"]["late_vu_fraction"] = (
            round(late_vu_fraction, 6)
            if isinstance(late_vu_fraction, float) else None)
        metrics["subject_lifecycle"] = {
            k: int(_count(metrics_raw, f"cap_subject_{k}"))
            for k in ("initial_mint", "refresh_update", "expired_reauth")}
        metrics["gate_population"] = "measurement_cohort"
        metrics["gate_p95"] = gate_p95
        metrics["gate_p99"] = gate_p99
    # Injector VU-cap is a diagnostic fact, never invalidity evidence by
    # itself: drops at the cap can equally mean the SUT slowed and held
    # VUs longer. Recorded whenever the numbers exist.
    if is_caprun:
        ivc = injector_vu_cap_reached(metrics_raw)
        if ivc is not None:
            metrics["injector_vu_cap_reached"] = ivc
        # Forensic tier projection: diag truncation is a report caveat,
        # never part of the authoritative validity computed above.
        if scohort is not None or sev.get("artifacts_complete"):
            metrics["forensic_diag"] = sev.get("forensic_diag")
    # Load-generator attribution: any measurement-window drop above the
    # formal bound triggers the generator-evidence check. Only INDEPENDENT
    # generator-resource evidence (OOM, throttle, analyzer lag/overflow,
    # local socket/fd exhaustion, abnormal k6 exit) produces
    # LOAD_GENERATOR_RESOURCE_INVALID — drops never attribute themselves.
    gate_drop = (measure_drop_fraction if is_caprun
                 else drop_fraction)
    if gate_drop is not None and gate_drop > 0.001 and unexpected == 0:
        ev = generator_resource_evidence(
            summary_path, metrics_raw, generator_facts)
        metrics["load_generator_evidence"] = ev or "absent"
        if ev:
            return "LOAD_GENERATOR_RESOURCE_INVALID", metrics
    # cap_mixed deliberately exercises the bounded-family cap: an evicted
    # refresh token answers invalid_grant, which is the *correct* response.
    # Its cascade (a VU whose token was evicted fails fast) counts in
    # cap_measure_errors without any HTTP error. For cap_mixed the capacity
    # question is "did the SUT keep pace with arrivals", so the gate uses the
    # full measured rate; for every other scenario an op failure is real and
    # the gate uses the successful-only rate.
    rate_for_gate = measured_ops_s if label == "cap_mixed" else successful_ops_s
    # For capRun the gate reads the measurement cohort only. k6 thresholds
    # (http_req_duration p99<5s, checks>0.99, http_req_failed<1%) are
    # whole-run health guardrails kept as diagnostics: a warmup-only breach
    # cannot override a clean measurement window, while process crashes,
    # stream parse failures and invalid contracts are INVALID/FAIL above.
    # Runner's `target_miss` status fires on ANY drop or <99% http rps,
    # which is stricter than the formal gate — not a gate input either.
    if is_caprun:
        ok = (
            measure_drop_fraction is not None
            and measure_drop_fraction <= 0.001
            and rate_for_gate is not None
            and rate_for_gate >= target * 0.995
            and unexpected == 0
            and gate_p95 <= 100
            and gate_p99 <= 250
        )
    else:
        ok = (
            status != "threshold_failed"
            and drop_fraction <= 0.001
            and rate_for_gate is not None
            and rate_for_gate >= target * 0.995
            and unexpected == 0
            and p95 <= 100
            and p99 <= 250
        )
    metrics["rate_for_gate"] = (round(rate_for_gate, 3)
                              if rate_for_gate is not None else None)
    metrics["threshold_status_diagnostic"] = status
    return ("PASS" if ok else "FAIL"), metrics


def search(label: str, initial: int, duration_s: int = 600) -> dict:
    scen = SCENARIO_MAP.get(label, label)
    out_base = OUT_ROOT / label
    out_base.mkdir(parents=True, exist_ok=True)
    ledger_path = out_base / "search-ledger.jsonl"
    target = initial
    passed: list[tuple[int, dict]] = []
    failed: list[tuple[int, dict]] = []
    invalid: dict | None = None
    points = 0
    while points < MAX_POINTS:
        points += 1
        if label == "cap_mixed":
            run_id = f"capsearch-mixed-{target}rps-{int(time.time())}"
            summary_path = run_mixed(target, run_id, duration_s)
        else:
            summary_path = run_isolated(
                scen, target, out_base / f"r{target}", f"{duration_s}s"
            )
        verdict, metrics = evaluate(
            load_summary(summary_path), summary_path, target, duration_s, label
        )
        metrics["target"] = target
        metrics["verdict"] = verdict
        metrics["summary"] = str(summary_path)
        with ledger_path.open("a") as handle:
            handle.write(json.dumps(metrics) + "\n")
        print(f"[{label}] point {points}: target={target} verdict={verdict} "
              f"rps={metrics.get('rps')} p95={metrics.get('p95')} p99={metrics.get('p99')} "
              f"drops={metrics.get('dropped')} err={metrics.get('error_rate')}", flush=True)
        if verdict == "INVALID":
            # Measurement itself is broken: the point cannot enter
            # FIRST_FAIL_ABOVE and the ladder must not keep probing.
            print(f"[{label}] INVALID at {target}: {metrics.get('reason')}; "
                  "search aborted", flush=True)
            invalid = metrics
            break
        if verdict == "LOAD_GENERATOR_RESOURCE_INVALID":
            print(f"[{label}] generator resource invalid at {target}; point excluded", flush=True)
            continue
        if verdict == "LOAD_MODEL_INVALID":
            print(f"[{label}] load model invalid at {target}; search aborted", flush=True)
            invalid = metrics
            break
        if verdict == "PASS":
            passed.append((target, metrics))
            if failed:
                break
            target = int(target * 1.25)
        else:
            failed.append((target, metrics))
            if passed:
                highest_pass = max(r for r, _ in passed)
                lowest_fail = min(r for r, _ in failed)
                midpoint = (highest_pass + lowest_fail) // 2
                if midpoint in {r for r, _ in passed + failed}:
                    break
                target = midpoint
            else:
                target = max(1, int(target / 1.25))
    highest = max(passed, default=(0, {}), key=lambda item: item[0])
    first_fail = min((r for r, _ in failed), default=None)
    result = {
        "scenario": label,
        "mapped_scenario": scen,
        "duration_s": duration_s,
        "points": points,
        "invalid": invalid,
        "max_10m_pass": highest[0] or None,
        "max_10m_pass_metrics": highest[1] or None,
        "first_fail_above": first_fail,
        "ledger": str(ledger_path),
    }
    (out_base / "result.json").write_text(json.dumps(result, indent=2))
    print(f"[{label}] DONE max_10m_pass={result['max_10m_pass']} first_fail={first_fail}", flush=True)
    return result


def main() -> None:
    args = sys.argv[1:]
    duration_s = int(os.environ.get("CAP_POINT_DURATION_S", "600"))
    results = {}
    i = 0
    while i < len(args):
        label = args[i]
        initial = int(args[i + 1]) if i + 1 < len(args) and args[i + 1].isdigit() else ISOLATED_DEFAULTS[label]
        i += 2 if i + 1 < len(args) and args[i + 1].isdigit() else 1
        results[label] = search(label, initial, duration_s)
    print(json.dumps({k: {"max_10m_pass": v["max_10m_pass"], "first_fail_above": v["first_fail_above"]} for k, v in results.items()}, indent=2))


if __name__ == "__main__":
    main()
