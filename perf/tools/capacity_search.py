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


def k6_metrics(summary_path: Path) -> dict:
    """Load the raw k6 summary export next to latest.json for counters that
    runner.py does not project (err_classified, err_expected_invalid_grant)."""
    for cand in summary_path.parent.glob("*.k6.json"):
        try:
            data = json.loads(cand.read_text())
        except json.JSONDecodeError:
            continue
        metrics = data.get("metrics", data)
        if isinstance(metrics, dict) and "iterations" in metrics or "cap_measure_ops" in metrics:
            return metrics
    return {}


def _count(metrics: dict, name: str) -> float:
    entry = metrics.get(name, {})
    values = entry.get("values", entry) if isinstance(entry, dict) else {}
    return float(values.get("count", 0) or 0)


def evaluate(summary: dict | None, summary_path: Path, target: int,
             duration_s: int, label: str) -> tuple[str, dict]:
    if summary is None:
        return "FAIL", {"reason": "no_summary"}
    k6 = summary.get("k6", {})
    measure = k6.get("measure", {}) or {}
    metrics_raw = k6_metrics(summary_path)
    dropped = int(k6.get("dropped_iterations", 0) or 0)
    completed = int(k6.get("iterations_completed", 0) or 0)
    cohort = completed + dropped
    drop_fraction = dropped / cohort if cohort else 0.0
    latency = k6.get("latency_ms", {})
    p95 = float(latency.get("p95", 0) or 0)
    p99 = float(latency.get("p99", 0) or 0)
    error_rate = float(k6.get("error_rate", 0) or 0)
    status = summary.get("status", "")
    # Successful rate is measured over the post-warmup window only: the k6
    # counter rate divides by total elapsed, which systematically under-reads
    # by warmup_ms/elapsed.
    # Measure window = point duration minus the 15s warmup; using
    # elapsed_seconds would fold k6 startup/teardown into the divisor and
    # systematically under-read the attained rate by ~1%.
    warmup_s = 15.0
    window_s = max(1.0, duration_s - warmup_s)
    ops = _count(metrics_raw, "cap_measure_ops")
    measure_errors = _count(metrics_raw, "cap_measure_errors")
    measured_ops_s = ops / window_s if ops else float(measure.get("ops_per_s", 0) or 0)
    successful_ops_s = (ops - measure_errors) / window_s if ops else 0.0
    if not ops:
        # Non-capRun scenarios (fapi2_*, mtls_client_credentials,
        # par_signed_request_object, metadata_jwks) do not emit cap_measure_*:
        # one iteration == one flow, so the attained rate is completed
        # iterations per post-warmup second; correctness is gated by
        # err_classified below.
        measured_ops_s = completed / window_s
        successful_ops_s = measured_ops_s
    classified = _count(metrics_raw, "err_classified")
    expected_invalid_grant = _count(metrics_raw, "err_expected_invalid_grant")
    unexpected = classified - expected_invalid_grant
    metrics = {
        "rps": float(k6.get("rps", 0) or 0),
        "p50": float(latency.get("p50", 0) or 0), "p95": p95,
        "p99": p99, "dropped": dropped, "drop_fraction": drop_fraction,
        "error_rate": error_rate, "status": status,
        "measured_ops_s": round(measured_ops_s, 3),
        "successful_ops_s": round(successful_ops_s, 3),
        "classified_errors": int(classified),
        "expected_invalid_grant": int(expected_invalid_grant),
        "unexpected_errors": int(unexpected),
    }
    if status in {"threshold_failed"} and drop_fraction > 0.001 and unexpected == 0:
        return "LOAD_GENERATOR_INVALID", metrics
    # cap_mixed deliberately exercises the bounded-family cap: an evicted
    # refresh token answers invalid_grant, which is the *correct* response.
    # Its cascade (a VU whose token was evicted fails fast) counts in
    # cap_measure_errors without any HTTP error. For cap_mixed the capacity
    # question is "did the SUT keep pace with arrivals", so the gate uses the
    # full measured rate; for every other scenario an op failure is real and
    # the gate uses the successful-only rate.
    rate_for_gate = measured_ops_s if label == "cap_mixed" else successful_ops_s
    # Runner's `target_miss` status fires on ANY drop or <99% http rps, which
    # is stricter than the formal gate (drops<=0.1%, ops>=99.5%). Gate on the
    # measured metrics directly; only a k6 threshold breach is an auto-FAIL.
    ok = (
        status != "threshold_failed"
        and drop_fraction <= 0.001
        and rate_for_gate >= target * 0.995
        and unexpected == 0
        and p95 <= 100
        and p99 <= 250
    )
    metrics["rate_for_gate"] = round(rate_for_gate, 3)
    return ("PASS" if ok else "FAIL"), metrics


def search(label: str, initial: int, duration_s: int = 600) -> dict:
    scen = SCENARIO_MAP.get(label, label)
    out_base = OUT_ROOT / label
    out_base.mkdir(parents=True, exist_ok=True)
    ledger_path = out_base / "search-ledger.jsonl"
    target = initial
    passed: list[tuple[int, dict]] = []
    failed: list[tuple[int, dict]] = []
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
        if verdict == "LOAD_GENERATOR_INVALID":
            print(f"[{label}] load-generator saturated at {target}; point excluded", flush=True)
            continue
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
