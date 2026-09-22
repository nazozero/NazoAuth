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
    env = os.environ.copy()
    env.update(
        {
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
    )
    log = out_dir / "run.log"
    with log.open("w") as handle:
        subprocess.run(
            COMPOSE + ["run", "--rm", "--no-deps", "-v", f"{out_dir}:/out", "perf"],
            cwd=ROOT, env=env, stdout=handle, stderr=subprocess.STDOUT, check=False,
        )
    return out_dir / "latest.json"


def run_mixed(rate: int, run_id: str, duration_s: int) -> Path:
    env = os.environ.copy()
    env.update(
        {
            "RUN_ID": run_id,
            "SOAK_RATE": str(rate),
            "SOAK_DURATION": f"{duration_s}s",
            "SOAK_SIDE_DURATION": f"{max(60, duration_s - 60)}s",
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


def evaluate(summary: dict | None, target: int) -> tuple[str, dict]:
    if summary is None:
        return "FAIL", {"reason": "no_summary"}
    k6 = summary.get("k6", {})
    rps = float(k6.get("rps", 0) or 0)
    dropped = int(k6.get("dropped_iterations", 0) or 0)
    completed = int(k6.get("iterations_completed", 0) or 0)
    cohort = completed + dropped
    drop_fraction = dropped / cohort if cohort else 0.0
    latency = k6.get("latency_ms", {})
    p95 = float(latency.get("p95", 0) or 0)
    p99 = float(latency.get("p99", 0) or 0)
    error_rate = float(k6.get("error_rate", 0) or 0)
    status = summary.get("status", "")
    metrics = {
        "rps": rps, "p50": float(latency.get("p50", 0) or 0), "p95": p95,
        "p99": p99, "dropped": dropped, "drop_fraction": drop_fraction,
        "error_rate": error_rate, "status": status,
    }
    if status in {"threshold_failed"} and drop_fraction > 0.001 and error_rate == 0:
        return "LOAD_GENERATOR_INVALID", metrics
    ok = (
        drop_fraction <= 0.001
        and rps >= target * 0.995
        and error_rate == 0
        and p95 <= 100
        and p99 <= 250
        and status == "passed"
    )
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
        verdict, metrics = evaluate(load_summary(summary_path), target)
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
