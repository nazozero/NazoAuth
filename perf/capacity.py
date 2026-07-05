#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "perf" / "results"
DEFAULT_CAPACITY_RESULTS = RESULTS_DIR / "capacity-latest.json"
DEFAULT_CAPACITY_REPORT = ROOT / "docs" / "performance-capacity-curve.md"

DEFAULT_RATES: dict[str, list[int]] = {
    "token_only_client_credentials": [1000, 2500, 5000, 7500, 10000],
    "oidc_cold_login_refresh": [16, 32, 64, 128, 256],
    "oidc_logged_in_authorization_code": [16, 32, 64, 128, 256],
    "oidc_refresh_only": [250, 500, 1000, 1500, 2000],
    "fapi2_full_security": [16, 32, 64, 128, 256],
    "mtls_client_credentials": [250, 500, 1000, 1500, 2000],
    "par_signed_request_object": [250, 500, 1000, 1500, 2000],
    "introspect_opaque_refresh_token": [16, 32, 64, 128, 256],
    "authorize_par_session": [16, 32, 64, 128, 256],
    "revoke_refresh_token": [16, 32, 64, 128, 256],
    "metadata_jwks": [250, 500, 1000, 1500, 2000],
    "same_user_refresh_token_rotation": [8, 16, 32, 64, 128],
    "same_user_introspect_opaque_refresh_token": [8, 16, 32, 64, 128],
    "same_user_authorize_par_session": [8, 16, 32, 64, 128],
}


def parse_csv_ints(value: str) -> list[int]:
    return [int(item.strip()) for item in value.split(",") if item.strip()]


def parse_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def run_command(command: list[str], env: dict[str, str]) -> None:
    completed = subprocess.run(command, cwd=ROOT, env=env, text=True)
    if completed.returncode != 0:
        raise RuntimeError(f"command failed with exit code {completed.returncode}: {' '.join(command)}")


def compose_project_name(env: dict[str, str]) -> str:
    value = env.get("COMPOSE_PROJECT_NAME", "nazoauth-perf").lower()
    value = re.sub(r"[^a-z0-9_-]+", "-", value).strip("-_")
    if not value or not value[0].isalnum():
        return "nazoauth-perf"
    return value[:63]


def compose_command(env: dict[str, str], *args: str) -> list[str]:
    compose_files = ["-f", "docker-compose.perf.yml"]
    if env.get("PERF_COMPOSE_OVERRIDE"):
        compose_files.extend(["-f", env["PERF_COMPOSE_OVERRIDE"]])
    return [
        "docker",
        "compose",
        "-p",
        compose_project_name(env),
        *compose_files,
        *args,
    ]


def root_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT)).replace("\\", "/")
    except ValueError:
        return str(path)


def service_metric(result: dict[str, Any], service: str, metric: str) -> float:
    return float(result.get("containers", {}).get("by_service", {}).get(service, {}).get(metric, 0))


def postgres_metric(result: dict[str, Any], metric: str) -> float:
    return float(result.get("postgres", {}).get(metric, 0))


def db_pool_metric(result: dict[str, Any], metric: str) -> float:
    return float(result.get("db_pool", {}).get(metric, 0))


def valkey_hit_rate(result: dict[str, Any]) -> float:
    valkey = result.get("valkey", {})
    hits = float(valkey.get("keyspace_hits", 0))
    misses = float(valkey.get("keyspace_misses", 0))
    total = hits + misses
    return hits / total if total > 0 else 0


def step_rps(result: dict[str, Any], *steps: str) -> float:
    wanted = set(steps)
    return sum(float(step["rps"]) for step in result.get("steps", []) if step["step"] in wanted)


def app_cpu_cores(result: dict[str, Any]) -> float:
    return service_metric(result, "nazoauth", "cpu_percent_avg") / 100


def per_core(value: float, result: dict[str, Any]) -> float:
    cores = app_cpu_cores(result)
    return value / cores if cores > 0 else 0


def markdown_table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(str(value) for value in row) + " |")
    return lines


def write_report(results: list[dict[str, Any]], *, duration: str, report_path: Path, results_path: Path) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    generated_at = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    rows: list[list[Any]] = []
    step_rows: list[list[Any]] = []
    for item in results:
        result = item["result"]
        login_rps = step_rps(result, "login")
        token_rps = step_rps(
            result,
            "token_client_credentials",
            "mtls_client_credentials",
            "token_authorization_code",
            "token_refresh",
            "fapi_token_authorization_code",
            "fapi_token_refresh",
        )
        rows.append(
            [
                item["instances"],
                item["scenario"],
                item["target_rate"],
                f"{result['k6']['rps']:.3f}",
                f"{result['k6']['latency_ms']['p50']:.3f}",
                f"{result['k6']['latency_ms']['p95']:.3f}",
                f"{result['k6']['latency_ms']['p99']:.3f}",
                f"{result['k6']['error_rate']:.6f}",
                f"{app_cpu_cores(result):.3f}",
                f"{per_core(float(result['k6']['rps']), result):.3f}",
                f"{per_core(login_rps, result):.3f}",
                f"{per_core(token_rps, result):.3f}",
                f"{service_metric(result, 'postgres', 'cpu_percent_avg'):.3f}",
                f"{service_metric(result, 'valkey', 'cpu_percent_avg'):.3f}",
                f"{postgres_metric(result, 'mean_statement_ms'):.3f}",
                f"{postgres_metric(result, 'statements_per_http_request'):.3f}",
                f"{db_pool_metric(result, 'wait_ms_avg'):.3f}",
                f"{db_pool_metric(result, 'wait_ms_max_observed_process_lifetime'):.3f}",
                f"{valkey_hit_rate(result):.6f}",
                result.get("valkey", {}).get("keyspace_hits", 0),
                result.get("valkey", {}).get("keyspace_misses", 0),
            ]
        )
        for step in result.get("steps", []):
            step_rows.append(
                [
                    item["instances"],
                    item["scenario"],
                    item["target_rate"],
                    step["step"],
                    step["http_reqs"],
                    f"{step['rps']:.3f}",
                    f"{step['latency_ms']['p50']:.3f}",
                    f"{step['latency_ms']['p95']:.3f}",
                    f"{step['latency_ms']['p99']:.3f}",
                    f"{step['error_rate']:.6f}",
                ]
            )
    lines = [
        "# NazoAuth Capacity Curve Benchmarks",
        "",
        f"Generated at: `{generated_at}`",
        "",
        "This report is generated by `perf/capacity.py`. It uses fixed arrival-rate k6 scenarios and can run the same traffic profile against 1, 2, and 4 NazoAuth replicas.",
        "",
        "## Run Configuration",
        "",
        *markdown_table(
            ["Setting", "Value"],
            [
                ["Duration per point", duration],
                ["Executor", "constant-arrival-rate"],
                ["Results JSON", display_path(results_path)],
            ],
        ),
        "",
        "## Capacity Curve",
        "",
        *markdown_table(
            [
                "Instances",
                "Scenario",
                "Target Rate",
                "Observed HTTP RPS",
                "p50 ms",
                "p95 ms",
                "p99 ms",
                "Error Rate",
                "App CPU Cores Avg",
                "HTTP RPS/App CPU Core",
                "Login RPS/App CPU Core",
                "Token RPS/App CPU Core",
                "Postgres CPU Avg %",
                "Valkey CPU Avg %",
                "Postgres Mean Statement ms",
                "DB Statements/HTTP Req",
                "DB Pool Wait Avg ms",
                "DB Pool Wait Max ms",
                "Valkey Hit Rate",
                "Valkey Hits",
                "Valkey Misses",
            ],
            rows,
        ),
        "",
        "## Step Breakdown",
        "",
        *markdown_table(
            ["Instances", "Scenario", "Target Rate", "Step", "Requests", "RPS", "p50 ms", "p95 ms", "p99 ms", "Error Rate"],
            step_rows,
        ),
        "",
        "## Notes",
        "",
        "- `oidc_cold_login_refresh` includes a fresh Argon2 password login in every flow.",
        "- `oidc_logged_in_authorization_code` keeps a session per VU after warm-up and measures authorization-code work without per-flow password verification.",
        "- `oidc_refresh_only` performs one per-VU bootstrap flow, then measures refresh rotation only; the bootstrap cost is negligible in sustained 30 minute runs but visible in short smoke tests.",
        "- Per-core normalization uses observed Docker CPU percent for the NazoAuth service: 100% equals one effective CPU core.",
        "",
    ]
    report_path.write_text("\n".join(lines), encoding="utf-8")


def run_point(*, scenario: str, rate: int, duration: str, instances: int, max_vus: int) -> dict[str, Any]:
    env = os.environ.copy()
    cnb_build = env.get("CNB_BUILD_ID", "")
    cnb_pipeline = env.get("CNB_PIPELINE_KEY", "")
    report_suffix = env.get("CAPACITY_REPORT_SUFFIX", scenario)
    if cnb_build and "COMPOSE_PROJECT_NAME" not in env:
        env["COMPOSE_PROJECT_NAME"] = f"nazoauth-{cnb_build}-{cnb_pipeline or report_suffix}"
    env.update(
        {
            "PERF_PROFILE": "capacity",
            "PERF_SCENARIO": scenario,
            "PERF_EXECUTOR": "constant-arrival-rate",
            "PERF_RATE": str(rate),
            "PERF_TIME_UNIT": "1s",
            "PERF_DURATION": duration,
            "PERF_VUS": str(max(16, min(max_vus, rate * 2))),
            "PERF_FLOW_VUS": str(max(16, min(max_vus, rate * 2))),
            "PERF_PRE_ALLOCATED_VUS": str(max(16, min(max_vus, rate * 2))),
            "PERF_MAX_VUS": str(max_vus),
            "PERF_USER_COUNT": str(max(max_vus, 64)),
            "PERF_VECTOR_COUNT": os.environ.get("PERF_VECTOR_COUNT", "1000"),
            "PERF_APP_REPLICAS": str(instances),
        }
    )
    point_results_dir = RESULTS_DIR / compose_project_name(env)
    point_results_dir.mkdir(parents=True, exist_ok=True)
    env["PERF_RESULTS_HOST_DIR"] = "./" + str(point_results_dir.relative_to(ROOT)).replace("\\", "/")
    env["PERF_REPORT_PATH"] = "/results/performance-benchmarks.md"
    down = compose_command(env, "down", "-v", "--remove-orphans")
    run_command(down, env)
    try:
        command = compose_command(
            env,
            "up",
            "--build",
            "--scale",
            f"nazoauth={instances}",
            "--abort-on-container-exit",
            "--exit-code-from",
            "perf",
        )
        run_command(command, env)
        latest = json.loads((point_results_dir / "latest.json").read_text(encoding="utf-8"))
        if len(latest) != 1:
            raise RuntimeError(f"capacity point expected one result, got {len(latest)}")
        result = {
            "instances": instances,
            "scenario": scenario,
            "target_rate": rate,
            "duration": duration,
            "result": latest[0],
        }
        safe_name = f"capacity-{instances}x-{scenario}-{rate}rps"
        (RESULTS_DIR / f"{safe_name}.summary.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        return result
    finally:
        run_command(down, env)


def point_key(point: dict[str, Any]) -> tuple[int, str, int] | None:
    try:
        return (
            int(point["instances"]),
            str(point["scenario"]),
            int(point["target_rate"]),
        )
    except (KeyError, TypeError, ValueError):
        return None


def load_existing_results(results_path: Path) -> list[dict[str, Any]]:
    if not results_path.exists():
        return []
    data = json.loads(results_path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise RuntimeError(f"capacity results must be a JSON array: {results_path}")
    results: list[dict[str, Any]] = []
    for item in data:
        if not isinstance(item, dict):
            raise RuntimeError(f"capacity result item must be an object: {results_path}")
        if point_key(item) is None:
            raise RuntimeError(f"capacity result item is missing point identity: {results_path}")
        results.append(item)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Run NazoAuth fixed arrival-rate capacity curves.")
    parser.add_argument("--duration", default="30m")
    parser.add_argument("--instances", default="1,2,4", help="Comma-separated NazoAuth replica counts.")
    parser.add_argument("--scenarios", default=",".join(DEFAULT_RATES), help="Comma-separated capacity scenarios.")
    parser.add_argument("--rates", default="", help="Comma-separated rates applied to every selected scenario.")
    parser.add_argument("--report-path", default=str(DEFAULT_CAPACITY_REPORT))
    parser.add_argument("--results-path", default=str(DEFAULT_CAPACITY_RESULTS))
    parser.add_argument("--max-vus", type=int, default=512)
    parser.add_argument("--smoke", action="store_true", help="Use a short, low-rate matrix for toolchain validation.")
    args = parser.parse_args()

    if args.smoke:
        args.duration = "20s"
        instances = [1, 2]
        scenario_rates = {
            "token_only_client_credentials": [50],
            "oidc_refresh_only": [5],
        }
        args.max_vus = 64
    else:
        instances = parse_csv_ints(args.instances)
        selected = parse_csv(args.scenarios)
        explicit_rates = parse_csv_ints(args.rates) if args.rates else []
        scenario_rates = {
            scenario: explicit_rates or DEFAULT_RATES[scenario]
            for scenario in selected
        }

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    report_path = root_path(args.report_path)
    results_path = root_path(args.results_path)
    results = load_existing_results(results_path)
    completed = {key for item in results if (key := point_key(item)) is not None}
    if results:
        print(f"resuming capacity matrix with {len(results)} completed point(s) from {results_path}")
        write_report(results, duration=args.duration, report_path=report_path, results_path=results_path)
    for instance_count in instances:
        for scenario, rates in scenario_rates.items():
            for rate in rates:
                key = (instance_count, scenario, rate)
                if key in completed:
                    print(
                        f"skip completed capacity point: instances={instance_count} "
                        f"scenario={scenario} rate={rate}/s"
                    )
                    continue
                print(
                    f"capacity point: instances={instance_count} "
                    f"scenario={scenario} rate={rate}/s duration={args.duration}"
                )
                point = run_point(
                    scenario=scenario,
                    rate=rate,
                    duration=args.duration,
                    instances=instance_count,
                    max_vus=args.max_vus,
                )
                results.append(point)
                completed.add(key)
                results_path.parent.mkdir(parents=True, exist_ok=True)
                results_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
                write_report(results, duration=args.duration, report_path=report_path, results_path=results_path)


if __name__ == "__main__":
    main()
