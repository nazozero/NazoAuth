#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from perf.tools.blackbox_contract import business_ops_per_second
RESULTS_DIR = ROOT / "perf" / "results"
DEFAULT_CAPACITY_RESULTS = RESULTS_DIR / "data" / "capacity" / "latest.json"
DEFAULT_CAPACITY_REPORT = RESULTS_DIR / "reports" / "performance-capacity-curve.md"

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


def db_pool_metric(result: dict[str, Any], metric: str) -> float | None:
    value = (result.get("db_pool") or {}).get(metric)
    return float(value) if value is not None else None

def db_pool_cell(result: dict[str, Any], metric: str) -> str:
    value = db_pool_metric(result, metric)
    return f"{value:.3f}" if value is not None else "UNAVAILABLE"


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


def target_ratio(result: dict[str, Any], target_rate: int) -> float | None:
    k6 = result.get("k6", {})
    target = k6.get("target_ops_per_s", target_rate)
    measured = business_ops_per_second(k6)
    return measured / target if measured is not None and target > 0 else None


def normalized_status(item: dict[str, Any]) -> str:
    result = item.get("result", {})
    if not isinstance(result, dict):
        return ""
    current = str(result.get("status", "passed"))
    if current in {"threshold_failed", "skipped_after_threshold_failure"}:
        return current
    target_rate = int(item.get("target_rate", 0) or 0)
    k6 = result.get("k6", {})
    ratio = target_ratio(result, target_rate)
    drop_fraction = (k6.get("measure") or {}).get("drop_fraction")
    # B4 pass band: unexpected failures = 0 handled elsewhere; arrival drops
    # tolerated only up to 0.1% of the arrival cohort.
    if target_rate > 0 and (ratio is None or drop_fraction is None):
        return "measurement_unavailable"
    if target_rate > 0 and (ratio < 0.99 or drop_fraction > 0.001):
        return "target_miss"
    return current


def normalize_result_statuses(results: list[dict[str, Any]]) -> None:
    for item in results:
        result = item.get("result", {})
        if isinstance(result, dict):
            result["status"] = normalized_status(item)
            result.setdefault("k6", {}).setdefault("dropped_iterations", 0)
            result["k6"].setdefault("dropped_per_s", 0)
            result["k6"].setdefault("drop_fraction", 0)
            ratio = target_ratio(result, int(item.get("target_rate", 0) or 0))
            result["k6"]["target_ops_ratio"] = round(ratio, 6) if ratio is not None else None


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
    normalize_result_statuses(results)
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
                result.get("status", "passed"),
                f"{result['k6']['rps']:.3f}",
                (f"{result['k6']['target_ops_ratio']:.3f}" if result['k6'].get('target_ops_ratio') is not None else "UNAVAILABLE"),
                result["k6"].get("dropped_iterations", 0),
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
                db_pool_cell(result, "wait_ms_avg"),
                db_pool_cell(result, "wait_ms_max_observed_process_lifetime"),
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
        "This report reads retained capacity records. Missing business-window or provenance evidence remains unavailable.",
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
                "Status",
                "Observed HTTP RPS",
                "Observed/Target",
                "Dropped Iterations",
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
    ]
    report_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Render retained capacity records offline; new load uses perf/tools/current_capacity.py.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--report-path", required=True)
    args = parser.parse_args()
    source, report = root_path(args.input), root_path(args.report_path)
    if source.resolve() == report.resolve():
        parser.error("report must not overwrite source evidence")
    records = json.loads(source.read_text())
    if not isinstance(records, list):
        parser.error("input must contain a capacity record list")
    durations = sorted({str(r.get("duration") or "UNAVAILABLE") for r in records})
    write_report(records, duration=", ".join(durations), report_path=report, results_path=source)

if __name__ == "__main__":
    main()
