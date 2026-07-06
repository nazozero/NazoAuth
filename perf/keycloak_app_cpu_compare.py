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


def parse_percent(value: str) -> float:
    return float(value.strip().rstrip("%") or 0)


def parse_memory_bytes(value: str) -> int:
    first = value.split("/")[0].strip()
    match = re.match(r"^([0-9.]+)([A-Za-z]+)$", first)
    if not match:
        return 0
    amount = float(match.group(1))
    unit = match.group(2).lower()
    factors = {
        "b": 1,
        "kib": 1024,
        "mib": 1024**2,
        "gib": 1024**3,
        "kb": 1000,
        "mb": 1000**2,
        "gb": 1000**3,
    }
    return int(amount * factors.get(unit, 1))


def command_output(command: list[str]) -> str:
    completed = subprocess.run(command, check=False, text=True, capture_output=True)
    if completed.returncode != 0:
        return "unknown"
    return completed.stdout.strip() or "unknown"


def metric_values(summary: dict[str, Any], name: str) -> dict[str, Any]:
    metric = summary.get("metrics", {}).get(name, {})
    if isinstance(metric.get("values"), dict):
        return metric["values"]
    return metric


def metric_rate(values: dict[str, Any]) -> float:
    return float(values.get("rate", values.get("value", 0)))


def k6_result(summary_path: Path) -> dict[str, Any]:
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    duration = metric_values(summary, "http_req_duration")
    failed = metric_values(summary, "http_req_failed")
    requests = metric_values(summary, "http_reqs")
    checks = metric_values(summary, "checks")
    step_duration = metric_values(summary, "http_req_duration{step:token_client_credentials}")
    step_failed = metric_values(summary, "http_req_failed{step:token_client_credentials}")
    step_requests = metric_values(summary, "http_reqs{step:token_client_credentials}") or requests
    return {
        "rps": round(float(requests.get("rate", 0)), 3),
        "requests": int(requests.get("count", 0)),
        "latency_ms": {
            "p50": round(float(duration.get("p(50)", 0)), 3),
            "p95": round(float(duration.get("p(95)", 0)), 3),
            "p99": round(float(duration.get("p(99)", 0)), 3),
            "max": round(float(duration.get("max", 0)), 3),
        },
        "error_rate": round(metric_rate(failed), 6),
        "check_rate": round(metric_rate(checks), 6),
        "steps": {
            "token_client_credentials": {
                "requests": int(step_requests.get("count", 0)),
                "rps": round(float(step_requests.get("rate", 0)), 3),
                "latency_ms": {
                    "p50": round(float(step_duration.get("p(50)", 0)), 3),
                    "p95": round(float(step_duration.get("p(95)", 0)), 3),
                    "p99": round(float(step_duration.get("p(99)", 0)), 3),
                },
                "error_rate": round(metric_rate(step_failed), 6),
            }
        },
    }


def classify_service(name: str) -> str | None:
    if "-keycloak-postgres-" in name or name.endswith("-keycloak-postgres-1"):
        return "keycloak-postgres"
    if "-keycloak-" in name or name.endswith("-keycloak-1"):
        return "keycloak"
    return None


def docker_stats(stats_path: Path) -> dict[str, Any]:
    samples: dict[str, list[dict[str, float]]] = {}
    if not stats_path.exists():
        return {"by_service": {}}
    for line in stats_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        raw = json.loads(line)
        name = raw.get("Name") or raw.get("Name".lower()) or raw.get("Container") or ""
        service = classify_service(name)
        if not service:
            continue
        samples.setdefault(service, []).append(
            {
                "cpu_percent": parse_percent(raw.get("CPUPerc", "0%")),
                "memory_bytes": parse_memory_bytes(raw.get("MemUsage", "0B / 0B")),
            }
        )
    by_service: dict[str, Any] = {}
    for service, values in samples.items():
        cpu_values = [item["cpu_percent"] for item in values]
        memory_values = [item["memory_bytes"] for item in values]
        by_service[service] = {
            "samples": len(values),
            "cpu_percent_avg": round(sum(cpu_values) / len(cpu_values), 3) if cpu_values else 0,
            "cpu_percent_max": round(max(cpu_values), 3) if cpu_values else 0,
            "memory_bytes_avg": int(sum(memory_values) / len(memory_values)) if memory_values else 0,
            "memory_bytes_max": max(memory_values) if memory_values else 0,
        }
    return {"by_service": by_service}


def load_nazoauth(path: Path) -> dict[int, dict[str, Any]]:
    rows = json.loads(path.read_text(encoding="utf-8"))
    return {int(row["target_rate"]): row for row in rows}


def environment(args: argparse.Namespace) -> dict[str, str]:
    return {
        "Source commit": command_output(["git", "rev-parse", "HEAD"]),
        "Keycloak image": f"quay.io/keycloak/keycloak:{args.keycloak_image_tag}",
        "Runner tag": "cnb:arch:amd64",
        "Observed logical CPUs": command_output(["sh", "-c", "nproc --all 2>/dev/null || echo unknown"]),
        "Process allowed CPUs": command_output(
            ["sh", "-c", "awk -F':\\t' '/Cpus_allowed_list/ { print $2; exit }' /proc/self/status 2>/dev/null || echo unknown"]
        ),
        "Observed CPU model": command_output(
            ["sh", "-c", "awk -F': ' '/model name/ { print $2; exit }' /proc/cpuinfo 2>/dev/null | sed 's/|/-/g' || echo unknown"]
        ),
        "Cgroup CPU max": command_output(["sh", "-c", "cat /sys/fs/cgroup/cpu.max 2>/dev/null || echo unknown"]),
        "Memory total": command_output(
            ["sh", "-c", "awk '/MemTotal/ { printf \"%.2f GiB\", $2 / 1024 / 1024 }' /proc/meminfo 2>/dev/null || echo unknown"]
        ),
        "Workspace disk available": command_output(["sh", "-c", "df -h . 2>/dev/null | awk 'NR==2 { print $4 \" on \" $6 }' || echo unknown"]),
        "Docker server": command_output(["sh", "-c", "docker version --format '{{.Server.Version}}' 2>/dev/null || echo unknown"]),
        "Docker compose": command_output(["sh", "-c", "docker compose version --short 2>/dev/null || echo unknown"]),
        "Compose file": "docker-compose.keycloak.perf.yml",
        "App CPU quota": str(args.app_cpus),
        "Infra CPU model": "PostgreSQL and k6 are not CPU-quota limited by this benchmark override.",
        "Duration per point": args.duration,
        "Rates": ",".join(str(rate) for rate in args.rates),
    }


def markdown_table(headers: list[str], rows: list[list[Any]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(str(value) for value in row) + " |")
    return "\n".join(lines)


def write_report(args: argparse.Namespace, results: list[dict[str, Any]], env: dict[str, str]) -> None:
    nazo = load_nazoauth(args.nazoauth_results)
    env_rows = [[key, value] for key, value in env.items()]
    keycloak_rows: list[list[Any]] = []
    compare_rows: list[list[Any]] = []
    rates_text = ", ".join(str(rate) for rate in args.rates)
    for row in results:
        keycloak = row["keycloak"]
        keycloak_cpu = row["containers"]["by_service"].get("keycloak", {}).get("cpu_percent_avg", 0) / 100
        postgres_cpu = row["containers"]["by_service"].get("keycloak-postgres", {}).get("cpu_percent_avg", 0)
        per_core = round(keycloak["rps"] / keycloak_cpu, 3) if keycloak_cpu else 0
        keycloak_rows.append(
            [
                row["target_rate"],
                row["status"],
                f"{keycloak['rps']:.3f}",
                f"{keycloak['latency_ms']['p50']:.3f}",
                f"{keycloak['latency_ms']['p95']:.3f}",
                f"{keycloak['latency_ms']['p99']:.3f}",
                f"{keycloak['error_rate']:.6f}",
                f"{keycloak_cpu:.3f}",
                f"{per_core:.3f}",
                f"{postgres_cpu:.3f}",
            ]
        )
        nazo_row = nazo.get(int(row["target_rate"]))
        if nazo_row:
            nazo_result = nazo_row["result"]
            nazo_k6 = nazo_result["k6"]
            nazo_cpu = nazo_result["containers"]["by_service"].get("nazoauth", {}).get("cpu_percent_avg", 0) / 100
            nazo_per_core = round(nazo_k6["rps"] / nazo_cpu, 3) if nazo_cpu else 0
            ratio = round(nazo_k6["rps"] / keycloak["rps"], 3) if keycloak["rps"] else 0
            efficiency_ratio = round(nazo_per_core / per_core, 3) if per_core else 0
            compare_rows.append(
                [
                    row["target_rate"],
                    f"{nazo_k6['rps']:.3f}",
                    f"{nazo_k6['latency_ms']['p95']:.3f}",
                    f"{nazo_k6['latency_ms']['p99']:.3f}",
                    f"{nazo_cpu:.3f}",
                    f"{nazo_per_core:.3f}",
                    f"{keycloak['rps']:.3f}",
                    f"{keycloak['latency_ms']['p95']:.3f}",
                    f"{keycloak['latency_ms']['p99']:.3f}",
                    f"{keycloak_cpu:.3f}",
                    f"{per_core:.3f}",
                    f"{ratio:.3f}x",
                    f"{efficiency_ratio:.3f}x",
                ]
            )

    source = [
        "# NazoAuth vs Keycloak App-CPU 1 vCPU Benchmark",
        "",
        f"Generated at: `{datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}`",
        "",
        "This report compares only the `client_credentials` token endpoint path under a single application CPU quota. It is not a full OAuth/OIDC feature comparison.",
        "",
        "## Test Environment and Topology",
        "",
        markdown_table(["Field", "Value"], env_rows),
        "",
        "## Method",
        "",
        f"- NazoAuth result source: `{args.nazoauth_results}`.",
        f"- Keycloak result source: `{args.results_path}`.",
        f"- Both sides use fixed-arrival-rate k6 traffic and the same target rates: {rates_text} requests per second.",
        "- Keycloak runs with PostgreSQL and a Docker CPU quota of 1 CPU on the Keycloak container only. PostgreSQL and k6 are intentionally left unrestricted, matching the NazoAuth app-CPU smoke-test shape.",
        "- The comparison uses HTTP RPS, p50/p95/p99 latency, error rate, and observed application CPU from Docker stats.",
        "",
        "## Behavior and Fairness Audit",
        "",
        "- Both benchmark clients use `grant_type=client_credentials`, confidential client authentication by `client_secret_post`, and request `scope=profile`.",
        "- Both benchmark assertions require HTTP 200 and an access token in the token response; refresh tokens are not expected for this grant.",
        "- Both services issue JWT access tokens in this path, but token claim sets, subject modeling, signing implementation, and default OIDC mappers are implementation-specific and are not forced to be byte-equivalent.",
        "- NazoAuth verifies the benchmark client secret through its `client-secret-v1:<salt>:<HMAC-SHA256>` digest format. Keycloak uses its own confidential-client secret handling. This benchmark compares endpoint behavior and observed resource usage, not identical credential storage internals.",
        "- The load generator, network shape, application CPU quota, and database-unrestricted topology are aligned. Product scope is not aligned: Keycloak remains a broad IAM server, while this benchmark exercises only the narrow token endpoint path.",
        "",
        "## Keycloak Result",
        "",
        markdown_table(
            [
                "Target Rate",
                "Status",
                "HTTP RPS",
                "p50 ms",
                "p95 ms",
                "p99 ms",
                "Error Rate",
                "Keycloak CPU Cores Avg",
                "HTTP RPS/App CPU Core",
                "Postgres CPU Avg %",
            ],
            keycloak_rows,
        ),
        "",
        "## Comparison",
        "",
        markdown_table(
            [
                "Target Rate",
                "NazoAuth RPS",
                "NazoAuth p95 ms",
                "NazoAuth p99 ms",
                "NazoAuth CPU Cores Avg",
                "NazoAuth RPS/App Core",
                "Keycloak RPS",
                "Keycloak p95 ms",
                "Keycloak p99 ms",
                "Keycloak CPU Cores Avg",
                "Keycloak RPS/App Core",
                "Observed RPS Ratio",
                "App-Core Efficiency Ratio",
            ],
            compare_rows,
        ),
        "",
        "## Interpretation",
        "",
        "- This benchmark is suitable for checking the single-core token endpoint order of magnitude, but it does not replace the 30-minute sustained capacity matrix.",
        "- The tested rates are fixed arrival-rate targets. When both systems meet the target, observed RPS is target-limited and should not be interpreted as maximum throughput.",
        "- Under target-limited points, latency and HTTP RPS per observed application CPU core are the more meaningful comparison fields.",
        "- Keycloak is a broad IAM product with administrative, realm, federation, theme, and policy surfaces that are outside this narrow endpoint test.",
        "- The test intentionally avoids TLS, clustering, external caches, custom providers, and production Keycloak tuning so that the result remains simple and reproducible.",
        "",
    ]
    args.report_path.write_text("\n".join(source), encoding="utf-8", newline="\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--summary-dir", type=Path, default=Path("perf/results"))
    parser.add_argument("--results-path", type=Path, required=True)
    parser.add_argument("--report-path", type=Path, required=True)
    parser.add_argument("--nazoauth-results", type=Path, required=True)
    parser.add_argument("--suffix", default="keycloak-app-cpu-1vcpu-smoke")
    parser.add_argument("--duration", default="2m")
    parser.add_argument("--rates", required=True)
    parser.add_argument("--app-cpus", default="1")
    parser.add_argument("--keycloak-image-tag", default="26.6.4")
    args = parser.parse_args()
    args.rates = [int(value) for value in args.rates.split(",") if value.strip()]

    results: list[dict[str, Any]] = []
    for rate in args.rates:
        summary_path = args.summary_dir / f"{args.suffix}-{rate}.summary.json"
        stats_path = args.summary_dir / f"{args.suffix}-{rate}.docker-stats.ndjson"
        k6 = k6_result(summary_path)
        status = (
            "passed"
            if k6["error_rate"] < 0.01 and k6["check_rate"] >= 0.99 and k6["latency_ms"]["p99"] < 5000
            else "failed"
        )
        results.append(
            {
                "target_rate": rate,
                "duration": args.duration,
                "status": status,
                "keycloak": k6,
                "containers": docker_stats(stats_path),
            }
        )

    args.results_path.write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    env = environment(args)
    write_report(args, results, env)


if __name__ == "__main__":
    main()
