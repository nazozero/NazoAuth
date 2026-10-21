#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "perf" / "results"
DOCS = RESULTS / "reports"
SUFFIX_SCENARIO = {
    "token-only": "token_only_client_credentials",
    "oidc-cold-login": "oidc_cold_login_refresh",
    "oidc-logged-in": "oidc_logged_in_authorization_code",
    "oidc-refresh-only": "oidc_refresh_only",
    "fapi2-full-security": "fapi2_full_security",
}


def load_capacity_module():
    spec = importlib.util.spec_from_file_location("capacity_report", ROOT / "perf" / "capacity.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load perf/capacity.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def markdown_table(rows: list[tuple[str, str]]) -> str:
    lines = ["| Field | Value |", "| --- | --- |"]
    lines.extend(f"| {field} | {value} |" for field, value in rows)
    return "\n".join(lines)


def recorded_values(data, field):
    return ", ".join(sorted({str(point.get(field) or "UNAVAILABLE") for point in data})) or "UNAVAILABLE"


def evidence_block(*, suffix: str, data: list) -> str:
    rows = [
        ("Source commit", "UNAVAILABLE (not recorded by this legacy producer)"),
        ("Runner architecture", "UNAVAILABLE"),
        ("CPU set", "UNAVAILABLE"),
        ("Capacity scenarios", recorded_values(data, "scenario")),
        ("Duration per point", recorded_values(data, "duration")),
        ("Recorded instance stages", recorded_values(data, "instances")),
        ("Recorded target rates", recorded_values(data, "target_rate")),
        ("Matrix completeness", "UNVERIFIED (no registered matrix manifest)"),
        ("Results JSON", f"[source](../data/dev/{suffix}.json)"),
    ]
    return "## Evidence\n\n" + markdown_table(rows) + "\n\n"


def insert_evidence(source: str, evidence: str) -> str:
    source = re.sub(
        r"\n## Test Environment(?: and Topology)?\n\n\| Field \| Value \|\n\| --- \| --- \|\n(?:\| .* \| .* \|\n)+\n",
        "\n",
        source,
    )
    source = re.sub(r"\n## Notes\n\n(?:- .*\n)+", "\n", source)
    marker = "\n## Run Configuration\n"
    if marker in source:
        return source.replace(marker, "\n" + evidence + "## Run Configuration\n", 1)
    return source.rstrip() + "\n\n" + evidence


def finalize_report(*, capacity, suffix: str, scenario: str, expected_points: int | None = None) -> None:
    results_path = RESULTS / "data" / "dev" / f"{suffix}.json"
    report_path = DOCS / f"performance-capacity-curve-dev-{suffix}.md"
    if not results_path.exists():
        print(f"skip {suffix}: missing {results_path}")
        return
    data = capacity.json.loads(results_path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise SystemExit(f"{suffix}: expected list results, got {type(data).__name__}")
    if expected_points is not None and len(data) != expected_points:
        raise SystemExit(f"{suffix}: expected {expected_points} recorded points, got {len(data)}")
    capacity.write_report(data, duration=recorded_values(data, "duration"), report_path=report_path, results_path=results_path)
    source = report_path.read_text(encoding="utf-8")
    source = insert_evidence(source, evidence_block(suffix=suffix, data=data))
    report_path.write_text(source, encoding="utf-8", newline="\n")
    print(f"finalized {report_path}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-points", type=int, help="Optional explicit record count; does not prove matrix coverage.")
    args = parser.parse_args()

    capacity = load_capacity_module()
    for suffix, scenario in SUFFIX_SCENARIO.items():
        finalize_report(capacity=capacity, suffix=suffix, scenario=scenario, expected_points=args.expected_points)


if __name__ == "__main__":
    main()
