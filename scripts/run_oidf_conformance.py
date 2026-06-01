#!/usr/bin/env python3
"""Run OpenID Foundation conformance plans with repository-owned input checks."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path


DEFAULT_PLAN_EXPRESSIONS = [
    "oidcc-basic-certification-test-plan oidf-plan-config.json",
    "oidcc-config-certification-test-plan oidf-plan-config.json",
    "fapi2-security-profile-final-test-plan[client_auth_type=private_key_jwt][fapi_profile=plain_fapi][fapi_request_method=unsigned][fapi_response_mode=plain_response][sender_constrain=dpop][openid=openid_connect] oidf-plan-config.json",
    "fapi2-message-signing-final-test-plan[client_auth_type=private_key_jwt][fapi_profile=plain_fapi][fapi_request_method=signed_non_repudiation][fapi_response_mode=plain_response][sender_constrain=dpop][openid=openid_connect] oidf-plan-config.json",
    "fapi2-security-profile-id2-test-plan[client_auth_type=private_key_jwt][fapi_profile=plain_fapi][fapi_request_method=unsigned][fapi_response_mode=plain_response][sender_constrain=dpop][openid=openid_connect] oidf-plan-config.json",
    "fapi2-message-signing-id1-test-plan[client_auth_type=private_key_jwt][fapi_profile=plain_fapi][fapi_request_method=signed_non_repudiation][fapi_response_mode=plain_response][sender_constrain=dpop][openid=openid_connect] oidf-plan-config.json",
]


def fail(message: str) -> None:
    raise SystemExit(message)


def non_empty_env(name: str) -> str:
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        fail(f"{name} is required")
    return value


def write_plan_config(suite_scripts: Path, file_name: str, env_name: str) -> Path:
    if Path(file_name).name != file_name:
        fail("--config-file-name must be a file name, not a path")
    raw_config = non_empty_env(env_name)
    try:
        parsed = json.loads(raw_config)
    except json.JSONDecodeError as exc:
        fail(f"{env_name} is not valid JSON: {exc}")
    if not isinstance(parsed, dict):
        fail(f"{env_name} must contain a JSON object")
    target = suite_scripts / file_name
    target.write_text(json.dumps(parsed, indent=2, sort_keys=True), encoding="utf-8")
    return target


def plan_expressions(raw_expression: str, env_name: str, config_name: str) -> list[str]:
    raw_plan_set = os.environ.get(env_name, "").strip()
    if raw_plan_set:
        try:
            parsed = json.loads(raw_plan_set)
        except json.JSONDecodeError as exc:
            fail(f"{env_name} is not valid JSON: {exc}")
        if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
            fail(f"{env_name} must contain a JSON array of plan expression strings")
        expressions = [item.strip() for item in parsed if item.strip()]
    elif raw_expression.strip():
        expressions = [raw_expression.strip()]
    else:
        expressions = DEFAULT_PLAN_EXPRESSIONS

    if not expressions:
        fail("at least one OIDF plan expression is required")
    for expression in expressions:
        parts = shlex.split(expression)
        if not parts:
            fail("OIDF plan expression must not be empty")
        if config_name not in parts:
            fail(f"OIDF plan expression must reference {config_name}: {expression}")
    return expressions


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Execute the official OpenID Foundation conformance-suite runner."
    )
    parser.add_argument("--suite-dir", required=True, help="Path to the cloned conformance-suite repository")
    parser.add_argument("--conformance-server", required=True, help="Base URL of the conformance suite")
    parser.add_argument("--plan-expression", default="", help="single run-test-plan.py plan expression")
    parser.add_argument("--plan-set-env", default="OIDF_PLAN_SET_JSON")
    parser.add_argument("--config-env", default="OIDF_PLAN_CONFIG_JSON")
    parser.add_argument("--config-file-name", default="oidf-plan-config.json")
    parser.add_argument("--token-env", default="OIDF_CONFORMANCE_TOKEN")
    parser.add_argument("--export-dir", default="")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--disable-ssl-verify", action="store_true")
    parser.add_argument("--list", action="store_true", help="list selected plans without running them")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    suite_dir = Path(args.suite_dir).resolve()
    suite_scripts = suite_dir / "scripts"
    runner = suite_scripts / "run-test-plan.py"
    if not runner.is_file():
        fail(f"official runner not found: {runner}")

    config_path = write_plan_config(suite_scripts, args.config_file_name, args.config_env)
    expressions = plan_expressions(args.plan_expression, args.plan_set_env, config_path.name)

    env = os.environ.copy()
    env["CONFORMANCE_SERVER"] = args.conformance_server
    env["CONFORMANCE_TOKEN"] = non_empty_env(args.token_env)
    if args.disable_ssl_verify:
        env["DISABLE_SSL_VERIFY"] = "1"

    command = [sys.executable, str(runner)]
    if args.list:
        command.append("--list")
    if args.export_dir:
        export_dir = Path(args.export_dir).resolve()
        export_dir.mkdir(parents=True, exist_ok=True)
        command.extend(["--export-dir", str(export_dir)])
    if args.verbose:
        command.append("--verbose")
    for expression in expressions:
        command.extend(shlex.split(expression))

    completed = subprocess.run(command, cwd=suite_scripts, env=env, check=False)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
