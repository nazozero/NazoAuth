#!/usr/bin/env python3
"""Build an OIDF --rerun selector from the current plan state."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from run_oidf_conformance import (
    fetch_alias_plans,
    oidf_api_request,
    value_as_upper,
)


def fail(message: str) -> None:
    raise SystemExit(message)


def token_from_env_or_file(env_name: str, env_file: Path) -> str:
    value = os.environ.get(env_name)
    if value is not None and value.strip():
        return value.strip()

    if not env_file.is_file():
        fail(f"{env_name} is not set and {env_file} does not exist")

    prefix = f"{env_name}="
    for line in env_file.read_text(encoding="utf-8").splitlines():
        if line.startswith(prefix):
            value = line[len(prefix) :].strip()
            if value:
                return value
            break

    fail(f"{env_name} is not set in the environment or {env_file}")


def latest_alias_plan(base_url: str, token: str, alias: str) -> dict[str, object]:
    plans = fetch_alias_plans(base_url, token, {alias})
    if not plans:
        fail(f"no OIDF plan found for alias {alias}")
    return max(
        plans,
        key=lambda plan: str(plan.get("started") or plan.get("created") or ""),
    )


def plan_by_id(base_url: str, token: str, plan_id: str) -> dict[str, object]:
    start = 0
    length = 200
    while True:
        _, payload = oidf_api_request(
            "GET",
            base_url,
            "api/plan",
            token,
            query={"start": start, "length": length},
            expected_statuses={200},
        )
        if not isinstance(payload, dict):
            break
        plans = payload.get("data")
        if not isinstance(plans, list) or not plans:
            break
        for plan in plans:
            if isinstance(plan, dict) and plan.get("_id") == plan_id:
                return plan
        start += len(plans)
        total = payload.get("recordsTotal")
        if isinstance(total, int) and start >= total:
            break
    fail(f"no OIDF plan found with id {plan_id}")


def module_name(module: object) -> str:
    if not isinstance(module, dict):
        return "<invalid module>"
    name = module.get("testModule") or module.get("testName") or module.get("name")
    return name if isinstance(name, str) and name else "<unknown module>"


def module_instances(module: object) -> list[str]:
    if not isinstance(module, dict):
        return []
    instances = module.get("instances")
    if not isinstance(instances, list):
        return []
    return [instance for instance in instances if isinstance(instance, str) and instance]


def instance_needs_rerun(base_url: str, token: str, instance_id: str) -> tuple[bool, str]:
    status_code, info = oidf_api_request(
        "GET",
        base_url,
        f"api/info/{instance_id}",
        token,
        expected_statuses={200, 404},
    )
    if status_code == 404 or not isinstance(info, dict):
        return True, f"{instance_id}: missing info"

    status = value_as_upper(info.get("status"))
    result = value_as_upper(info.get("result"))
    error = info.get("error")

    if isinstance(error, str) and error.strip():
        return True, f"{instance_id}: error"
    if isinstance(error, dict) and error:
        return True, f"{instance_id}: structured error"
    if status != "FINISHED":
        return True, f"{instance_id}: status {status or '<empty>'}"
    if result != "PASSED":
        return True, f"{instance_id}: result {result or '<empty>'}"
    return False, f"{instance_id}: PASSED"


def rerun_selectors(
    base_url: str,
    token: str,
    plan: dict[str, object],
    runner_plan_number: int,
) -> list[tuple[str, str, str]]:
    modules = plan.get("modules")
    if not isinstance(modules, list) or not modules:
        fail("selected OIDF plan has no module list")

    instantiated_indexes = [
        index
        for index, module in enumerate(modules, start=1)
        if module_instances(module)
    ]
    first_instantiated_index = min(instantiated_indexes, default=1)

    selected: list[tuple[str, str, str]] = []
    for module_index, module in enumerate(modules, start=1):
        selector = f"{runner_plan_number}:{module_index}"
        name = module_name(module)
        instances = module_instances(module)
        if not instances:
            if module_index < first_instantiated_index:
                continue
            selected.append((selector, name, "not started"))
            continue

        reasons: list[str] = []
        needs_rerun = False
        for instance_id in instances:
            instance_needs, reason = instance_needs_rerun(base_url, token, instance_id)
            reasons.append(reason)
            needs_rerun = needs_rerun or instance_needs
        if needs_rerun:
            selected.append((selector, name, "; ".join(reasons)))

    return selected


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate official OIDF --rerun selectors for modules that are not "
            "FINISHED/PASSED in the selected plan."
        )
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--alias", help="select the latest plan with this config alias")
    target.add_argument("--plan-id", help="select a concrete OIDF plan id")
    parser.add_argument(
        "--conformance-server",
        default="https://www.certification.openid.net/",
        help="OIDF conformance server base URL",
    )
    parser.add_argument(
        "--token-env",
        default="OIDF_CONFORMANCE_TOKEN",
        help="environment variable containing the OIDF API token",
    )
    parser.add_argument(
        "--env-file",
        default=".env.oidf.local",
        help="local env file used when --token-env is not present",
    )
    parser.add_argument(
        "--runner-plan-number",
        type=int,
        default=1,
        help="official runner plan number prefix for plan:module selectors",
    )
    parser.add_argument(
        "--selector-only",
        action="store_true",
        help="print only the comma-separated selector",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.runner_plan_number <= 0:
        fail("--runner-plan-number must be positive")

    token = token_from_env_or_file(args.token_env, Path(args.env_file))
    plan = (
        plan_by_id(args.conformance_server, token, args.plan_id)
        if args.plan_id
        else latest_alias_plan(args.conformance_server, token, args.alias)
    )
    plan_id = plan.get("_id")
    if not isinstance(plan_id, str) or not plan_id:
        fail("selected OIDF plan does not include an id")

    selected = rerun_selectors(
        args.conformance_server,
        token,
        plan,
        args.runner_plan_number,
    )
    selector = ",".join(item[0] for item in selected)

    if args.selector_only:
        print(selector)
        return 0

    alias = None
    config = plan.get("config")
    if isinstance(config, dict):
        alias = config.get("alias")

    print(f"OIDF plan: {plan_id}")
    if isinstance(alias, str) and alias:
        print(f"OIDF alias: {alias}")
    print(f"Selected modules: {len(selected)}")
    for selector_item, name, reason in selected:
        print(f"{selector_item} {name} [{reason}]")
    print(f"OIDF_RERUN={selector}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
