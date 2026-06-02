#!/usr/bin/env python3
"""Run OpenID Foundation conformance plans with repository-owned input checks."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from urllib.parse import urlparse


OIDCC_CONFIG_FILE = "oidf-oidcc-plan-config.json"
FAPI_CONFIG_FILE = "oidf-fapi-plan-config.json"
OIDCC_BASIC_CONFIG_FILE = "oidf-oidcc-basic-plan-config.json"
OIDCC_CONFIG_CONFIG_FILE = "oidf-oidcc-config-plan-config.json"
FAPI_SECURITY_FINAL_CONFIG_FILE = "oidf-fapi-security-final-plan-config.json"
FAPI_MESSAGE_FINAL_CONFIG_FILE = "oidf-fapi-message-final-plan-config.json"
FAPI_SECURITY_ID2_CONFIG_FILE = "oidf-fapi-security-id2-plan-config.json"
FAPI_MESSAGE_ID1_CONFIG_FILE = "oidf-fapi-message-id1-plan-config.json"
OIDF_REVIEW_PLACEHOLDER_IMAGE = (
    "data:image/png;base64,"
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII="
)

DEFAULT_PLAN_EXPRESSIONS = [
    f"oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client] {OIDCC_CONFIG_FILE}",
    f"oidcc-config-certification-test-plan {OIDCC_CONFIG_FILE}",
    f"fapi2-security-profile-final-test-plan[client_auth_type=private_key_jwt][fapi_profile=plain_fapi][sender_constrain=dpop][openid=openid_connect] {FAPI_CONFIG_FILE}",
    f"fapi2-message-signing-final-test-plan[client_auth_type=private_key_jwt][fapi_profile=plain_fapi][fapi_request_method=signed_non_repudiation][fapi_response_mode=plain_response][sender_constrain=dpop][openid=openid_connect] {FAPI_CONFIG_FILE}",
    f"fapi2-security-profile-id2-test-plan[client_auth_type=private_key_jwt][fapi_profile=plain_fapi][sender_constrain=dpop][openid=openid_connect] {FAPI_CONFIG_FILE}",
    f"fapi2-message-signing-id1-test-plan[client_auth_type=private_key_jwt][fapi_profile=plain_fapi][fapi_request_method=signed_non_repudiation][fapi_response_mode=plain_response][sender_constrain=dpop][openid=openid_connect] {FAPI_CONFIG_FILE}",
]
PER_PLAN_CONFIG_EXPRESSIONS = [
    f"oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client] {OIDCC_BASIC_CONFIG_FILE}",
    f"oidcc-config-certification-test-plan {OIDCC_CONFIG_CONFIG_FILE}",
    f"fapi2-security-profile-final-test-plan[client_auth_type=private_key_jwt][fapi_profile=plain_fapi][sender_constrain=dpop][openid=openid_connect] {FAPI_SECURITY_FINAL_CONFIG_FILE}",
    f"fapi2-message-signing-final-test-plan[client_auth_type=private_key_jwt][fapi_profile=plain_fapi][fapi_request_method=signed_non_repudiation][fapi_response_mode=plain_response][sender_constrain=dpop][openid=openid_connect] {FAPI_MESSAGE_FINAL_CONFIG_FILE}",
    f"fapi2-security-profile-id2-test-plan[client_auth_type=private_key_jwt][fapi_profile=plain_fapi][sender_constrain=dpop][openid=openid_connect] {FAPI_SECURITY_ID2_CONFIG_FILE}",
    f"fapi2-message-signing-id1-test-plan[client_auth_type=private_key_jwt][fapi_profile=plain_fapi][fapi_request_method=signed_non_repudiation][fapi_response_mode=plain_response][sender_constrain=dpop][openid=openid_connect] {FAPI_MESSAGE_ID1_CONFIG_FILE}",
]


def fail(message: str) -> None:
    raise SystemExit(message)


def non_empty_env(name: str) -> str:
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        fail(f"{name} is required")
    return value


def validate_config_file_name(file_name: str) -> None:
    if Path(file_name).name != file_name:
        fail("--config-file-name must be a file name, not a path")


def issuer_from_discovery_url(discovery_url: str) -> str | None:
    suffix = "/.well-known/openid-configuration"
    if not discovery_url.endswith(suffix):
        return None
    issuer = discovery_url[: -len(suffix)].rstrip("/")
    if not issuer:
        return None
    parsed = urlparse(issuer)
    if parsed.scheme not in {"https", "http"} or not parsed.netloc:
        return None
    return issuer


def validate_browser_automation(config_name: str, config_value: dict[str, object]) -> None:
    server = config_value.get("server")
    if not isinstance(server, dict):
        return
    discovery_url = server.get("discoveryUrl")
    if not isinstance(discovery_url, str):
        return
    issuer = issuer_from_discovery_url(discovery_url)
    if issuer is None:
        return

    browser = config_value.get("browser")
    if not isinstance(browser, list) or not browser:
        fail(
            f"{config_name} must include browser automation for {issuer}/authorize; "
            "OIDF OP modules otherwise remain in WAITING until they time out"
        )

    authorization_prefix = f"{issuer}/authorize"
    for entry in browser:
        if not isinstance(entry, dict):
            continue
        match = entry.get("match")
        if not isinstance(match, str):
            continue
        if match.startswith(authorization_prefix) or "/authorize" in match:
            return

    fail(
        f"{config_name} browser automation must match the authorization endpoint "
        f"{authorization_prefix}; matching only frontend pages does not start OIDF OP modules"
    )


def config_alias(config_value: dict[str, object]) -> str | None:
    alias = config_value.get("alias")
    if isinstance(alias, str) and alias.strip():
        return alias.strip()
    return None


def write_plan_configs(suite_scripts: Path, file_name: str, env_name: str) -> tuple[set[str], set[str]]:
    validate_config_file_name(file_name)
    raw_config = non_empty_env(env_name)
    try:
        parsed = json.loads(raw_config)
    except json.JSONDecodeError as exc:
        fail(f"{env_name} is not valid JSON: {exc}")
    if not isinstance(parsed, dict):
        fail(f"{env_name} must contain a JSON object")

    configs = parsed.get("configs")
    if configs is None:
        validate_browser_automation(file_name, parsed)
        target = suite_scripts / file_name
        target.write_text(json.dumps(parsed, indent=2, sort_keys=True), encoding="utf-8")
        aliases = {alias} if (alias := config_alias(parsed)) else set()
        return {file_name}, aliases

    if not isinstance(configs, dict) or not configs:
        fail(f"{env_name}.configs must contain a non-empty JSON object")

    written: set[str] = set()
    aliases: set[str] = set()
    for config_name, config_value in configs.items():
        if not isinstance(config_name, str) or not config_name.strip():
            fail(f"{env_name}.configs contains an invalid file name")
        validate_config_file_name(config_name)
        if not isinstance(config_value, dict):
            fail(f"{env_name}.configs.{config_name} must contain a JSON object")
        validate_browser_automation(config_name, config_value)
        alias = config_alias(config_value)
        if alias:
            aliases.add(alias)
        target = suite_scripts / config_name
        target.write_text(json.dumps(config_value, indent=2, sort_keys=True), encoding="utf-8")
        written.add(config_name)
    return written, aliases


def api_url(base_url: str, path: str, query: dict[str, str | int] | None = None) -> str:
    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    if query:
        return f"{url}?{urllib.parse.urlencode(query)}"
    return url


def oidf_api_request(
    method: str,
    base_url: str,
    path: str,
    token: str,
    *,
    query: dict[str, str | int] | None = None,
    expected_statuses: set[int],
) -> tuple[int, object | None]:
    request = urllib.request.Request(
        api_url(base_url, path, query),
        method=method,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
    )
    attempts = 3
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                status = response.status
                body = response.read()
        except urllib.error.HTTPError as exc:
            status = exc.code
            body = exc.read()
            if status < 500 or attempt == attempts:
                break
            time.sleep(attempt * 2)
            continue
        except urllib.error.URLError as exc:
            last_error = exc
            if attempt == attempts:
                fail(f"OIDF API {method} {path} failed: {exc}")
            time.sleep(attempt * 2)
            continue
        break
    else:
        fail(f"OIDF API {method} {path} failed: {last_error}")

    if status not in expected_statuses:
        text = body.decode("utf-8", "replace")[:300] if body else ""
        fail(f"OIDF API {method} {path} failed with HTTP {status}: {text}")

    if not body:
        return status, None
    try:
        return status, json.loads(body.decode("utf-8"))
    except json.JSONDecodeError:
        return status, None


def is_runner_finalisation_error(payload: object | None) -> bool:
    if not isinstance(payload, dict):
        return False

    fields = [
        payload.get("message"),
        payload.get("error"),
        payload.get("exception"),
        payload.get("trace"),
    ]
    text = "\n".join(value for value in fields if isinstance(value, str))
    return "runInBackground called after runFinalisationTaskInBackground()" in text


def module_ids_from_plan(plan: dict[str, object]) -> set[str]:
    modules = plan.get("modules")
    if not isinstance(modules, list):
        return set()

    module_ids: set[str] = set()
    for module in modules:
        if not isinstance(module, dict):
            continue
        instances = module.get("instances")
        if not isinstance(instances, list):
            continue
        for instance_id in instances:
            if isinstance(instance_id, str) and instance_id:
                module_ids.add(instance_id)
    return module_ids


def alias_plan_matches(alias: str, plan: object) -> bool:
    if not isinstance(plan, dict):
        return False
    config = plan.get("config")
    plan_alias = config.get("alias") if isinstance(config, dict) else None
    return plan_alias == alias and plan.get("immutable") is not True


def list_alias_module_ids(base_url: str, token: str, aliases: set[str]) -> set[str]:
    if not aliases:
        return set()

    start = 0
    length = 200
    module_ids: set[str] = set()
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
            return module_ids

        plans = payload.get("data")
        if not isinstance(plans, list) or not plans:
            return module_ids

        for plan in plans:
            if any(alias_plan_matches(alias, plan) for alias in aliases) and isinstance(plan, dict):
                module_ids.update(module_ids_from_plan(plan))

        start += len(plans)
        total = payload.get("recordsTotal")
        if isinstance(total, int) and start >= total:
            return module_ids


def module_waiting_for_review_placeholder(base_url: str, token: str, module_id: str) -> list[str]:
    _, info = oidf_api_request(
        "GET",
        base_url,
        f"api/info/{module_id}",
        token,
        expected_statuses={200, 404},
    )
    if not isinstance(info, dict) or info.get("status") != "WAITING":
        return []

    _, logs = oidf_api_request(
        "GET",
        base_url,
        f"api/log/{module_id}",
        token,
        expected_statuses={200, 404},
    )
    if not isinstance(logs, list):
        return []

    placeholders: list[str] = []
    for entry in logs:
        if not isinstance(entry, dict):
            continue
        placeholder = entry.get("upload")
        if entry.get("result") == "REVIEW" and isinstance(placeholder, str) and placeholder:
            placeholders.append(placeholder)
    return placeholders


def oidf_api_upload_review_placeholder(
    base_url: str,
    token: str,
    module_id: str,
    placeholder: str,
) -> bool:
    request = urllib.request.Request(
        api_url(base_url, f"api/log/{module_id}/images/{placeholder}"),
        method="POST",
        data=OIDF_REVIEW_PLACEHOLDER_IMAGE.encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "text/plain; charset=utf-8",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            response.read()
            return response.status == 200
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")[:300]
        print(
            "OIDF review placeholder upload failed for "
            f"{module_id}/{placeholder}: HTTP {exc.code}: {body}",
            flush=True,
        )
    except urllib.error.URLError as exc:
        print(
            f"OIDF review placeholder upload failed for {module_id}/{placeholder}: {exc}",
            flush=True,
        )
    return False


def monitor_review_placeholders(
    base_url: str,
    token: str,
    aliases: set[str],
    stop_event: threading.Event,
    *,
    poll_seconds: int = 5,
) -> None:
    filled: set[tuple[str, str]] = set()
    while not stop_event.wait(poll_seconds):
        try:
            module_ids = list_alias_module_ids(base_url, token, aliases)
            for module_id in module_ids:
                for placeholder in module_waiting_for_review_placeholder(base_url, token, module_id):
                    key = (module_id, placeholder)
                    if key in filled:
                        continue
                    if oidf_api_upload_review_placeholder(base_url, token, module_id, placeholder):
                        filled.add(key)
                        print(
                            f"Filled OIDF review placeholder {placeholder} for module {module_id}",
                            flush=True,
                        )
        except Exception as exc:
            print(f"OIDF review placeholder monitor skipped a poll: {exc}", flush=True)


def cancel_plan_module_instances(base_url: str, token: str, plan: dict[str, object]) -> None:
    modules = plan.get("modules")
    if not isinstance(modules, list):
        return
    for module in modules:
        if not isinstance(module, dict):
            continue
        instances = module.get("instances")
        if not isinstance(instances, list):
            continue
        for instance_id in instances:
            if not isinstance(instance_id, str) or not instance_id:
                continue
            status, payload = oidf_api_request(
                "DELETE",
                base_url,
                f"api/runner/{instance_id}",
                token,
                expected_statuses={200, 404, 500},
            )
            if status == 200:
                print(f"Cancelled stale OIDF module instance {instance_id}", flush=True)
            elif status == 500:
                if not is_runner_finalisation_error(payload):
                    fail(f"OIDF API DELETE api/runner/{instance_id} failed with unexpected HTTP 500")
                print(
                    "Skipped stale OIDF module instance "
                    f"{instance_id}: conformance suite rejected runner cancellation",
                    flush=True,
                )


def cleanup_existing_alias_plans(base_url: str, token: str, aliases: set[str]) -> None:
    if not aliases:
        return

    while True:
        deleted = cleanup_existing_alias_plans_pass(base_url, token, aliases)
        if deleted == 0:
            return


def cleanup_existing_alias_plans_pass(base_url: str, token: str, aliases: set[str]) -> int:
    start = 0
    length = 200
    deleted = 0
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
            return deleted

        plans = payload.get("data")
        if not isinstance(plans, list) or not plans:
            return deleted

        for plan in plans:
            if cleanup_alias_plan(base_url, token, aliases, plan):
                deleted += 1

        start += len(plans)
        total = payload.get("recordsTotal")
        if isinstance(total, int) and start >= total:
            return deleted


def cleanup_alias_plan(
    base_url: str,
    token: str,
    aliases: set[str],
    plan: object,
) -> bool:
    if not isinstance(plan, dict):
        return False
    config = plan.get("config")
    alias = config.get("alias") if isinstance(config, dict) else None
    plan_id = plan.get("_id")
    if alias not in aliases or not isinstance(plan_id, str):
        return False
    if plan.get("immutable") is True:
        print(f"Skipping immutable OIDF plan {plan_id} for alias {alias}", flush=True)
        return False

    cancel_plan_module_instances(base_url, token, plan)
    status, _ = oidf_api_request(
        "DELETE",
        base_url,
        f"api/plan/{plan_id}",
        token,
        expected_statuses={200, 204, 404, 405},
    )
    if status in {200, 204}:
        print(f"Deleted stale mutable OIDF plan {plan_id} for alias {alias}", flush=True)
        return True
    elif status == 405:
        print(f"Skipped non-deletable OIDF plan {plan_id} for alias {alias}", flush=True)
    return False


def default_plan_expressions(config_names: set[str], fallback_config_name: str) -> list[str]:
    per_plan_config_names = {
        OIDCC_BASIC_CONFIG_FILE,
        OIDCC_CONFIG_CONFIG_FILE,
        FAPI_SECURITY_FINAL_CONFIG_FILE,
        FAPI_MESSAGE_FINAL_CONFIG_FILE,
        FAPI_SECURITY_ID2_CONFIG_FILE,
        FAPI_MESSAGE_ID1_CONFIG_FILE,
    }
    if per_plan_config_names.issubset(config_names):
        return PER_PLAN_CONFIG_EXPRESSIONS
    if {OIDCC_CONFIG_FILE, FAPI_CONFIG_FILE}.issubset(config_names):
        return DEFAULT_PLAN_EXPRESSIONS
    return [
        expression.replace(OIDCC_CONFIG_FILE, fallback_config_name).replace(
            FAPI_CONFIG_FILE, fallback_config_name
        )
        for expression in DEFAULT_PLAN_EXPRESSIONS
    ]


def plan_expressions(
    raw_expression: str,
    env_name: str,
    config_names: set[str],
    fallback_config_name: str,
) -> list[str]:
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
        expressions = default_plan_expressions(config_names, fallback_config_name)

    if not expressions:
        fail("at least one OIDF plan expression is required")
    for expression in expressions:
        parts = shlex.split(expression)
        if not parts:
            fail("OIDF plan expression must not be empty")
        if not any(config_name in parts for config_name in config_names):
            fail(
                "OIDF plan expression must reference one of "
                f"{sorted(config_names)}: {expression}"
            )
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
    parser.add_argument("--no-parallel", action="store_true")
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=10_800,
        help="maximum runtime for the official conformance runner",
    )
    parser.add_argument("--list", action="store_true", help="list selected plans without running them")
    return parser.parse_args()


def run_official_runner(
    command: list[str],
    expressions: list[str],
    suite_scripts: Path,
    env: dict[str, str],
    timeout_seconds: int,
    conformance_server: str,
    aliases: set[str],
) -> int:
    if timeout_seconds <= 0:
        fail("--timeout-seconds must be greater than zero")

    print("OIDF selected plan expressions:", flush=True)
    for index, expression in enumerate(expressions, start=1):
        print(f"  {index}. {expression}", flush=True)
    print("OIDF official runner argv:", flush=True)
    for index, argument in enumerate(command):
        print(f"  argv[{index}]: {argument}", flush=True)
    print(f"OIDF official runner timeout: {timeout_seconds} seconds", flush=True)

    stop_monitor = threading.Event()
    monitor_thread: threading.Thread | None = None
    if aliases:
        monitor_thread = threading.Thread(
            target=monitor_review_placeholders,
            args=(conformance_server, env["CONFORMANCE_TOKEN"], aliases, stop_monitor),
            name="oidf-review-placeholder-monitor",
            daemon=True,
        )
        monitor_thread.start()
        print("OIDF review placeholder monitor started", flush=True)

    process = subprocess.Popen(
        command,
        cwd=suite_scripts,
        env=env,
        start_new_session=True,
    )
    try:
        return process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        print("OIDF official runner timed out; terminating process group", flush=True)
        terminate_runner(process)
        return 124
    finally:
        stop_monitor.set()
        if monitor_thread is not None:
            monitor_thread.join(timeout=15)


def terminate_runner(process: subprocess.Popen[bytes]) -> None:
    if hasattr(os, "killpg"):
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=15)
            return
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            return

    process.terminate()
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def main() -> int:
    args = parse_args()
    suite_dir = Path(args.suite_dir).resolve()
    suite_scripts = suite_dir / "scripts"
    runner = suite_scripts / "run-test-plan.py"
    if not runner.is_file():
        fail(f"official runner not found: {runner}")

    config_names, aliases = write_plan_configs(suite_scripts, args.config_file_name, args.config_env)
    expressions = plan_expressions(
        args.plan_expression,
        args.plan_set_env,
        config_names,
        args.config_file_name,
    )

    env = os.environ.copy()
    env["CONFORMANCE_SERVER"] = args.conformance_server
    env["CONFORMANCE_TOKEN"] = non_empty_env(args.token_env)
    if args.disable_ssl_verify:
        env["DISABLE_SSL_VERIFY"] = "1"

    if not args.list:
        cleanup_existing_alias_plans(args.conformance_server, env["CONFORMANCE_TOKEN"], aliases)

    command = [sys.executable, str(runner)]
    if args.list:
        command.append("--list")
    if args.no_parallel:
        command.append("--no-parallel")
    if args.export_dir:
        export_dir = Path(args.export_dir).resolve()
        export_dir.mkdir(parents=True, exist_ok=True)
        command.extend(["--export-dir", str(export_dir)])
    if args.verbose:
        command.append("--verbose")
    for expression in expressions:
        command.extend(shlex.split(expression))

    return run_official_runner(
        command,
        expressions,
        suite_scripts,
        env,
        args.timeout_seconds,
        args.conformance_server,
        set() if args.list else aliases,
    )


if __name__ == "__main__":
    raise SystemExit(main())
