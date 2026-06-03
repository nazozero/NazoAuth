#!/usr/bin/env python3
"""Run OpenID Foundation conformance plans with repository-owned input checks."""

from __future__ import annotations

import argparse
import copy
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
FAPI_SECURITY_FINAL_USER_REJECTS_AUTHENTICATION = (
    "fapi2-security-profile-final-user-rejects-authentication"
)
FAPI_SECURITY_FINAL_PAR_REUSE_BEFORE_AUTH = (
    "fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds"
)
OIDCC_SECOND_LOGIN_SCREENSHOT_MODULES = (
    "oidcc-prompt-login",
    "oidcc-max-age-1",
)
NAZO_AUTHORIZATION_ERROR_PAGE_TASK = "Capture authorization error page"
NAZO_AUTHORIZATION_ERROR_PAGE_PATTERN = (
    r"(invalid_request|invalid_request_object|access_denied|login_required|server_error)"
)
OIDF_BAD_FINAL_RESULTS = {"FAILED", "SKIPPED", "INTERRUPTED", "WARNING"}
OIDF_BAD_STATUS_VALUES = {"FAILED", "SKIPPED", "INTERRUPTED"}
OIDF_BAD_LOG_RESULTS = {"FAILURE", "WARNING"}
OIDF_ALLOWED_REVIEW_MODULES = {
    "oidcc-prompt-login",
    "oidcc-max-age-1",
    "oidcc-ensure-registered-redirect-uri",
}

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


def config_uses_nazo_hosted_conformance_ui(config_value: dict[str, object]) -> bool:
    browser = config_value.get("browser")
    if not isinstance(browser, list):
        return False

    for entry in browser:
        if not isinstance(entry, dict):
            continue
        match = entry.get("match")
        if isinstance(match, str) and match.startswith("https://oauth.nazo.run/authorize"):
            return True
    return False


def nazo_user_reject_browser_automation() -> list[dict[str, object]]:
    return [
        {
            "comment": (
                "Nazo OAuth hosted conformance UI signs in after an explicit browser click, "
                "then lets this negative module choose deny before the default approval."
            ),
            "match": "https://oauth.nazo.run/authorize*",
            "tasks": [
                {
                    "task": "Complete login page",
                    "optional": True,
                    "match": "https://oauth.nazo.run/ui/auth*",
                    "commands": [
                        [
                            "wait",
                            "id",
                            "oidf_conformance_interaction",
                            5,
                            "OIDF conformance login page",
                        ],
                        ["click", "id", "oidf_conformance_login"],
                        ["wait", "contains", "/ui/consent", 30],
                    ],
                },
                {
                    "task": "Deny consent page",
                    "match": "https://oauth.nazo.run/ui/consent*",
                    "commands": [
                        ["wait", "id", "oidf_conformance_deny", 10],
                        ["click", "id", "oidf_conformance_deny"],
                        ["wait", "contains", "/test/", 30],
                        ["wait", "id", "submission_complete", 10],
                    ],
                },
                {
                    "task": "Verify callback completion",
                    "match": "*/test/*/callback*",
                    "commands": [["wait", "id", "submission_complete", 10]],
                },
            ],
        }
    ]


def authorization_error_page_task() -> dict[str, object]:
    return {
        "task": NAZO_AUTHORIZATION_ERROR_PAGE_TASK,
        "optional": True,
        "match": "https://oauth.nazo.run/authorize*",
        "commands": [
            [
                "wait",
                "id",
                "oidf_conformance_interaction",
                5,
                NAZO_AUTHORIZATION_ERROR_PAGE_PATTERN,
                "update-image-placeholder-optional",
            ]
        ],
    }


def login_page_wait_command(command: object) -> bool:
    return (
        isinstance(command, list)
        and len(command) >= 5
        and command[:5]
        == [
            "wait",
            "id",
            "oidf_conformance_interaction",
            5,
            "OIDF conformance login page",
        ]
    )


def login_page_click_command(command: object) -> bool:
    return (
        isinstance(command, list)
        and len(command) >= 3
        and command[:3] == ["click", "id", "oidf_conformance_login"]
    )


def add_login_page_click(task: object) -> None:
    if not isinstance(task, dict):
        return
    commands = task.get("commands")
    if not isinstance(commands, list):
        return
    if any(login_page_click_command(command) for command in commands):
        return

    for index, command in enumerate(commands):
        if login_page_wait_command(command):
            commands.insert(index + 1, ["click", "id", "oidf_conformance_login"])
            return


def add_login_page_clicks(config_value: dict[str, object]) -> None:
    browser = config_value.get("browser")
    if not isinstance(browser, list):
        return

    for entry in browser:
        if not isinstance(entry, dict):
            continue
        match = entry.get("match")
        if not (isinstance(match, str) and match.startswith("https://oauth.nazo.run/authorize")):
            continue
        tasks = entry.get("tasks")
        if not isinstance(tasks, list):
            continue
        for task in tasks:
            add_login_page_click(task)


def add_authorization_error_page_capture(config_value: dict[str, object]) -> None:
    browser = config_value.get("browser")
    if not isinstance(browser, list):
        return

    for entry in browser:
        if not isinstance(entry, dict):
            continue
        match = entry.get("match")
        if not (isinstance(match, str) and match.startswith("https://oauth.nazo.run/authorize")):
            continue
        tasks = entry.setdefault("tasks", [])
        if not isinstance(tasks, list):
            continue
        if any(
            isinstance(task, dict) and task.get("task") == NAZO_AUTHORIZATION_ERROR_PAGE_TASK
            for task in tasks
        ):
            continue
        tasks.insert(0, authorization_error_page_task())


def remove_login_page_placeholder_update(task: object) -> None:
    if not isinstance(task, dict):
        return
    commands = task.get("commands")
    if not isinstance(commands, list):
        return

    for command in commands:
        if not isinstance(command, list) or len(command) < 6:
            continue
        if not login_page_wait_command(command):
            continue
        if command[5] == "update-image-placeholder-optional":
            command.pop(5)


def remove_default_login_page_placeholder_updates(config_value: dict[str, object]) -> None:
    browser = config_value.get("browser")
    if not isinstance(browser, list):
        return

    for entry in browser:
        if not isinstance(entry, dict):
            continue
        match = entry.get("match")
        if not (isinstance(match, str) and match.startswith("https://oauth.nazo.run/authorize")):
            continue
        tasks = entry.get("tasks")
        if not isinstance(tasks, list):
            continue
        for task in tasks:
            remove_login_page_placeholder_update(task)


def mark_login_page_wait_as_placeholder_update(task: object) -> None:
    if not isinstance(task, dict):
        return
    commands = task.get("commands")
    if not isinstance(commands, list):
        return

    for command in commands:
        if not isinstance(command, list) or len(command) < 5:
            continue
        if not login_page_wait_command(command):
            continue
        if len(command) == 5:
            command.append("update-image-placeholder-optional")
        elif command[5] in {None, ""}:
            command[5] = "update-image-placeholder-optional"


def browser_automation_with_second_login_placeholder(
    browser: list[object],
) -> list[object]:
    automation: list[object] = []
    for entry in browser:
        if not isinstance(entry, dict):
            automation.append(copy.deepcopy(entry))
            continue

        match = entry.get("match")
        if not (isinstance(match, str) and match.startswith("https://oauth.nazo.run/authorize")):
            automation.append(copy.deepcopy(entry))
            continue

        first_authorization = copy.deepcopy(entry)
        first_authorization["match-limit"] = 1
        automation.append(first_authorization)

        second_authorization = copy.deepcopy(entry)
        second_authorization.pop("match-limit", None)
        tasks = second_authorization.get("tasks")
        if isinstance(tasks, list):
            for task in tasks:
                mark_login_page_wait_as_placeholder_update(task)
        automation.append(second_authorization)

    return automation


def first_login_observation_automation(browser: list[object]) -> list[object]:
    automation: list[object] = []
    for entry in browser:
        if not isinstance(entry, dict):
            automation.append(copy.deepcopy(entry))
            continue

        match = entry.get("match")
        if not (isinstance(match, str) and match.startswith("https://oauth.nazo.run/authorize")):
            automation.append(copy.deepcopy(entry))
            continue

        first_authorization = {
            "comment": (
                "This module requires the first authorization endpoint visit to stop at "
                "the login page without authenticating."
            ),
            "match": match,
            "match-limit": 1,
            "tasks": [
                {
                    "task": "Observe first login page without authentication",
                    "match": "https://oauth.nazo.run/ui/auth*",
                    "commands": [
                        [
                            "wait",
                            "id",
                            "oidf_conformance_interaction",
                            5,
                            "OIDF conformance login page",
                            "update-image-placeholder-optional",
                        ]
                    ],
                }
            ],
        }
        automation.append(first_authorization)

        second_authorization = copy.deepcopy(entry)
        second_authorization.pop("match-limit", None)
        automation.append(second_authorization)

    return automation


def add_nazo_second_login_placeholder_overrides(config_value: dict[str, object]) -> None:
    if not config_uses_nazo_hosted_conformance_ui(config_value):
        return

    browser = config_value.get("browser")
    if not isinstance(browser, list):
        return

    override = config_value.setdefault("override", {})
    if not isinstance(override, dict):
        fail("OIDF plan config override must be a JSON object when present")

    browser_override = browser_automation_with_second_login_placeholder(browser)
    for module_name in OIDCC_SECOND_LOGIN_SCREENSHOT_MODULES:
        override.setdefault(module_name, {"browser": copy.deepcopy(browser_override)})


def add_nazo_par_reuse_before_auth_override(config_value: dict[str, object]) -> None:
    if not config_uses_nazo_hosted_conformance_ui(config_value):
        return

    browser = config_value.get("browser")
    if not isinstance(browser, list):
        return

    override = config_value.setdefault("override", {})
    if not isinstance(override, dict):
        fail("OIDF plan config override must be a JSON object when present")

    override.setdefault(
        FAPI_SECURITY_FINAL_PAR_REUSE_BEFORE_AUTH,
        {"browser": first_login_observation_automation(browser)},
    )


def add_nazo_user_reject_override(config_value: dict[str, object]) -> None:
    if not config_uses_nazo_hosted_conformance_ui(config_value):
        return

    override = config_value.setdefault("override", {})
    if not isinstance(override, dict):
        fail("OIDF plan config override must be a JSON object when present")
    override.setdefault(
        FAPI_SECURITY_FINAL_USER_REJECTS_AUTHENTICATION,
        {"browser": nazo_user_reject_browser_automation()},
    )


def add_nazo_browser_overrides(config_value: dict[str, object]) -> None:
    remove_default_login_page_placeholder_updates(config_value)
    add_login_page_clicks(config_value)
    add_authorization_error_page_capture(config_value)
    add_nazo_second_login_placeholder_overrides(config_value)
    add_nazo_par_reuse_before_auth_override(config_value)
    add_nazo_user_reject_override(config_value)


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
        add_nazo_browser_overrides(parsed)
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
        add_nazo_browser_overrides(config_value)
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


def value_as_upper(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip().upper()


def module_name_without_variant(test_name: str) -> str:
    return test_name.split("[", 1)[0]


def is_allowed_review_module(test_name: str) -> bool:
    return module_name_without_variant(test_name) in OIDF_ALLOWED_REVIEW_MODULES


def oidf_module_failure(info: object) -> str | None:
    if not isinstance(info, dict):
        return None

    module_id = info.get("_id") or info.get("testId") or info.get("id") or "<unknown>"
    test_name_value = info.get("testName") or info.get("name") or "<unknown>"
    test_name = test_name_value if isinstance(test_name_value, str) else "<unknown>"
    status = value_as_upper(info.get("status"))
    result = value_as_upper(info.get("result"))
    error = info.get("error")

    if isinstance(error, str) and error.strip():
        return f"{test_name} {module_id} reported error: {error.strip()[:300]}"
    if isinstance(error, dict) and error:
        return f"{test_name} {module_id} reported a structured error"
    if status in OIDF_BAD_STATUS_VALUES:
        return f"{test_name} {module_id} status {status}"
    if result in OIDF_BAD_FINAL_RESULTS:
        return f"{test_name} {module_id} result {result}"
    if result == "REVIEW" and not is_allowed_review_module(test_name):
        return f"{test_name} {module_id} result REVIEW"

    return None


def oidf_log_failure(module_id: str, logs: object) -> str | None:
    if not isinstance(logs, list):
        return None

    for entry in logs:
        if not isinstance(entry, dict):
            continue
        result = value_as_upper(entry.get("result"))
        if result not in OIDF_BAD_LOG_RESULTS:
            continue
        src = entry.get("src")
        msg = entry.get("msg")
        src_text = src if isinstance(src, str) and src else "<unknown>"
        msg_text = msg if isinstance(msg, str) and msg else "<no message>"
        return f"{module_id} log {result} at {src_text}: {msg_text[:300]}"
    return None


def fetch_alias_plans(base_url: str, token: str, aliases: set[str]) -> list[dict[str, object]]:
    if not aliases:
        return []

    start = 0
    length = 200
    matched: list[dict[str, object]] = []
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
            return matched

        plans = payload.get("data")
        if not isinstance(plans, list) or not plans:
            return matched

        for plan in plans:
            if not isinstance(plan, dict):
                continue
            config = plan.get("config")
            alias = config.get("alias") if isinstance(config, dict) else None
            if alias in aliases:
                matched.append(plan)

        start += len(plans)
        total = payload.get("recordsTotal")
        if isinstance(total, int) and start >= total:
            return matched


def inspect_oidf_state(
    base_url: str,
    token: str,
    aliases: set[str],
    *,
    final: bool,
) -> str | None:
    plans = fetch_alias_plans(base_url, token, aliases)
    if not plans:
        return "OIDF monitor found no plan for current aliases" if final else None

    module_ids: set[str] = set()
    for plan in plans:
        module_ids.update(module_ids_from_plan(plan))

    if not module_ids:
        return "OIDF monitor found no module instances for current plan" if final else None

    for module_id in sorted(module_ids):
        status_code, info = oidf_api_request(
            "GET",
            base_url,
            f"api/info/{module_id}",
            token,
            expected_statuses={200, 404},
        )
        if status_code == 200 and info is not None:
            failure = oidf_module_failure(info)
            if failure:
                return failure
            status = value_as_upper(info.get("status")) if isinstance(info, dict) else ""
            if final and status and status != "FINISHED":
                return f"{module_id} ended with non-final status {status}"

        status_code, logs = oidf_api_request(
            "GET",
            base_url,
            f"api/log/{module_id}",
            token,
            expected_statuses={200, 404},
        )
        if status_code == 200:
            failure = oidf_log_failure(module_id, logs)
            if failure:
                return failure

    return None


def cancel_alias_plan_instances(base_url: str, token: str, aliases: set[str]) -> None:
    for plan in fetch_alias_plans(base_url, token, aliases):
        cancel_plan_module_instances(base_url, token, plan)


class OidfEarlyStopMonitor:
    def __init__(
        self,
        base_url: str,
        token: str,
        aliases: set[str],
        interval_seconds: int,
    ) -> None:
        self.base_url = base_url
        self.token = token
        self.aliases = aliases
        self.interval_seconds = interval_seconds
        self.stop_requested = threading.Event()
        self.failure_message: str | None = None
        self.consecutive_errors = 0

    def run(self, process: subprocess.Popen[bytes]) -> None:
        while not self.stop_requested.wait(self.interval_seconds):
            if process.poll() is not None:
                return

            try:
                failure = inspect_oidf_state(
                    self.base_url,
                    self.token,
                    self.aliases,
                    final=False,
                )
                self.consecutive_errors = 0
            except SystemExit as exc:
                self.consecutive_errors += 1
                print(f"OIDF early-stop monitor API error: {exc}", flush=True)
                if self.consecutive_errors < 3:
                    continue
                failure = "OIDF early-stop monitor could not read suite state after 3 attempts"

            if failure:
                self.failure_message = failure
                print(f"OIDF early stop: {failure}", flush=True)
                terminate_runner(process)
                try:
                    cancel_alias_plan_instances(self.base_url, self.token, self.aliases)
                except SystemExit as exc:
                    print(f"OIDF early-stop cleanup error: {exc}", flush=True)
                return

    def stop(self) -> None:
        self.stop_requested.set()


def alias_plan_matches(alias: str, plan: object) -> bool:
    if not isinstance(plan, dict):
        return False
    config = plan.get("config")
    plan_alias = config.get("alias") if isinstance(config, dict) else None
    return plan_alias == alias and plan.get("immutable") is not True


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
    if raw_expression.strip():
        expressions = [raw_expression.strip()]
    elif raw_plan_set:
        try:
            parsed = json.loads(raw_plan_set)
        except json.JSONDecodeError as exc:
            fail(f"{env_name} is not valid JSON: {exc}")
        if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
            fail(f"{env_name} must contain a JSON array of plan expression strings")
        expressions = [item.strip() for item in parsed if item.strip()]
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
        "--rerun",
        default="",
        help="pass through the official runner --rerun filter, for example 1 or 1:3 or 1,3",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=10_800,
        help="maximum runtime for the official conformance runner",
    )
    parser.add_argument(
        "--monitor-interval-seconds",
        type=int,
        default=60,
        help="poll OIDF APIs at this interval and stop early on failed module state",
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
    token: str,
    monitor_interval_seconds: int,
) -> int:
    if timeout_seconds <= 0:
        fail("--timeout-seconds must be greater than zero")
    if monitor_interval_seconds <= 0:
        fail("--monitor-interval-seconds must be greater than zero")

    print("OIDF selected plan expressions:", flush=True)
    for index, expression in enumerate(expressions, start=1):
        print(f"  {index}. {expression}", flush=True)
    print("OIDF official runner argv:", flush=True)
    for index, argument in enumerate(command):
        print(f"  argv[{index}]: {argument}", flush=True)
    print(f"OIDF official runner timeout: {timeout_seconds} seconds", flush=True)

    process = subprocess.Popen(
        command,
        cwd=suite_scripts,
        env=env,
        start_new_session=True,
    )
    monitor: OidfEarlyStopMonitor | None = None
    monitor_thread: threading.Thread | None = None
    if aliases:
        monitor = OidfEarlyStopMonitor(
            conformance_server,
            token,
            aliases,
            monitor_interval_seconds,
        )
        monitor_thread = threading.Thread(
            target=monitor.run,
            args=(process,),
            name="oidf-early-stop-monitor",
            daemon=True,
        )
        print(
            f"OIDF early-stop monitor interval: {monitor_interval_seconds} seconds",
            flush=True,
        )
        monitor_thread.start()

    try:
        exit_code = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        print("OIDF official runner timed out; terminating process group", flush=True)
        terminate_runner(process)
        return 124
    finally:
        if monitor is not None:
            monitor.stop()
        if monitor_thread is not None:
            monitor_thread.join(timeout=5)

    if monitor is not None and monitor.failure_message:
        return 1

    if aliases:
        final_failure = inspect_oidf_state(
            conformance_server,
            token,
            aliases,
            final=exit_code == 0,
        )
        if final_failure:
            print(f"OIDF final state check failed: {final_failure}", flush=True)
            return 1

    return exit_code


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
    if args.rerun:
        command.extend(["--rerun", args.rerun])
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
        env["CONFORMANCE_TOKEN"],
        args.monitor_interval_seconds,
    )


if __name__ == "__main__":
    raise SystemExit(main())
