#!/usr/bin/env python3
"""Exercise the original OIDF Basic RP plan against the NazoAuth HTTP fixture.

This is a run driver, not an alternate RP implementation. It preserves Suite
results and checks local login independently. WAITING stays incomplete. Evidence
exports redact temporary credentials, private keys, token values and URL queries;
Suite execution and its original status/result/condition records stay unchanged.
Requires requests. Run only against the isolated instance from bootstrap-suite.sh.
"""

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import time
from urllib.parse import urljoin, urlsplit

import requests


PLAN = "oidcc-client-basic-certification-test-plan"
TERMINAL = {"FINISHED", "INTERRUPTED"}
POSITIVE_MODULES = {
    "oidcc-client-test",
    "oidcc-client-test-kid-absent-single-jwks",
    "oidcc-client-test-idtoken-sig-rs256",
    "oidcc-client-test-scope-userinfo-claims",
    "oidcc-client-test-client-secret-basic",
}
REJECTED_MODULES = {
    "oidcc-client-test-invalid-iss",
    "oidcc-client-test-missing-sub",
    "oidcc-client-test-invalid-aud",
    "oidcc-client-test-missing-iat",
    "oidcc-client-test-invalid-sig-rs256",
    "oidcc-client-test-userinfo-invalid-sub",
    "oidcc-client-test-nonce-invalid",
    # The Suite permits rejection when multiple keys match without a kid.
    "oidcc-client-test-kid-absent-multiple-jwks",
    "oidcc-client-test-idtoken-sig-none",
}
EXPECTED_MODULES = POSITIVE_MODULES | REJECTED_MODULES
SESSION_COOKIE = "nazo_federation_session"
CSRF_COOKIE = "nazo_federation_csrf"
REDACTED_KEYS = {
    "d", "p", "q", "dp", "dq", "qi", "oth", "k", "key",
    "client_secret", "access_token", "refresh_token", "id_token",
    "authorization_code", "code", "code_verifier", "nonce", "state",
    "csrf_token", "session_id", "authorization", "cookie", "set-cookie",
    "verifiable_jws", "incoming_body", "outgoing",
}


def evidence(value):
    """Redact known Suite payload fields only at the artifact boundary."""
    if isinstance(value, dict):
        return {
            key: "[redacted]" if key.lower() in REDACTED_KEYS else evidence(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [evidence(item) for item in value]
    if isinstance(value, str):
        # Some Suite log fields and the local response contain JSON as text.
        if value.lstrip().startswith(("{", "[")):
            try:
                return json.dumps(evidence(json.loads(value)), ensure_ascii=False)
            except json.JSONDecodeError:
                pass
        if value.startswith(("https://", "http://")):
            return without_query(value)
    return value


def save(path, value):
    path.write_text(json.dumps(evidence(value), ensure_ascii=False, indent=2) + "\n")


def without_query(url):
    parts = urlsplit(url)
    return parts._replace(query="", fragment="").geturl()


def callback_errors(module, response, callback):
    """Suite PASSED alone does not establish successful or rejected local login."""
    errors = []
    if response["url"] != without_query(callback):
        errors.append("flow did not finish at the NazoAuth callback")
    try:
        body = json.loads(response["body"])
    except json.JSONDecodeError:
        return errors + ["callback did not return JSON"]
    if not isinstance(body, dict):
        return errors + ["callback did not return a JSON object"]
    if module in POSITIVE_MODULES:
        if response["status"] != 200:
            errors.append("valid upstream identity did not authenticate its existing link")
        if body.get("mfa_required") is not False:
            errors.append("fixture account did not receive a complete local session")
        if type(body.get("expires_in")) is not int or body["expires_in"] <= 0:
            errors.append("local session lifetime is missing or invalid")
        if not isinstance(body.get("csrf_token"), str) or not body["csrf_token"]:
            errors.append("local CSRF token is missing")
        if not response["session_cookie_set"] or not response["csrf_cookie_set"]:
            errors.append("local session or CSRF cookie is missing")
        if not response["csrf_cookie_matches_body"]:
            errors.append("local CSRF cookie does not match the response")
    else:
        if response["status"] != 401 or body.get("error") != "access_denied":
            errors.append("invalid upstream identity was not rejected by the callback")
        if {SESSION_COOKIE, CSRF_COOKIE}.intersection(response["cookie_names"]):
            errors.append("rejected identity received local session or CSRF cookies")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--ca", default=os.environ.get("OIDF_SUITE_CA"))
    parser.add_argument("--suite", default="https://localhost:8443")
    parser.add_argument("--start", default="https://localhost:8443/rp/auth/federation/oidf-rp-test/start")
    parser.add_argument("--callback", default="https://localhost:8443/rp/auth/federation/oidf-rp-test/callback")
    parser.add_argument("--alias", default="nazo-issue202")
    parser.add_argument("--finish-timeout", type=float, default=20)
    parser.add_argument("--tested-commit", required=True)
    args = parser.parse_args()
    if not args.ca:
        parser.error("--ca or OIDF_SUITE_CA is required; TLS verification stays enabled")
    args.output.mkdir(parents=True, exist_ok=True)
    suite = args.suite.rstrip("/")
    api = requests.Session()
    api.verify = args.ca
    api.trust_env = False
    api.headers["Content-Type"] = "application/json"

    def call(method, path, *, params=None, body=None):
        response = api.request(method, suite + path, params=params, json=body, timeout=40)
        response.raise_for_status()
        return response.json()

    def wait(module_id, statuses, timeout):
        deadline = time.monotonic() + timeout
        while True:
            info = call("GET", f"/api/info/{module_id}")
            if info.get("status") in statuses or time.monotonic() >= deadline:
                return info
            time.sleep(0.5)

    def follow_rp():
        # A new cookie jar per module exercises production browser state binding.
        browser = requests.Session()
        browser.verify = args.ca
        browser.trust_env = False
        hops = []
        url = args.start
        for _ in range(10):
            response = browser.get(url, allow_redirects=False, timeout=40)
            location = response.headers.get("Location")
            hop = {"url": without_query(url), "status": response.status_code}
            if location:
                hop["redirect"] = without_query(urljoin(url, location))
            hops.append(hop)
            if response.is_redirect:
                url = urljoin(url, location)
                continue
            cookies = {cookie.name: cookie.value for cookie in browser.cookies}
            try:
                body = response.json()
            except requests.exceptions.JSONDecodeError:
                body = None
            return {
                "hops": hops,
                "url": without_query(url),
                "status": response.status_code,
                "body": response.text,
                "cookie_names": sorted(cookies),
                "session_cookie_set": bool(cookies.get(SESSION_COOKIE)),
                "csrf_cookie_set": bool(cookies.get(CSRF_COOKIE)),
                "csrf_cookie_matches_body": isinstance(body, dict)
                and bool(body.get("csrf_token"))
                and cookies.get(CSRF_COOKIE) == body["csrf_token"],
            }
        raise RuntimeError("RP flow exceeded ten redirects")

    variants = {"client_registration": "static_client", "request_type": "plain_http_request"}
    config = {
        "alias": args.alias,
        "description": f"NazoAuth issue 202: {args.tested_commit}",
        "waitTimeoutSeconds": 5,
        "client": {
            "client_id": os.environ.get("OIDF_RP_CLIENT_ID", "nazoauth-issue202"),
            "client_secret": os.environ.get("OIDF_RP_CLIENT_SECRET", "nazoauth-issue202-test-secret"),
            "redirect_uri": args.callback,
            "id_token_signed_response_alg": "RS256",
        },
    }
    suite_server = call("GET", "/api/server")
    save(args.output / "suite-server.json", suite_server)
    if (suite_server.get("version"), suite_server.get("tag"), suite_server.get("revision")) != (
        "5.3.4", "release-v5.3.4", "23353b3"
    ):
        raise RuntimeError("Suite runtime identity differs from the pinned tested image")
    save(args.output / "plan-definition.json", call("GET", f"/api/plan/info/{PLAN}"))
    plan = call("POST", "/api/plan", params={"planName": PLAN, "variant": json.dumps(variants)}, body=config)
    save(args.output / "created-plan.json", plan)
    plan_id = plan["id"]
    modules = plan["modules"]
    if len(modules) != 14 or {entry["testModule"] for entry in modules} != EXPECTED_MODULES:
        raise RuntimeError("Suite Basic RP plan differs from the 14 reviewed modules")
    summary = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "tested_commit": args.tested_commit,
        "suite_runtime": suite_server,
        "evidence_policy": "Temporary secrets, private JWK fields, token values and URL queries are redacted at export; Suite statuses, results and condition records are preserved.",
        "suite_origin": suite,
        "plan_name": PLAN,
        "plan_id": plan_id,
        "declared_modules": len(modules),
        "results": [],
    }
    save(args.output / "summary.json", summary)
    for entry in modules:
        name = entry["testModule"]
        folder = args.output / name
        folder.mkdir()
        record = {"module": name, "variant": entry.get("variant"), "id": None}
        record["application_errors"] = ["NazoAuth callback was not exercised"]
        try:
            created = call("POST", "/api/runner", params={"plan": plan_id, "test": name})
            save(folder / "created.json", created)
            module_id = record["id"] = created["id"]
            ready = wait(module_id, {"WAITING", "CONFIGURED"} | TERMINAL, 90)
            if ready.get("status") == "CONFIGURED":
                save(folder / "start.json", call("POST", f"/api/runner/{module_id}"))
                ready = wait(module_id, {"WAITING"} | TERMINAL, 90)
            save(folder / "before.json", ready)
            save(folder / "runner-before.json", call("GET", f"/api/runner/{module_id}"))
            if ready.get("status") == "WAITING":
                try:
                    rp_response = follow_rp()
                    save(folder / "rp-response.json", rp_response)
                    record["rp_status"] = rp_response["status"]
                    record["application_errors"] = callback_errors(name, rp_response, args.callback)
                except Exception as error:
                    # Request exceptions can contain the callback's code/state URL.
                    record["rp_driver_error"] = type(error).__name__
                    save(folder / "rp-driver-error.json", {"error": type(error).__name__})
                observed = wait(module_id, TERMINAL, args.finish_timeout)
            else:
                observed = ready
            save(folder / "info-observed.json", observed)
            save(folder / "logs-observed.json", call("GET", f"/api/log/{module_id}"))
            record["status"] = observed.get("status")
            record["result"] = observed.get("result")
            record["expected_suite_result"] = (
                "SKIPPED" if name == "oidcc-client-test-idtoken-sig-none" else "PASSED"
            )
            record["application_pass"] = not record["application_errors"]
            record["suite_expectation_met"] = (
                record["status"] == "FINISHED"
                and record["result"] == record["expected_suite_result"]
            )
            record["incomplete"] = record["status"] not in TERMINAL
            if record["incomplete"]:
                # Preserve the pre-stop WAITING state. Cancel only to release the alias.
                save(folder / "stop.json", call("DELETE", f"/api/runner/{module_id}"))
                stopped = wait(module_id, TERMINAL, 15)
                save(folder / "info-after-stop.json", stopped)
                save(folder / "logs-after-stop.json", call("GET", f"/api/log/{module_id}"))
                if stopped.get("status") not in TERMINAL:
                    raise RuntimeError("Module did not stop; refusing to reassign its alias")
        except Exception as error:
            record["driver_error"] = str(error)
            save(folder / "driver-error.json", {"error": str(error)})
            summary["results"].append(record)
            save(args.output / "summary.json", summary)
            # A failed orchestration cannot be safely disguised as a module result.
            raise
        summary["results"].append(record)
        save(args.output / "summary.json", summary)
        print(json.dumps(evidence(record), ensure_ascii=False), flush=True)

    save(args.output / "plan-final.json", call("GET", f"/api/plan/{plan_id}"))
    summary["finished_at"] = datetime.now(timezone.utc).isoformat()
    summary["result_counts"] = dict(Counter(row.get("result", "UNKNOWN") for row in summary["results"]))
    summary["status_counts"] = dict(Counter(row.get("status", "UNKNOWN") for row in summary["results"]))
    summary["incomplete_count"] = sum(row.get("incomplete", True) for row in summary["results"])
    summary["rp_driver_error_count"] = sum("rp_driver_error" in row for row in summary["results"])
    summary["application_failure_count"] = sum(not row["application_pass"] for row in summary["results"])
    summary["suite_expectation_failure_count"] = sum(not row["suite_expectation_met"] for row in summary["results"])
    save(args.output / "summary.json", summary)
    print(json.dumps({key: summary[key] for key in ("plan_id", "declared_modules", "result_counts", "status_counts", "incomplete_count", "rp_driver_error_count", "application_failure_count", "suite_expectation_failure_count")}, ensure_ascii=False), flush=True)
    failed = any(not row["application_pass"] or not row["suite_expectation_met"] or "rp_driver_error" in row for row in summary["results"])
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
