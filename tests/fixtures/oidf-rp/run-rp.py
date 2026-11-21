#!/usr/bin/env python3
"""Exercise the original OIDF Basic, Config and Back-Channel Logout RP plans.

This is a run driver, not an alternate RP implementation. It preserves Suite
results and checks local login independently. WAITING stays incomplete. Evidence
exports redact temporary credentials, private keys, token values and URL queries;
Suite execution and its original status/result/condition records stay unchanged.
Requires requests. Run only against the isolated instance from bootstrap-suite.sh.
"""

import argparse
from collections import Counter
from datetime import datetime, timezone
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import sys
import time
from urllib.parse import urljoin, urlsplit

import requests


PLANS = {
    "basic": ("oidcc-client-basic-certification-test-plan", "nazo-issue202", "oidf-rp-test"),
    "config": ("oidcc-client-config-certification-test-plan", "nazo-config", "oidf-config"),
    "backchannel": ("oidcc-client-back-channel-logout-rp-basic", "nazo-logout", "oidf-logout"),
}
TERMINAL = {"FINISHED", "INTERRUPTED"}
BASIC_POSITIVE = {
    "oidcc-client-test",
    "oidcc-client-test-kid-absent-single-jwks",
    "oidcc-client-test-idtoken-sig-rs256",
    "oidcc-client-test-scope-userinfo-claims",
    "oidcc-client-test-client-secret-basic",
}
BASIC_REJECTED = {
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
CONFIG_ONLY = "oidcc-client-test-discovery-openid-config"
ISSUER_MISMATCH = "oidcc-client-test-discovery-issuer-mismatch"
DISCOVERED_JWKS = "oidcc-client-test-discovery-jwks-uri-keys"
ROTATION = "oidcc-client-test-signing-key-rotation"
UNSIGNED = "oidcc-client-test-idtoken-sig-none"
BACKCHANNEL_VALID = "oidcc-client-test-rp-backchannel-rpinitlogout"
PROFILE_MODULES = {
    "basic": BASIC_POSITIVE | BASIC_REJECTED,
    "config": {
        CONFIG_ONLY, ISSUER_MISMATCH, ROTATION, UNSIGNED,
        DISCOVERED_JWKS,
        "oidcc-client-test-signing-key-rotation-just-before-signing",
    },
    "backchannel": {BACKCHANNEL_VALID} | {
        f"{BACKCHANNEL_VALID}-{suffix}"
        for suffix in ("alg-none", "no-event", "with-nonce", "wrong-alg", "wrong-aud", "wrong-event", "wrong-iss")
    },
}
SESSION_COOKIE = "nazo_federation_session"
CSRF_COOKIE = "nazo_federation_csrf"
REDACTED_KEYS = {
    "d", "p", "q", "dp", "dq", "qi", "oth", "k", "key",
    "client_secret", "access_token", "refresh_token", "id_token",
    "authorization_code", "code", "code_verifier", "nonce", "state",
    "csrf_token", "session_id", "authorization", "cookie", "set-cookie",
    "verifiable_jws", "incoming_body", "outgoing", "logout_token", "id_token_hint",
    "all_issued_id_tokens", "issued_id_tokens",
}
COMPACT_JOSE = re.compile(r"eyJ[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]*){2,4}")


def evidence(value):
    """Redact known Suite payload fields only at the artifact boundary."""
    if isinstance(value, dict):
        return {
            COMPACT_JOSE.sub("[redacted]", key): "[redacted]" if key.lower() in REDACTED_KEYS else evidence(item)
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
        return COMPACT_JOSE.sub("[redacted]", value)
    return value


def save(path, value):
    path.write_text(json.dumps(evidence(value), ensure_ascii=False, indent=2) + "\n")


def without_query(url):
    parts = urlsplit(url)
    return parts._replace(query="", fragment="").geturl()


def callback_errors(response, callback, expect_login):
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
    if expect_login:
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


class LogoutForm(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.action = None
        self.fields = {}
        self.feed(html)

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if tag == "form" and attrs.get("method") == "post":
            self.action = attrs.get("action")
        if tag == "input" and attrs.get("type") == "hidden":
            self.fields[attrs.get("name")] = attrs.get("value")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--ca", default=os.environ.get("OIDF_SUITE_CA"))
    parser.add_argument("--suite", default="https://localhost:8443")
    parser.add_argument("--profile", choices=PLANS, default="basic")
    parser.add_argument("--finish-timeout", type=float, default=20)
    parser.add_argument("--tested-commit", required=True)
    args = parser.parse_args()
    if not args.ca:
        parser.error("--ca or OIDF_SUITE_CA is required; TLS verification stays enabled")
    args.output.mkdir(parents=True, exist_ok=True)
    suite = args.suite.rstrip("/")
    plan_name, alias, provider = PLANS[args.profile]
    rp = f"{suite}/rp/auth/federation/{provider}"
    callback = f"{rp}/callback"
    keys_rp = f"{suite}/rp/auth/federation/oidf-config-keys"
    post_logout = f"{suite}/rp/signed-out"
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

    def follow_rp(browser, base):
        hops = []
        url = f"{base}/start"
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
                "session_cookie_set": bool(response.cookies.get(SESSION_COOKIE)),
                "csrf_cookie_set": bool(response.cookies.get(CSRF_COOKIE)),
                "csrf_cookie_matches_body": isinstance(body, dict)
                and bool(body.get("csrf_token"))
                and cookies.get(CSRF_COOKIE) == body["csrf_token"],
            }
        raise RuntimeError("RP flow exceeded ten redirects")

    def drive_profile(module, folder):
        # Each module starts with a distinct browser session.
        with requests.Session() as browser:
            browser.verify = args.ca
            browser.trust_env = False
            if module in (CONFIG_ONLY, ISSUER_MISMATCH):
                start = browser.get(f"{rp}/start", allow_redirects=False, timeout=40)
                redirect = start.headers.get("Location")
                save(folder / "rp-start.json", {"status": start.status_code, "redirect": redirect})
                if module == CONFIG_ONLY:
                    expected = f"{suite}/test/a/{alias}/authorize"
                    ok = start.status_code == 302 and redirect and without_query(redirect) == expected
                else:
                    ok = start.status_code == 503 and redirect is None and not browser.cookies
                return start.status_code, [] if ok else ["unexpected discovery start outcome"]

            expect_login = module not in BASIC_REJECTED
            base = keys_rp if module == DISCOVERED_JWKS else rp
            response = follow_rp(browser, base)
            save(folder / "rp-response.json", response)
            errors = callback_errors(response, f"{base}/callback", expect_login)
            if module == ROTATION and not errors:
                second = follow_rp(browser, rp)
                save(folder / "rp-second-response.json", second)
                errors.extend(callback_errors(second, callback, True))
            if args.profile == "backchannel" and not errors:
                errors.extend(drive_logout(browser, module, folder))
            return response["status"], errors

    def drive_logout(browser, module, folder):
        check = f"{suite}/rp/session-status"
        before = browser.get(check, timeout=40).status_code
        forbidden = browser.post(f"{rp}/logout", timeout=40, allow_redirects=False).status_code
        csrf = browser.cookies.get(CSRF_COOKIE)
        intent = browser.post(f"{rp}/logout", data={"csrf_token": csrf}, timeout=40, allow_redirects=False)
        form = LogoutForm(intent.text)
        result = {"session_before": before, "without_csrf": forbidden, "intent_status": intent.status_code}
        if (
            intent.status_code != 200 or intent.headers.get("Cache-Control") != "no-store"
            or form.action != f"{suite}/test/a/{alias}/end_session_endpoint"
            or form.fields.get("post_logout_redirect_uri") != post_logout
            or not form.fields.get("id_token_hint")
        ):
            save(folder / "rp-logout.json", result)
            return ["the RP did not issue the upstream logout form"]
        op = browser.post(form.action, data=form.fields, timeout=40, allow_redirects=False)
        return_target = urljoin(form.action, op.headers.get("Location", ""))
        returned = browser.get(return_target, timeout=40, allow_redirects=False) if return_target == post_logout else None
        after = browser.get(check, timeout=40).status_code
        result.update({
            "end_session_status": op.status_code,
            "returned_to_registered_uri": returned is not None and returned.status_code == 200,
            "session_after": after,
        })
        save(folder / "rp-logout.json", result)
        expected_session = 401 if module == BACKCHANNEL_VALID else 200
        return [] if before == 200 and forbidden == 400 and result["returned_to_registered_uri"] and after == expected_session else [
            "logout did not preserve the expected return or local session behavior"
        ]

    variants = {"client_registration": "static_client", "request_type": "plain_http_request"}
    if args.profile != "basic":
        variants.update(client_auth_type="client_secret_basic", response_mode="default")
    config = {
        "alias": alias,
        "description": f"NazoAuth issue 202: {args.tested_commit}",
        "waitTimeoutSeconds": 5,
        "client": {
            "client_id": os.environ.get("OIDF_RP_CLIENT_ID", "nazoauth-issue202"),
            "client_secret": os.environ.get("OIDF_RP_CLIENT_SECRET", "nazoauth-issue202-test-secret"),
            "redirect_uri": callback,
            "id_token_signed_response_alg": "RS256",
        },
    }
    if args.profile == "backchannel":
        config["client"].update(
            backchannel_logout_uri=f"{rp}/backchannel-logout",
            backchannel_logout_session_required=True,
            post_logout_redirect_uri=post_logout,
        )
    if args.profile == "config":
        # This Suite module ends when JWKS is served. Use the RP's
        # authentication-only configuration, with its own registered callback.
        config["override"] = {
            DISCOVERED_JWKS: {"client": config["client"] | {"redirect_uri": f"{keys_rp}/callback"}},
        }
    suite_server = call("GET", "/api/server")
    save(args.output / "suite-server.json", suite_server)
    if (suite_server.get("version"), suite_server.get("tag"), suite_server.get("revision")) != (
        "5.3.4", "release-v5.3.4", "23353b3"
    ):
        raise RuntimeError("Suite runtime identity differs from the pinned tested image")
    save(args.output / "plan-definition.json", call("GET", f"/api/plan/info/{plan_name}"))
    plan = call("POST", "/api/plan", params={"planName": plan_name, "variant": json.dumps(variants)}, body=config)
    save(args.output / "created-plan.json", plan)
    plan_id = plan["id"]
    modules = plan["modules"]
    expected = PROFILE_MODULES[args.profile]
    if len(modules) != len(expected) or {entry["testModule"] for entry in modules} != expected:
        raise RuntimeError(f"Suite {plan_name} differs from its reviewed modules")
    summary = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "tested_commit": args.tested_commit,
        "suite_runtime": suite_server,
        "evidence_policy": "Temporary secrets, private JWK fields, token values and URL queries are redacted at export; Suite statuses, results and condition records are preserved.",
        "suite_origin": suite,
        "plan_name": plan_name,
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
                    record["rp_status"], record["application_errors"] = drive_profile(name, folder)
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
                "SKIPPED" if name == UNSIGNED else "PASSED"
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
