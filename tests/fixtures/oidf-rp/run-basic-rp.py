#!/usr/bin/env python3
"""Exercise the original OIDF Basic RP plan against the NazoAuth HTTP fixture.

This is a run driver, not an alternate RP implementation. It preserves Suite
results and local responses separately. WAITING at the deadline stays incomplete.
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
SUITE_SOURCE = "23353b36957d6466010de767c812d2c91ed37638"
TERMINAL = {"FINISHED", "INTERRUPTED"}


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def without_query(url):
    parts = urlsplit(url)
    return parts._replace(query="", fragment="").geturl()


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
            return {
                "hops": hops,
                "status": response.status_code,
                "body": response.text,
                "cookie_names": sorted({cookie.name for cookie in browser.cookies}),
            }
        raise RuntimeError("RP flow exceeded ten redirects")

    variants = {"client_registration": "static_client", "request_type": "plain_http_request"}
    config = {
        "alias": args.alias,
        "description": f"NazoAuth issue 202 baseline: {args.tested_commit}",
        "waitTimeoutSeconds": 5,
        "client": {
            "client_id": os.environ.get("OIDF_RP_CLIENT_ID", "nazoauth-issue202"),
            "client_secret": os.environ.get("OIDF_RP_CLIENT_SECRET", "nazoauth-issue202-test-secret"),
            "redirect_uri": args.callback,
            "id_token_signed_response_alg": "RS256",
        },
    }
    save(args.output / "suite-server.json", call("GET", "/api/server"))
    save(args.output / "plan-definition.json", call("GET", f"/api/plan/info/{PLAN}"))
    plan = call("POST", "/api/plan", params={"planName": PLAN, "variant": json.dumps(variants)}, body=config)
    save(args.output / "created-plan.json", plan)
    plan_id = plan["id"]
    modules = plan["modules"]
    summary = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "tested_commit": args.tested_commit,
        "suite_source_reference": SUITE_SOURCE,
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
                except Exception as error:
                    record["rp_driver_error"] = str(error)
                    save(folder / "rp-driver-error.json", {"error": str(error)})
                observed = wait(module_id, TERMINAL, args.finish_timeout)
            else:
                observed = ready
            save(folder / "info-observed.json", observed)
            save(folder / "logs-observed.json", call("GET", f"/api/log/{module_id}"))
            record["status"] = observed.get("status")
            record["result"] = observed.get("result")
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
        print(json.dumps(record, ensure_ascii=False), flush=True)

    save(args.output / "plan-final.json", call("GET", f"/api/plan/{plan_id}"))
    summary["finished_at"] = datetime.now(timezone.utc).isoformat()
    summary["result_counts"] = dict(Counter(row.get("result", "UNKNOWN") for row in summary["results"]))
    summary["status_counts"] = dict(Counter(row.get("status", "UNKNOWN") for row in summary["results"]))
    summary["incomplete_count"] = sum(row.get("incomplete", True) for row in summary["results"])
    summary["rp_driver_error_count"] = sum("rp_driver_error" in row for row in summary["results"])
    save(args.output / "summary.json", summary)
    print(json.dumps({key: summary[key] for key in ("plan_id", "declared_modules", "result_counts", "status_counts", "incomplete_count", "rp_driver_error_count")}, ensure_ascii=False), flush=True)
    failed = any(row.get("status") != "FINISHED" or row.get("result") not in {"PASSED", "WARNING", "SKIPPED", "REVIEW"} or "rp_driver_error" in row for row in summary["results"])
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
