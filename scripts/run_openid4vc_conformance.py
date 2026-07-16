#!/usr/bin/env python3
"""Drive NazoAuth's issuer/verifier management APIs while the official OIDF runner executes.

The upstream OpenID4VC plans test an issuer or verifier, so they wait for the
implementation under test to initiate the flow. This wrapper is deliberately
small: it never reads protocol state from the database and can only observe the
OIDF API plus the public and management HTTP surfaces.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_oidf_conformance as oidf  # noqa: E402


PRE_AUTHORIZED_CODE_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
OIDF_TERMINAL_MODULE_STATUSES = {"FINISHED", "FAILED", "INTERRUPTED"}


def fail(message: str) -> None:
    raise SystemExit(message)


def request_json(method: str, url: str, token: str, payload: object | None = None) -> object:
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            **({"Content-Type": "application/json"} if body is not None else {}),
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        encoded = response.read()
    return json.loads(encoded) if encoded else {}


def get_url(url: str) -> None:
    with urllib.request.urlopen(url, timeout=30) as response:
        response.read()


def suite_reachable_url(conformance_server: str, url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.hostname not in {"nginx"}:
        return url
    base = urllib.parse.urlparse(conformance_server)
    if base.scheme not in {"http", "https"} or not base.netloc:
        raise RuntimeError("conformance_server must be an absolute HTTP(S) URL")
    return urllib.parse.urlunparse(
        (
            base.scheme,
            base.netloc,
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )


def module_entries(
    base_url: str,
    token: str | None,
    aliases: set[str],
    *,
    ignored_module_ids: set[str] | None = None,
    max_workers: int = 8,
) -> list[dict[str, object]]:
    ignored = ignored_module_ids or set()
    candidates: list[tuple[str, object]] = []
    for plan in oidf.fetch_alias_plans(base_url, token, aliases):
        plan_name = plan.get("planName")
        for module_id in sorted(oidf.module_ids_from_plan(plan)):
            if module_id not in ignored:
                candidates.append((module_id, plan_name))

    def fetch_entry(candidate: tuple[str, object]) -> dict[str, object] | None:
        module_id, plan_name = candidate
        status, info = oidf.oidf_api_request(
            "GET", base_url, f"api/info/{module_id}", token, expected_statuses={200, 404}
        )
        if status != 200 or not isinstance(info, dict):
            return None
        entry = {
            **info,
            "_driver_module_id": module_id,
            "_driver_plan": plan_name,
        }
        if str(info.get("status", "")).upper() != "WAITING":
            return entry
        runner_status, runner_info = oidf.oidf_api_request(
            "GET",
            base_url,
            f"api/runner/{module_id}",
            token,
            expected_statuses={200, 404},
        )
        exposed = (
            runner_info.get("exposed")
            if runner_status == 200 and isinstance(runner_info, dict)
            else None
        )
        return {**entry, **({"exposed": exposed} if isinstance(exposed, dict) else {})}

    if not candidates:
        return []
    workers = max(1, min(max_workers, len(candidates)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        return [
            entry
            for entry in executor.map(fetch_entry, candidates)
            if entry is not None
        ]


class Openid4vcDriver:
    def __init__(self, config: dict[str, object], stop: threading.Event) -> None:
        self.config = config
        self.stop = stop
        self.triggered: set[str] = set()
        self.terminal_modules: set[str] = set()

    def run(self) -> None:
        interval = max(1, int(self.config.get("poll_interval_seconds", 2)))
        while not self.stop.is_set():
            try:
                self.drive_once()
            except Exception as exc:  # runner monitor remains authoritative
                print(f"OpenID4VC driver retryable error: {type(exc).__name__}: {exc}", flush=True)
            if self.stop.wait(interval):
                break

    def drive_once(self) -> None:
        server = str(self.config["conformance_server"])
        no_api_token = self.config.get("conformance_no_api_token") is True
        hostname = urllib.parse.urlparse(server).hostname
        if no_api_token and hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise RuntimeError("tokenless conformance API access is restricted to loopback")
        configured_token = str(
            self.config.get("conformance_token") or os.environ.get("OIDF_CONFORMANCE_TOKEN", "")
        )
        token = None if no_api_token else configured_token
        if token == "":
            raise RuntimeError("OIDF conformance API token is required")
        aliases = {str(value) for value in self.config["aliases"]}
        max_workers = int(self.config.get("driver_scan_workers", 8))
        start = time.monotonic()
        entries = module_entries(
            server,
            token,
            aliases,
            ignored_module_ids=self.triggered | self.terminal_modules,
            max_workers=max_workers,
        )
        triggered_before = len(self.triggered)
        for info in entries:
            module_id = str(info["_driver_module_id"])
            status = str(info.get("status", "")).upper()
            if status in OIDF_TERMINAL_MODULE_STATUSES:
                self.terminal_modules.add(module_id)
                continue
            if module_id in self.triggered or status != "WAITING":
                continue
            plan_name = str(info.get("_driver_plan", ""))
            variant = info.get("variant") if isinstance(info.get("variant"), dict) else {}
            if plan_name.startswith("oid4vci-"):
                if variant.get("vci_authorization_code_flow_variant") == "issuer_initiated":
                    self.drive_issuer(module_id, info, variant)
            elif plan_name.startswith("oid4vp-"):
                self.drive_verifier(module_id, info, variant, "haip" in plan_name)
        if entries:
            print(
                "OpenID4VC driver scan completed: "
                f"{len(entries)} live modules, "
                f"{len(self.terminal_modules)} cached terminal, "
                f"{len(self.triggered) - triggered_before} newly triggered, "
                f"{time.monotonic() - start:.2f}s",
                flush=True,
            )

    def drive_issuer(self, module_id: str, info: dict[str, object], variant: dict[str, object]) -> None:
        exposed = info.get("exposed")
        endpoint = exposed.get("credential_offer_endpoint") if isinstance(exposed, dict) else None
        if not isinstance(endpoint, str) or not endpoint.startswith("https://"):
            return
        issuer = self.config["issuer"]
        format_name = str(variant.get("credential_format", "sd_jwt_vc"))
        configuration_ids = issuer["credential_configuration_ids"]
        configuration_id = str(configuration_ids[format_name])
        grant = str(variant.get("vci_grant_type", "authorization_code"))
        grant_type = PRE_AUTHORIZED_CODE_GRANT if grant == "pre_authorization_code" else "authorization_code"
        tx_code = issuer.get("tx_code") if grant == "pre_authorization_code" else None
        offer = request_json(
            "POST",
            urllib.parse.urljoin(str(self.config["target_origin"]), "/openid4vci/offers"),
            str(issuer["management_token"]),
            {
                "subject_id": issuer["subject_id"],
                "credential_configuration_ids": [configuration_id],
                "grant_types": [grant_type],
                **({"tx_code": tx_code} if tx_code else {}),
                "expires_in": 300,
            },
        )
        if issuer.get("offer_delivery", "uri") == "value":
            value = json.dumps(offer["credential_offer"], separators=(",", ":"))
            callback = f"{endpoint}?{urllib.parse.urlencode({'credential_offer': value})}"
        else:
            callback = f"{endpoint}?{urllib.parse.urlencode({'credential_offer_uri': offer['credential_offer_uri']})}"
        get_url(suite_reachable_url(str(self.config["conformance_server"]), callback))
        self.triggered.add(module_id)
        print(f"OpenID4VC driver delivered credential offer to {module_id}", flush=True)

    def drive_verifier(self, module_id: str, info: dict[str, object], variant: dict[str, object], haip: bool) -> None:
        verifier = self.config["verifier"]
        alias = info.get("alias")
        if not isinstance(alias, str) or not alias:
            return
        format_name = str(variant.get("credential_format", "sd_jwt_vc"))
        dcql_format = "mso_mdoc" if format_name == "iso_mdl" else "dc+sd-jwt"
        credential_type_values = verifier.get("credential_type_values")
        if not isinstance(credential_type_values, dict):
            raise RuntimeError("verifier credential_type_values are required")
        credential_type = credential_type_values.get(format_name)
        if not isinstance(credential_type, str) or not credential_type:
            raise RuntimeError(f"verifier credential type is missing for {format_name}")
        credential_meta = (
            {"doctype_value": credential_type}
            if dcql_format == "mso_mdoc"
            else {"vct_values": [credential_type]}
        )
        prefix = str(variant.get("client_id_prefix", "x509_hash"))
        method = str(variant.get("request_method", "request_uri_signed"))
        test_name = str(info.get("testName", ""))
        request_method = (
            "url_query"
            if method == "url_query"
            else "request_uri_signed_post"
            if test_name == "oid4vp-1final-verifier-request-uri-method-post"
            else "request_uri_signed_get"
        )
        response_mode = str(variant.get("response_mode", "direct_post.jwt" if haip else "direct_post"))
        wallet_endpoint = urllib.parse.urljoin(
            str(self.config["conformance_server"]), f"/test/a/{alias}/authorize"
        )
        created = request_json(
            "POST",
            urllib.parse.urljoin(str(self.config["target_origin"]), "/openid4vp/presentations"),
            str(verifier["management_token"]),
            {
                "wallet_authorization_endpoint": wallet_endpoint,
                "dcql_query": {
                    "credentials": [
                        {
                            "id": "credential",
                            "format": dcql_format,
                            "meta": credential_meta,
                            "require_cryptographic_holder_binding": True,
                        }
                    ]
                },
                "haip": haip,
                "client_id_prefix": prefix,
                "request_method": request_method,
                "response_mode": response_mode,
            },
        )
        authorization_url = created.get("authorization_url") if isinstance(created, dict) else None
        if not isinstance(authorization_url, str):
            raise RuntimeError("verifier management response lacks authorization_url")
        get_url(authorization_url)
        self.triggered.add(module_id)
        print(f"OpenID4VC driver initiated presentation for {module_id}", flush=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--driver-config-json-file", required=True)
    parser.add_argument("runner_args", nargs=argparse.REMAINDER)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    runner_args = args.runner_args[1:] if args.runner_args[:1] == ["--"] else args.runner_args
    if not runner_args:
        fail("arguments for run_oidf_conformance.py are required after --")
    config = json.loads(Path(args.driver_config_json_file).read_text(encoding="utf-8"))
    if "--no-api-token" in runner_args:
        config["conformance_no_api_token"] = True
    stop = threading.Event()
    driver = Openid4vcDriver(config, stop)
    thread = threading.Thread(target=driver.run, name="openid4vc-oidf-driver", daemon=True)
    thread.start()
    command = [sys.executable, str(Path(__file__).with_name("run_oidf_conformance.py")), *runner_args]
    try:
        return subprocess.run(command, check=False).returncode
    finally:
        stop.set()
        thread.join(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
