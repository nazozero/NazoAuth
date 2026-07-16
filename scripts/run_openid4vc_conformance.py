#!/usr/bin/env python3
"""Drive NazoAuth's issuer/verifier management APIs while the official OIDF runner executes.

The upstream OpenID4VC plans test an issuer or verifier, so they wait for the
implementation under test to initiate the flow. This wrapper is deliberately
small: it never reads protocol state from the database and can only observe the
OIDF API plus the public and management HTTP surfaces.
"""

from __future__ import annotations

import argparse
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


def module_entries(base_url: str, token: str, aliases: set[str]) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for plan in oidf.fetch_alias_plans(base_url, token, aliases):
        plan_name = plan.get("planName")
        for module_id in oidf.module_ids_from_plan(plan):
            status, info = oidf.oidf_api_request(
                "GET", base_url, f"api/info/{module_id}", token, expected_statuses={200, 404}
            )
            if status == 200 and isinstance(info, dict):
                entries.append({**info, "_driver_module_id": module_id, "_driver_plan": plan_name})
    return entries


class Openid4vcDriver:
    def __init__(self, config: dict[str, object], stop: threading.Event) -> None:
        self.config = config
        self.stop = stop
        self.triggered: set[str] = set()

    def run(self) -> None:
        interval = max(1, int(self.config.get("poll_interval_seconds", 2)))
        while not self.stop.wait(interval):
            try:
                self.drive_once()
            except Exception as exc:  # runner monitor remains authoritative
                print(f"OpenID4VC driver retryable error: {type(exc).__name__}: {exc}", flush=True)

    def drive_once(self) -> None:
        server = str(self.config["conformance_server"])
        token = str(self.config.get("conformance_token") or os.environ.get("OIDF_CONFORMANCE_TOKEN", ""))
        if not token:
            raise RuntimeError("OIDF conformance API token is required")
        aliases = {str(value) for value in self.config["aliases"]}
        for info in module_entries(server, token, aliases):
            module_id = str(info["_driver_module_id"])
            if module_id in self.triggered or str(info.get("status", "")).upper() != "WAITING":
                continue
            plan_name = str(info.get("_driver_plan", ""))
            variant = info.get("variant") if isinstance(info.get("variant"), dict) else {}
            if plan_name.startswith("oid4vci-"):
                if variant.get("vci_authorization_code_flow_variant") == "issuer_initiated":
                    self.drive_issuer(module_id, info, variant)
            elif plan_name.startswith("oid4vp-"):
                self.drive_verifier(module_id, info, variant, "haip" in plan_name)

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
        get_url(callback)
        self.triggered.add(module_id)
        print(f"OpenID4VC driver delivered credential offer to {module_id}", flush=True)

    def drive_verifier(self, module_id: str, info: dict[str, object], variant: dict[str, object], haip: bool) -> None:
        verifier = self.config["verifier"]
        alias = info.get("alias")
        if not isinstance(alias, str) or not alias:
            return
        format_name = str(variant.get("credential_format", "sd_jwt_vc"))
        dcql_format = "mso_mdoc" if format_name == "iso_mdl" else "dc+sd-jwt"
        prefix = str(variant.get("client_id_prefix", "x509_hash"))
        method = str(variant.get("request_method", "request_uri_signed"))
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
                        {"id": "credential", "format": dcql_format, "require_cryptographic_holder_binding": True}
                    ]
                },
                "haip": haip,
                "client_id_prefix": prefix,
                "request_method": (
                    "url_query" if method == "url_query" else str(verifier.get("signed_request_method", "request_uri_signed_post"))
                ),
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
