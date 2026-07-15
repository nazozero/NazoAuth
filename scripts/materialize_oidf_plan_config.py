#!/usr/bin/env python3
"""Materialize OIDF plan config templates with secret patches."""

from __future__ import annotations

import argparse
import base64
import copy
import gzip
import json
import os
from pathlib import Path
from typing import Any

OIDCC_BASIC_CONFIG_FILE = "oidf-oidcc-basic-plan-config.json"
OIDCC_DYNAMIC_CONFIG_FILE = "oidf-oidcc-dynamic-plan-config.json"
OIDCC_FORMPOST_CONFIG_FILE = "oidf-oidcc-formpost-plan-config.json"
OIDCC_THIRD_PARTY_INIT_CONFIG_FILE = "oidf-oidcc-third-party-init-plan-config.json"
FAPI_CIBA_SOURCE_CONFIG_FILE = (
    "oidf-fapi-ciba-plain-private-key-jwt-poll-plan-config.json"
)
FAPI_CIBA_MATRIX = (
    ("private_key_jwt", "poll"),
    ("mtls", "poll"),
    ("private_key_jwt", "ping"),
    ("mtls", "ping"),
)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def secret_patch_from_env(prefix: str) -> dict[str, Any]:
    parts: list[str] = []
    for index in range(1, 21):
        value = os.environ.get(f"{prefix}_{index:02d}", "").strip()
        if value:
            parts.append(value)
    if not parts:
        raise SystemExit(f"{prefix}_01 secret patch chunk is required")
    payload = gzip.decompress(base64.b64decode("".join(parts)))
    patch = json.loads(payload.decode("utf-8"))
    if not isinstance(patch, dict):
        raise SystemExit("OIDF secret patch must be a JSON object")
    return patch


def secret_patch_from_file(path: Path) -> dict[str, Any]:
    patch = read_json(path)
    if not isinstance(patch, dict):
        raise SystemExit("OIDF secret patch file must contain a JSON object")
    return patch


def materialize(value: Any, patch: dict[str, Any]) -> Any:
    if isinstance(value, dict):
        secret = value.get("$secret")
        if isinstance(secret, str):
            if set(value) != {"$secret"}:
                raise SystemExit(f"secret placeholder has unexpected keys: {secret}")
            if secret not in patch:
                raise SystemExit(f"missing secret patch value for {secret}")
            return patch[secret]
        return {key: materialize(child, patch) for key, child in value.items()}
    if isinstance(value, list):
        return [materialize(child, patch) for child in value]
    return value


def derive_dynamic_oidcc_config(rendered: dict[str, Any], initial_access_token: str) -> None:
    configs = rendered.get("configs")
    if not isinstance(configs, dict):
        raise SystemExit("OIDF config root must contain a configs object")

    basic = configs.get(OIDCC_BASIC_CONFIG_FILE)
    if not isinstance(basic, dict):
        raise SystemExit(f"missing {OIDCC_BASIC_CONFIG_FILE} config to derive dynamic OIDC config")
    if OIDCC_DYNAMIC_CONFIG_FILE in configs:
        raise SystemExit(f"{OIDCC_DYNAMIC_CONFIG_FILE} already exists in rendered configs")
    dynamic = copy.deepcopy(basic)
    dynamic["alias"] = f"{basic.get('alias', 'nazo-oauth-oidf-basic')}-dynamic"
    dynamic["description"] = "OIDC Basic OP: RFC 7591 dynamic client registration."

    for client_key in ("client", "client2", "client_secret_post"):
        source = basic.get(client_key)
        if not isinstance(source, dict):
            raise SystemExit(f"missing {client_key} object in {OIDCC_BASIC_CONFIG_FILE}")
        scope = source.get("scope")
        dynamic[client_key] = {"initial_access_token": initial_access_token}
        if isinstance(scope, str):
            dynamic[client_key]["scope"] = scope

    configs[OIDCC_DYNAMIC_CONFIG_FILE] = dynamic
    formpost = copy.deepcopy(basic)
    formpost["alias"] = f"{basic.get('alias', 'nazo-oauth-oidf-basic')}-formpost"
    formpost["description"] = "OIDC Form Post OP certification coverage."
    configs[OIDCC_FORMPOST_CONFIG_FILE] = formpost

    third_party = copy.deepcopy(dynamic)
    third_party["alias"] = (
        f"{basic.get('alias', 'nazo-oauth-oidf-basic')}-third-party-init"
    )
    third_party["description"] = (
        "OIDC third-party initiated login registration coverage."
    )
    configs[OIDCC_THIRD_PARTY_INIT_CONFIG_FILE] = third_party


def _ciba_slug(client_auth_type: str, ciba_mode: str) -> str:
    auth_slug = "private-key-jwt" if client_auth_type == "private_key_jwt" else "mtls"
    return f"fapi-ciba-plain-{auth_slug}-{ciba_mode}"


def _replace_client_identity(client: dict[str, Any], source_slug: str, target_slug: str) -> None:
    client_id = client.get("client_id")
    if not isinstance(client_id, str) or source_slug not in client_id:
        raise SystemExit("FAPI-CIBA source client_id does not contain its profile slug")
    client["client_id"] = client_id.replace(source_slug, target_slug)
    jwks = client.get("jwks")
    keys = jwks.get("keys") if isinstance(jwks, dict) else None
    if not isinstance(keys, list) or not keys:
        raise SystemExit("FAPI-CIBA source client must contain signing keys")
    for key in keys:
        if isinstance(key, dict) and isinstance(key.get("kid"), str):
            key["kid"] = key["kid"].replace(source_slug, target_slug)


def derive_fapi_ciba_matrix_configs(
    rendered: dict[str, Any], notification_base_url: str
) -> None:
    configs = rendered.get("configs")
    if not isinstance(configs, dict):
        raise SystemExit("OIDF config root must contain a configs object")
    source = configs.get(FAPI_CIBA_SOURCE_CONFIG_FILE)
    if not isinstance(source, dict):
        raise SystemExit(
            f"missing {FAPI_CIBA_SOURCE_CONFIG_FILE} config to derive FAPI-CIBA matrix"
        )
    notification_base_url = notification_base_url.rstrip("/")
    if not notification_base_url.startswith("https://"):
        raise SystemExit("FAPI-CIBA notification base URL must use HTTPS")
    source_slug = _ciba_slug("private_key_jwt", "poll")

    for client_auth_type, ciba_mode in FAPI_CIBA_MATRIX:
        target_slug = _ciba_slug(client_auth_type, ciba_mode)
        filename = f"oidf-{target_slug}-plan-config.json"
        if filename == FAPI_CIBA_SOURCE_CONFIG_FILE:
            config = source
        else:
            if filename in configs:
                raise SystemExit(f"{filename} already exists in rendered configs")
            config = copy.deepcopy(source)
            configs[filename] = config
            alias = config.get("alias")
            if not isinstance(alias, str) or source_slug not in alias:
                raise SystemExit("FAPI-CIBA source alias does not contain its profile slug")
            config["alias"] = alias.replace(source_slug, target_slug)
            for client_key in ("client", "client2"):
                client = config.get(client_key)
                if not isinstance(client, dict):
                    raise SystemExit(f"missing {client_key} object in {filename}")
                _replace_client_identity(client, source_slug, target_slug)

        config["description"] = (
            "FAPI-CIBA ID1 AS: plain FAPI profile with "
            f"{client_auth_type} client authentication and {ciba_mode} delivery mode."
        )
        for client_key in ("client", "client2"):
            client = config.get(client_key)
            if not isinstance(client, dict):
                raise SystemExit(f"missing {client_key} object in {filename}")
            client["backchannel_token_delivery_mode"] = ciba_mode
            client["backchannel_authentication_request_signing_alg"] = "PS256"
            client["backchannel_user_code_parameter"] = False
            if ciba_mode == "ping":
                client["backchannel_client_notification_endpoint"] = (
                    f"{notification_base_url.rstrip('/')}/test/a/{config['alias']}"
                    "/ciba-notification-endpoint"
                )
            else:
                client.pop("backchannel_client_notification_endpoint", None)
        nazo = config.setdefault("nazo", {})
        if not isinstance(nazo, dict):
            raise SystemExit(f"{filename}.nazo must be an object")
        nazo.update(
            {
                "client_auth_type": client_auth_type,
                "sender_constrain": "mtls",
                "fapi_ciba_profile": "plain_fapi",
                "ciba_mode": ciba_mode,
                "matrix_title": (
                    f"FAPI-CIBA ID1 / {client_auth_type} / {ciba_mode} / plain FAPI"
                ),
            }
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--template", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--secret-patch-file",
        type=Path,
        default=None,
        help="read the secret patch JSON object from this file",
    )
    parser.add_argument(
        "--secret-prefix",
        default="OIDF_PLAN_CONFIG_SECRET_PATCH_GZ_B64",
        help="environment variable prefix for gzip+base64 secret patch chunks",
    )
    parser.add_argument(
        "--derive-dynamic-oidcc-config",
        action="store_true",
        help="derive RFC 7591 dynamic OIDC Basic config from the static OIDC Basic config",
    )
    parser.add_argument(
        "--dynamic-registration-token-env",
        default="OIDF_DYNAMIC_REGISTRATION_INITIAL_ACCESS_TOKEN",
        help="environment variable containing the RFC 7591 initial access token",
    )
    parser.add_argument(
        "--derive-fapi-ciba-matrix-configs",
        action="store_true",
        help="derive the four orthogonal FAPI-CIBA static-client configurations",
    )
    parser.add_argument(
        "--ciba-notification-base-url",
        default="https://www.certification.openid.net",
        help="OIDF suite base URL used by ping notification endpoints",
    )
    args = parser.parse_args()

    template = read_json(args.template)
    patch = (
        secret_patch_from_file(args.secret_patch_file)
        if args.secret_patch_file is not None
        else secret_patch_from_env(args.secret_prefix)
    )
    rendered = materialize(template, patch)
    if args.derive_dynamic_oidcc_config:
        initial_access_token = os.environ.get(args.dynamic_registration_token_env, "")
        if not initial_access_token:
            raise SystemExit(f"{args.dynamic_registration_token_env} is required")
        if not isinstance(rendered, dict):
            raise SystemExit("OIDF rendered config must be a JSON object")
        derive_dynamic_oidcc_config(rendered, initial_access_token)
    if args.derive_fapi_ciba_matrix_configs:
        if not isinstance(rendered, dict):
            raise SystemExit("OIDF rendered config must be a JSON object")
        derive_fapi_ciba_matrix_configs(rendered, args.ciba_notification_base_url)
    args.output.write_text(json.dumps(rendered, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
