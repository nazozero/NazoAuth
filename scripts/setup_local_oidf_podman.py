#!/usr/bin/env python3
"""Prepare gitignored local files for Podman OIDF conformance runs."""

from __future__ import annotations

import json
import os
import subprocess
import copy
import base64
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "runtime" / "oidf"
ISSUER = os.environ.get("OIDF_LOCAL_ISSUER", "https://host.containers.internal:9443").rstrip("/")
SUITE_BASE_URL = os.environ.get("OIDF_LOCAL_SUITE_BASE_URL", "https://nginx:8443").rstrip("/")
BASIC_ALIAS = os.environ.get("OIDF_LOCAL_BASIC_ALIAS", "local-nazo-oauth-oidf")
USER_EMAIL = os.environ.get("OIDF_LOCAL_USER_EMAIL", "oidf-local@example.test")
USER_PASSWORD = os.environ.get("OIDF_LOCAL_USER_PASSWORD", "oidf-local-password")
CLIENT_SECRET = os.environ.get("OIDF_LOCAL_CLIENT_SECRET", "oidf-local-client-secret")
FAPI_CLIENT_PREFIX = os.environ.get("OIDF_LOCAL_FAPI_CLIENT_PREFIX", "local-oidf-fapi")
OIDCC_SECOND_LOGIN_SCREENSHOT_MODULES = (
    "oidcc-prompt-login",
    "oidcc-max-age-1",
)
OIDCC_REGISTERED_REDIRECT_URI_MODULE = "oidcc-ensure-registered-redirect-uri"
FAPI_SECURITY_FINAL_PAR_REUSE_BEFORE_AUTH = (
    "fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds"
)
FAPI_SECURITY_ID2_PAR_REUSE_BEFORE_AUTH = (
    "fapi2-security-profile-id2-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds"
)
FAPI_SECURITY_FINAL_USER_REJECTS_AUTHENTICATION = (
    "fapi2-security-profile-final-user-rejects-authentication"
)
FAPI_SECURITY_ID2_USER_REJECTS_AUTHENTICATION = (
    "fapi2-security-profile-id2-user-rejects-authentication"
)
PLAN_CONFIG_FILES = (
    "oidf-oidcc-basic-plan-config.json",
    "oidf-oidcc-config-plan-config.json",
    "oidf-fapi-security-final-plan-config.json",
    "oidf-fapi-message-final-plan-config.json",
    "oidf-fapi-security-id2-plan-config.json",
    "oidf-fapi-message-id1-plan-config.json",
)


def write_text(path: Path, body: str, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    if mode is not None:
        path.chmod(mode)


def ensure_cert() -> None:
    cert_dir = RUNTIME / "certs"
    cert = cert_dir / "oidf.crt"
    key = cert_dir / "oidf.key"
    if cert.is_file() and key.is_file():
        return
    cert_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "30",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-subj",
            "/CN=host.containers.internal",
            "-addext",
            "subjectAltName=DNS:host.containers.internal,DNS:localhost,IP:127.0.0.1",
        ],
        check=True,
        cwd=ROOT,
    )
    key.chmod(0o600)


def write_env_yaml() -> None:
    write_text(
        ROOT / ".env.yaml",
        f"""BIND: "0.0.0.0:8000"
DATABASE_URL: "postgresql://postgres:postgres@postgres:5432/oauth"
VALKEY_URL: "redis://valkey:6379/0"
ISSUER: "{ISSUER}"
FRONTEND_BASE_URL: "{ISSUER}/ui"
CORS_ALLOWED_ORIGINS:
  - "{ISSUER}"
COOKIE_SECURE: true
DEFAULT_AUDIENCE: "resource://default"
EMAIL_DELIVERY: "disabled"
AVATAR_STORAGE_DIR: "/var/lib/nazo_oauth/avatars"
JWK_KEYS_DIR: "/var/lib/nazo_oauth/keys"
RUST_LOG: "info"
""",
        0o600,
    )


def write_nginx() -> None:
    write_text(
        RUNTIME / "nginx.conf",
        """events {}

http {
  server {
    listen 9443 ssl;
    server_name _;

    ssl_certificate /etc/nginx/certs/oidf.crt;
    ssl_certificate_key /etc/nginx/certs/oidf.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;

    location = /ui/auth {
      root /usr/share/nginx/html;
      try_files /ui/auth/index.html =404;
    }

    location = /ui/consent {
      root /usr/share/nginx/html;
      try_files /ui/consent/index.html =404;
    }

    location / {
      proxy_pass http://nazo-oauth-server:8000;
      proxy_set_header Host $host;
      proxy_set_header X-Forwarded-Proto https;
      proxy_set_header X-Forwarded-Host $host;
      proxy_set_header X-Forwarded-Port 9443;
    }
  }
}
""",
    )


def write_ui() -> None:
    auth_template = (ROOT / "deploy" / "conformance-ui" / "auth" / "index.html.template").read_text(
        encoding="utf-8"
    )
    auth_html = auth_template.replace("__OIDF_USER_EMAIL_JSON__", json.dumps(USER_EMAIL)).replace(
        "__OIDF_USER_PASSWORD_JSON__", json.dumps(USER_PASSWORD)
    )
    write_text(RUNTIME / "ui" / "auth" / "index.html", auth_html)
    consent_html = (ROOT / "deploy" / "conformance-ui" / "consent" / "index.html").read_text(
        encoding="utf-8"
    )
    write_text(RUNTIME / "ui" / "consent" / "index.html", consent_html)


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def openssl_hex_field(text: str, label: str) -> bytes:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.strip() == f"{label}:":
            hex_lines: list[str] = []
            for candidate in lines[index + 1 :]:
                stripped = candidate.strip()
                if not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2})*:?", stripped):
                    break
                hex_lines.append(stripped)
            if not hex_lines:
                break
            raw = bytes.fromhex("".join(line.replace(":", "") for line in hex_lines))
            return raw[1:] if len(raw) > 1 and raw[0] == 0 else raw
    else:
        raise RuntimeError(f"openssl rsa output is missing {label}")
    raise RuntimeError(f"openssl rsa output is missing {label}")


def openssl_public_exponent(text: str) -> bytes:
    match = re.search(r"publicExponent:\s+(\d+)", text)
    if match is None:
        raise RuntimeError("openssl rsa output is missing publicExponent")
    return int(match.group(1)).to_bytes(3, "big")


def generate_rsa_jwk(kid: str) -> dict[str, str]:
    key_dir = RUNTIME / "keys"
    key_dir.mkdir(parents=True, exist_ok=True)
    pem = key_dir / f"{kid}.pem"
    if not pem.is_file():
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                str(pem),
            ],
            check=True,
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        pem.chmod(0o600)
    result = subprocess.run(
        ["openssl", "rsa", "-in", str(pem), "-text", "-noout"],
        check=True,
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    text = result.stdout
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "PS256",
        "n": b64url(openssl_hex_field(text, "modulus")),
        "e": b64url(openssl_public_exponent(text)),
        "d": b64url(openssl_hex_field(text, "privateExponent")),
        "p": b64url(openssl_hex_field(text, "prime1")),
        "q": b64url(openssl_hex_field(text, "prime2")),
        "dp": b64url(openssl_hex_field(text, "exponent1")),
        "dq": b64url(openssl_hex_field(text, "exponent2")),
        "qi": b64url(openssl_hex_field(text, "coefficient")),
    }


def client_private_jwks(client_id: str) -> dict[str, object]:
    path = RUNTIME / "keys" / f"{client_id}-jwks.json"
    jwks = {"keys": [generate_rsa_jwk(f"{client_id}-ps256")]}
    write_text(path, json.dumps(jwks, indent=2) + "\n", 0o600)
    return jwks


def public_jwks(private_jwks: dict[str, object]) -> dict[str, object]:
    private_fields = {"d", "p", "q", "dp", "dq", "qi", "oth"}
    keys = []
    for key in private_jwks.get("keys", []):
        if isinstance(key, dict):
            keys.append({name: value for name, value in key.items() if name not in private_fields})
    return {"keys": keys}


def callback_for(alias: str) -> str:
    return f"{SUITE_BASE_URL}/test/a/{alias}/callback"


def mark_login_page_wait_as_placeholder_update(task: object) -> None:
    if not isinstance(task, dict):
        return
    commands = task.get("commands")
    if not isinstance(commands, list):
        return

    for command in commands:
        if not isinstance(command, list) or len(command) < 5:
            continue
        if command[:5] != [
            "wait",
            "id",
            "oidf_conformance_interaction",
            5,
            "OIDF conformance login page",
        ]:
            continue
        if len(command) == 5:
            command.append("update-image-placeholder-optional")
        elif command[5] in {None, ""}:
            command[5] = "update-image-placeholder-optional"


def browser_automation_with_second_login_placeholder(browser: list[object]) -> list[object]:
    automation: list[object] = []
    for entry in browser:
        if not isinstance(entry, dict):
            automation.append(copy.deepcopy(entry))
            continue

        match = entry.get("match")
        if not (isinstance(match, str) and match == f"{ISSUER}/authorize*"):
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
        if not (isinstance(match, str) and match == f"{ISSUER}/authorize*"):
            automation.append(copy.deepcopy(entry))
            continue

        automation.append(
            {
                "comment": (
                    "This module requires the first authorization endpoint visit to stop "
                    "at the login page without authenticating."
                ),
                "match": match,
                "match-limit": 1,
                "tasks": [
                    {
                        "task": "Observe first login page without authentication",
                        "match": f"{ISSUER}/ui/auth*",
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
        )

        second_authorization = copy.deepcopy(entry)
        second_authorization.pop("match-limit", None)
        automation.append(second_authorization)

    return automation


def user_reject_browser_automation() -> list[dict[str, object]]:
    return [
        {
            "comment": (
                "Local Podman Nazo OAuth signs in after an explicit browser click, "
                "then lets this negative module deny consent before auto-approval."
            ),
            "match": f"{ISSUER}/authorize*",
            "tasks": [
                {
                    "task": "Complete login page",
                    "optional": True,
                    "match": f"{ISSUER}/ui/auth*",
                    "commands": [
                        ["wait", "id", "oidf_conformance_interaction", 5, "OIDF conformance login page"],
                        ["click", "id", "oidf_conformance_login"],
                        ["wait", "contains", "/ui/consent", 30],
                    ],
                },
                {
                    "task": "Deny consent page",
                    "match": f"{ISSUER}/ui/consent*",
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


def browser_automation() -> list[dict[str, object]]:
    return [
        {
            "comment": "Local Podman Nazo OAuth conformance browser automation.",
            "match": f"{ISSUER}/authorize*",
            "tasks": [
                {
                    "task": "Capture authorization error page",
                    "optional": True,
                    "match": f"{ISSUER}/authorize*",
                    "commands": [
                        [
                            "wait",
                            "id",
                            "oidf_conformance_interaction",
                            5,
                            "(invalid_request|invalid_request_object|access_denied|login_required|server_error)",
                            "update-image-placeholder-optional",
                        ]
                    ],
                },
                {
                    "task": "Complete login page",
                    "optional": True,
                    "match": f"{ISSUER}/ui/auth*",
                    "commands": [
                        ["wait", "id", "oidf_conformance_interaction", 5, "OIDF conformance login page"],
                        ["click", "id", "oidf_conformance_login"],
                        ["wait", "contains", "/ui/consent", 30],
                    ],
                },
                {
                    "task": "Complete consent page",
                    "optional": True,
                    "match": f"{ISSUER}/ui/consent*",
                    "commands": [
                        ["wait", "id", "oidf_conformance_interaction", 10, "OIDF conformance consent page"],
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


def redirect_error_browser_automation() -> list[dict[str, object]]:
    return [
        {
            "comment": "Capture the local authorization error page for redirect_uri rejection.",
            "match": f"{ISSUER}/authorize*",
            "tasks": [
                {
                    "task": "Capture authorization error page",
                    "match": f"{ISSUER}/authorize*",
                    "commands": [
                        [
                            "wait",
                            "id",
                            "oidf_conformance_interaction",
                            5,
                            "(invalid_request|invalid_request_object|access_denied|login_required|server_error)",
                            "update-image-placeholder-optional",
                        ]
                    ],
                }
            ],
        }
    ]


def fapi_overrides(browser: list[object], include_id2: bool) -> dict[str, object]:
    override: dict[str, object] = {
        module_name: {
            "browser": copy.deepcopy(browser_automation_with_second_login_placeholder(browser))
        }
        for module_name in OIDCC_SECOND_LOGIN_SCREENSHOT_MODULES
    }
    override[FAPI_SECURITY_FINAL_PAR_REUSE_BEFORE_AUTH] = {
        "browser": first_login_observation_automation(browser)
    }
    override[FAPI_SECURITY_FINAL_USER_REJECTS_AUTHENTICATION] = {
        "browser": user_reject_browser_automation()
    }
    if include_id2:
        override[FAPI_SECURITY_ID2_PAR_REUSE_BEFORE_AUTH] = {
            "browser": first_login_observation_automation(browser)
        }
        override[FAPI_SECURITY_ID2_USER_REJECTS_AUTHENTICATION] = {
            "browser": user_reject_browser_automation()
        }
    return override


def write_plan_config(name: str, config: dict[str, object]) -> None:
    write_text(RUNTIME / name, json.dumps(config, indent=2) + "\n", 0o600)


def write_basic_plan_config() -> None:
    browser = browser_automation()
    config = {
        "alias": BASIC_ALIAS,
        "description": "Local Podman Nazo OAuth OIDCC basic conformance configuration",
        "server": {"discoveryUrl": f"{ISSUER}/.well-known/openid-configuration"},
        "client": {
            "client_id": "local-oidf-basic-client",
            "client_secret": CLIENT_SECRET,
            "scope": "openid profile email address phone offline_access",
        },
        "client2": {
            "client_id": "local-oidf-basic-client-2",
            "client_secret": CLIENT_SECRET,
            "scope": "openid profile email address phone offline_access",
        },
        "client_secret_post": {
            "client_id": "local-oidf-post-client",
            "client_secret": CLIENT_SECRET,
            "scope": "openid profile email address phone offline_access",
        },
        "browser": browser,
        "override": {
            module_name: {
                "browser": copy.deepcopy(browser_automation_with_second_login_placeholder(browser))
            }
            for module_name in OIDCC_SECOND_LOGIN_SCREENSHOT_MODULES
        },
    }
    config["override"][OIDCC_REGISTERED_REDIRECT_URI_MODULE] = {
        "browser": redirect_error_browser_automation()
    }
    write_plan_config("oidf-oidcc-basic-plan-config.json", config)
    return config


def fapi_client_config(client_id: str, private_jwks: dict[str, object]) -> dict[str, object]:
    return {
        "client_id": client_id,
        "jwks": private_jwks,
        "scope": "openid profile email offline_access",
        "dpop_signing_alg": "ES256",
    }


def write_oidcc_config_plan_config() -> dict[str, object]:
    config = {
        "alias": "local-nazo-oauth-oidf-config",
        "description": "Local Podman Nazo OAuth OIDCC config conformance configuration",
        "server": {"discoveryUrl": f"{ISSUER}/.well-known/openid-configuration"},
    }
    write_plan_config("oidf-oidcc-config-plan-config.json", config)
    return config


def fapi_client_ids(plan_slug: str) -> tuple[str, str]:
    return (
        f"{FAPI_CLIENT_PREFIX}-{plan_slug}-client-1",
        f"{FAPI_CLIENT_PREFIX}-{plan_slug}-client-2",
    )


def fapi_plan_config(
    alias: str,
    description: str,
    plan_slug: str,
    include_id2_overrides: bool,
) -> dict[str, object]:
    browser = browser_automation()
    client1_id, client2_id = fapi_client_ids(plan_slug)
    client1_jwks = client_private_jwks(client1_id)
    client2_jwks = client_private_jwks(client2_id)
    return {
        "alias": alias,
        "description": description,
        "server": {"discoveryUrl": f"{ISSUER}/.well-known/openid-configuration"},
        "resource": {"resourceUrl": f"{ISSUER}/userinfo"},
        "client": fapi_client_config(client1_id, client1_jwks),
        "client2": fapi_client_config(client2_id, client2_jwks),
        "browser": browser,
        "override": fapi_overrides(browser, include_id2_overrides),
    }


def write_fapi_plan_configs() -> dict[str, dict[str, object]]:
    configs = {
        "oidf-fapi-security-final-plan-config.json": fapi_plan_config(
            "local-nazo-oauth-oidf-fapi-security-final",
            "Local Podman Nazo OAuth FAPI2 Security Final conformance configuration",
            "security-final",
            False,
        ),
        "oidf-fapi-message-final-plan-config.json": fapi_plan_config(
            "local-nazo-oauth-oidf-fapi-message-final",
            "Local Podman Nazo OAuth FAPI2 Message Signing Final conformance configuration",
            "message-final",
            False,
        ),
        "oidf-fapi-security-id2-plan-config.json": fapi_plan_config(
            "local-nazo-oauth-oidf-fapi-security-id2",
            "Local Podman Nazo OAuth FAPI2 Security ID2 conformance configuration",
            "security-id2",
            True,
        ),
        "oidf-fapi-message-id1-plan-config.json": fapi_plan_config(
            "local-nazo-oauth-oidf-fapi-message-id1",
            "Local Podman Nazo OAuth FAPI2 Message Signing ID1 conformance configuration",
            "message-id1",
            True,
        ),
    }
    for name, config in configs.items():
        write_plan_config(name, config)
    return configs


def write_all_plan_configs() -> None:
    configs: dict[str, dict[str, object]] = {
        "oidf-oidcc-basic-plan-config.json": write_basic_plan_config(),
        "oidf-oidcc-config-plan-config.json": write_oidcc_config_plan_config(),
    }
    configs.update(write_fapi_plan_configs())
    write_text(RUNTIME / "oidf-local.env", f"OIDF_PLAN_CONFIG_JSON={json.dumps({'configs': configs})}\n", 0o600)
    callbacks = {
        name: callback_for(str(config["alias"]))
        for name, config in configs.items()
        if name != "oidf-oidcc-config-plan-config.json"
    }
    write_text(RUNTIME / "callbacks.json", json.dumps(callbacks, indent=2) + "\n", 0o600)
    write_text(RUNTIME / "callback.txt", callback_for(BASIC_ALIAS) + "\n")


def main() -> int:
    ensure_cert()
    write_env_yaml()
    write_nginx()
    write_ui()
    write_all_plan_configs()
    print(f"Prepared local OIDF runtime files under {RUNTIME}")
    print(f"Issuer: {ISSUER}")
    print(f"Suite callback base: {SUITE_BASE_URL}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
