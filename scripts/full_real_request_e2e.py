#!/usr/bin/env python3
"""Full real HTTP request gate for nazo-oauth-server.

The script is intentionally black-box at the HTTP boundary. It seeds only
prerequisite state that has no public bootstrap endpoint, then exercises every
declared Actix route through real requests against a running server.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from email import message_from_bytes
from typing import Any
from urllib.parse import parse_qs, urlparse

import jwt
import psycopg
import redis
import requests
from aiosmtpd.controller import Controller
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa


BASE_URL = os.environ.get("E2E_BASE_URL", "http://nazo-oauth-e2e-server:8000")
ISSUER_URL = os.environ.get("E2E_ISSUER_URL", BASE_URL)
DATABASE_URL = os.environ.get(
    "E2E_DATABASE_URL",
    "postgresql://postgres:postgres@nazo-oauth-e2e-postgres:5432/oauth",
)
VALKEY_URL = os.environ.get("E2E_VALKEY_URL", "redis://nazo-oauth-e2e-valkey:6379/0")
E2E_CORS_ORIGIN = os.environ.get("E2E_CORS_ORIGIN", "http://127.0.0.1:3000")

ADMIN_EMAIL = "admin-full-e2e@example.com"
ADMIN_PASSWORD = "AdminPassword-2026"
USER_EMAIL = "user-full-e2e@example.com"
USER_PASSWORD = "UserPassword-2026"
CLIENT_REDIRECT_URI = "https://client.example/callback"
DEFAULT_AUDIENCE = "resource://default"
CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
SESSION_COOKIE_NAME = "nazo_oauth_session"


checks: list[str] = []


def fail(message: str) -> None:
    raise AssertionError(message)


def check(name: str, condition: bool, detail: Any = None) -> None:
    if not condition:
        if detail is None:
            fail(name)
        fail(f"{name}: {detail}")
    checks.append(name)


def expect_status(name: str, response: requests.Response, expected: int) -> requests.Response:
    if response.status_code != expected:
        fail(f"{name}: expected {expected}, got {response.status_code}: {response.text}")
    checks.append(name)
    return response


def expect_json(response: requests.Response) -> dict[str, Any]:
    try:
        return response.json()
    except Exception as exc:  # noqa: BLE001
        fail(f"response is not JSON: {response.status_code} {response.text} ({exc})")
    raise AssertionError("unreachable")


def comma_header_values(response: requests.Response, name: str) -> set[str]:
    raw = response.headers.get(name, "")
    return {value.strip().lower() for value in raw.split(",") if value.strip()}


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def now() -> int:
    return int(time.time())


def ed25519_private_pem(key: ed25519.Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def private_key_pem(key: Any) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def ed25519_public_jwk(key: ed25519.Ed25519PrivateKey, kid: str | None = None) -> dict[str, Any]:
    raw_public = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    jwk: dict[str, Any] = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": b64url(raw_public),
        "alg": "EdDSA",
        "use": "sig",
    }
    if kid:
        jwk["kid"] = kid
    return jwk


def rsa_public_jwk(key: rsa.RSAPrivateKey, kid: str, algorithm: str) -> dict[str, Any]:
    public_numbers = key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "n": b64url(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, "big")),
        "e": b64url(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, "big")),
        "alg": algorithm,
        "use": "sig",
        "kid": kid,
    }


def ec_public_jwk(key: ec.EllipticCurvePrivateKey, kid: str) -> dict[str, Any]:
    public_numbers = key.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url(public_numbers.x.to_bytes(32, "big")),
        "y": b64url(public_numbers.y.to_bytes(32, "big")),
        "alg": "ES256",
        "use": "sig",
        "kid": kid,
    }


def dpop_proof(
    method: str,
    url: str,
    key: Any,
    *,
    algorithm: str = "EdDSA",
    public_jwk: dict[str, Any] | None = None,
    nonce: str | None = None,
    access_token: str | None = None,
) -> str:
    claims: dict[str, Any] = {
        "htm": method.upper(),
        "htu": url,
        "iat": now(),
        "jti": str(uuid.uuid4()),
    }
    if nonce is not None:
        claims["nonce"] = nonce
    if access_token is not None:
        claims["ath"] = b64url(hashlib.sha256(access_token.encode("utf-8")).digest())
    return jwt.encode(
        claims,
        private_key_pem(key),
        algorithm=algorithm,
        headers={"typ": "dpop+jwt", "jwk": public_jwk or ed25519_public_jwk(key)},
    )


def client_assertion(
    client_id: str,
    key: Any,
    *,
    jti: str | None = None,
    audience_path: str = "/token",
    algorithm: str = "EdDSA",
    kid: str = "private-key-jwt-e2e",
) -> str:
    claims = {
        "iss": client_id,
        "sub": client_id,
        "aud": f"{ISSUER_URL}{audience_path}",
        "iat": now(),
        "exp": now() + 120,
        "jti": jti or str(uuid.uuid4()),
    }
    return jwt.encode(
        claims,
        private_key_pem(key),
        algorithm=algorithm,
        headers={"typ": "JWT", "kid": kid},
    )


def authorization_request_object(
    client_id: str,
    key: Any,
    *,
    code_challenge: str,
    scope: str = "openid profile email",
    state: str = "jar-flow",
    audience: str | None = None,
    jti: str | None = None,
    algorithm: str = "EdDSA",
    kid: str = "private-key-jwt-e2e",
) -> str:
    claims = {
        "iss": client_id,
        "sub": client_id,
        "client_id": client_id,
        "aud": audience or ISSUER_URL,
        "exp": now() + 120,
        "nbf": now() - 5,
        "iat": now(),
        "jti": jti or str(uuid.uuid4()),
        "response_type": "code",
        "redirect_uri": CLIENT_REDIRECT_URI,
        "scope": scope,
        "state": state,
        "nonce": f"nonce-{state}",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    if algorithm == "none":
        return jwt.encode(claims, key="", algorithm="none", headers={"typ": "oauth-authz-req+jwt"})
    return jwt.encode(
        claims,
        private_key_pem(key),
        algorithm=algorithm,
        headers={"typ": "oauth-authz-req+jwt", "kid": kid},
    )


def csrf_header(session: requests.Session) -> dict[str, str]:
    token = session.cookies.get("nazo_oauth_csrf")
    if not token:
        fail("missing csrf cookie")
    return {"x-csrf-token": token}


def location_query(response: requests.Response) -> dict[str, list[str]]:
    location = response.headers.get("Location")
    if not location:
        fail("redirect response missing Location")
    return parse_qs(urlparse(location).query)


def pkce_pair() -> tuple[str, str]:
    verifier = b64url(secrets.token_bytes(32))
    challenge = b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


class SmtpSink:
    def __init__(self) -> None:
        self.messages: list[bytes] = []

    async def handle_DATA(self, server: Any, session: Any, envelope: Any) -> str:  # noqa: N802
        self.messages.append(envelope.content)
        return "250 OK"

    def wait_for_code(self) -> str:
        deadline = time.time() + 10
        while time.time() < deadline:
            for raw in self.messages:
                msg = message_from_bytes(raw)
                bodies: list[str] = []
                if msg.is_multipart():
                    for part in msg.walk():
                        payload = part.get_payload(decode=True)
                        if payload:
                            bodies.append(payload.decode("utf-8", errors="replace"))
                else:
                    payload = msg.get_payload(decode=True)
                    if payload:
                        bodies.append(payload.decode("utf-8", errors="replace"))
                text = "\n".join(bodies)
                for pattern in (
                    r"验证码是\s*(\d{6})",
                    r"验证码[^\d]{0,40}(\d{6})",
                    r">\s*(\d{6})\s*</div>",
                ):
                    match = re.search(pattern, text)
                    if match:
                        return match.group(1)
            time.sleep(0.1)
        fail("verification code email was not received")
        raise AssertionError("unreachable")


def assert_destructive_targets_are_e2e() -> None:
    database = urlparse(DATABASE_URL)
    valkey = urlparse(VALKEY_URL)
    base = urlparse(BASE_URL)

    actual = {
        "database_host": database.hostname,
        "database_name": database.path.lstrip("/"),
        "valkey_host": valkey.hostname,
        "valkey_db": valkey.path or "/0",
        "base_host": base.hostname,
    }
    allowed_targets = [
        {
            "database_host": "nazo-oauth-e2e-postgres",
            "database_name": "oauth",
            "valkey_host": "nazo-oauth-e2e-valkey",
            "valkey_db": "/0",
            "base_host": "nazo-oauth-e2e-server",
        }
    ]
    if os.environ.get("E2E_ALLOW_SAME_CONTAINER_LOOPBACK") == "1":
        allowed_targets.append(
            {
                "database_host": "postgres",
                "database_name": "oauth",
                "valkey_host": "valkey",
                "valkey_db": "/0",
                "base_host": "127.0.0.1",
            }
        )
    if actual not in allowed_targets:
        fail(f"refusing destructive seed outside Docker E2E targets: {actual}")


def seed_prerequisites() -> None:
    assert_destructive_targets_are_e2e()
    password_hash = PasswordHasher().hash(ADMIN_PASSWORD)
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                TRUNCATE TABLE
                    access_token_revocations,
                    oauth_tokens,
                    user_client_grants,
                    client_access_requests,
                    oauth_clients,
                    users
                RESTART IDENTITY CASCADE
                """
            )
            cur.execute(
                """
                INSERT INTO users (
                    username, email, password_hash, email_verified,
                    display_name, role, admin_level, is_active
                )
                VALUES (%s, %s, %s, TRUE, %s, 'admin', 10, TRUE)
                """,
                ("admin_full_e2e", ADMIN_EMAIL, password_hash, "Admin E2E"),
            )
        conn.commit()

    redis.Redis.from_url(VALKEY_URL, decode_responses=True).flushdb()


def wait_for_service() -> None:
    deadline = time.time() + 30
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            response = requests.get(f"{BASE_URL}/health", timeout=2)
            if response.status_code == 200:
                return
        except Exception as exc:  # noqa: BLE001
            last_error = exc
        time.sleep(0.5)
    fail(f"service did not become healthy: {last_error}")


def login(session: requests.Session, email: str, password: str, check_name: str) -> dict[str, Any]:
    response = session.post(
        f"{BASE_URL}/auth/login",
        json={"email": email, "password": password},
        timeout=10,
    )
    expect_status(check_name, response, 200)
    body = expect_json(response)
    check(f"{check_name}_sets_csrf", bool(body.get("csrf_token")))
    return body


def create_client(
    admin: requests.Session,
    payload: dict[str, Any],
    check_name: str,
) -> dict[str, Any]:
    response = admin.post(
        f"{BASE_URL}/admin/clients",
        json=payload,
        headers=csrf_header(admin),
        timeout=10,
    )
    expect_status(check_name, response, 201)
    return expect_json(response)


def authorize_request(
    user: requests.Session,
    client_id: str,
    *,
    state: str,
    nonce: str | None = "nonce-e2e",
) -> tuple[str, str]:
    verifier, challenge = pkce_pair()
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": CLIENT_REDIRECT_URI,
        "scope": "openid profile email offline_access",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    if nonce is not None:
        params["nonce"] = nonce
    response = user.get(f"{BASE_URL}/authorize", params=params, allow_redirects=False, timeout=10)
    expect_status(f"authorize_{state}", response, 302)
    request_id = location_query(response).get("request_id", [None])[0]
    if not request_id:
        fail("authorize did not redirect to consent request")

    response = user.get(
        f"{BASE_URL}/authorize/consent",
        params={"request_id": request_id},
        timeout=10,
    )
    expect_status(f"authorize_consent_{state}", response, 200)
    consent = expect_json(response)
    check(f"authorize_consent_payload_{state}", consent["request_id"] == request_id)

    return request_id, verifier


def approve_authorization(
    user: requests.Session,
    request_id: str,
    verifier: str,
    *,
    state: str,
) -> tuple[str, str]:
    response = user.post(
        f"{BASE_URL}/authorize/decision",
        data={
            "request_id": request_id,
            "decision": "approve",
            "csrf_token": user.cookies.get("nazo_oauth_csrf"),
        },
        allow_redirects=False,
        timeout=10,
    )
    expect_status(f"authorize_decision_approve_{state}", response, 302)
    query = location_query(response)
    code = query.get("code", [None])[0]
    check(f"authorize_code_issued_{state}", bool(code))
    check(f"authorize_state_roundtrip_{state}", query.get("state", [None])[0] == state)
    return code, verifier


def consent_request_from_redirect(response: requests.Response, check_name: str) -> str:
    request_id = location_query(response).get("request_id", [None])[0]
    check(f"{check_name}_request_id", bool(request_id))
    return request_id or ""


def token_plain(form: dict[str, str], check_name: str) -> dict[str, Any]:
    response = requests.post(f"{BASE_URL}/token", data=form, timeout=10)
    expect_status(check_name, response, 200)
    return expect_json(response)


def request_dpop_nonce(
    form: dict[str, str],
    key: Any,
    path: str = "/token",
    *,
    algorithm: str = "EdDSA",
    public_jwk: dict[str, Any] | None = None,
) -> str:
    url = f"{BASE_URL}{path}"
    proof_url = f"{ISSUER_URL}{path}"
    response = requests.post(
        url,
        data=form,
        headers={
            "DPoP": dpop_proof(
                "POST",
                proof_url,
                key,
                algorithm=algorithm,
                public_jwk=public_jwk,
            )
        },
        timeout=10,
    )
    expect_status(f"dpop_nonce_challenge_{path}_{len(checks)}", response, 400)
    body = expect_json(response)
    check(f"dpop_nonce_error_{path}_{len(checks)}", body.get("error") == "use_dpop_nonce")
    nonce = response.headers.get("DPoP-Nonce")
    check(f"dpop_nonce_header_{path}_{len(checks)}", bool(nonce))
    return nonce or ""


def token_with_dpop(
    form: dict[str, str],
    key: Any,
    nonce: str,
    check_name: str,
    *,
    algorithm: str = "EdDSA",
    public_jwk: dict[str, Any] | None = None,
) -> dict[str, Any]:
    response = requests.post(
        f"{BASE_URL}/token",
        data=form,
        headers={
            "DPoP": dpop_proof(
                "POST",
                f"{ISSUER_URL}/token",
                key,
                algorithm=algorithm,
                public_jwk=public_jwk,
                nonce=nonce,
            )
        },
        timeout=10,
    )
    expect_status(check_name, response, 200)
    return expect_json(response)


def run() -> None:
    seed_prerequisites()
    wait_for_service()

    smtp_sink = SmtpSink()
    smtp = Controller(smtp_sink, hostname="0.0.0.0", port=1025)
    smtp.start()
    try:
        anonymous = requests.Session()
        user = requests.Session()
        admin = requests.Session()

        health = expect_status("GET /health", anonymous.get(f"{BASE_URL}/health", timeout=10), 200)
        check("health_body", expect_json(health).get("status") == "正常")

        discovery = expect_json(
            expect_status(
                "GET /.well-known/openid-configuration",
                anonymous.get(f"{BASE_URL}/.well-known/openid-configuration", timeout=10),
                200,
            )
        )
        check(
            "discovery_metadata",
            "private_key_jwt" in discovery["token_endpoint_auth_methods_supported"]
            and "private_key_jwt" in discovery["introspection_endpoint_auth_methods_supported"]
            and set(discovery["revocation_endpoint_auth_signing_alg_values_supported"])
            == {"EdDSA", "RS256", "ES256", "PS256"}
            and set(discovery["request_object_signing_alg_values_supported"])
            == {"EdDSA", "RS256", "ES256", "PS256"}
            and set(discovery["dpop_signing_alg_values_supported"])
            == {"EdDSA", "RS256", "ES256", "PS256"}
            and "email_verified" in discovery["claims_supported"],
        )
        oauth_metadata = expect_json(
            expect_status(
                "GET /.well-known/oauth-authorization-server",
                anonymous.get(f"{BASE_URL}/.well-known/oauth-authorization-server", timeout=10),
                200,
            )
        )
        check(
            "oauth_authorization_server_metadata",
            oauth_metadata["issuer"] == discovery["issuer"]
            and oauth_metadata["authorization_endpoint"] == discovery["authorization_endpoint"],
        )

        jwks = expect_json(
            expect_status("GET /jwks.json", anonymous.get(f"{BASE_URL}/jwks.json", timeout=10), 200)
        )
        check("jwks_has_keys", bool(jwks.get("keys")))

        captcha = expect_json(
            expect_status(
                "GET /auth/captcha-config",
                anonymous.get(f"{BASE_URL}/auth/captcha-config", timeout=10),
                200,
            )
        )
        check("captcha_config_shape", captcha.get("registration_enabled") is True)

        cors = anonymous.options(
            f"{BASE_URL}/token",
            headers={
                "Origin": E2E_CORS_ORIGIN,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "authorization,content-type,dpop,x-csrf-token",
            },
            timeout=10,
        )
        check("OPTIONS /token CORS", cors.status_code < 400, cors.text)
        check(
            "CORS allow origin",
            cors.headers.get("access-control-allow-origin") == E2E_CORS_ORIGIN,
        )
        cors_actual = anonymous.get(
            f"{BASE_URL}/health",
            headers={"Origin": E2E_CORS_ORIGIN},
            timeout=10,
        )
        expect_status("GET /health CORS actual", cors_actual, 200)
        exposed_headers = comma_header_values(cors_actual, "access-control-expose-headers")
        check(
            "CORS exposes retry-after",
            "retry-after" in exposed_headers,
            cors_actual.headers,
        )

        anonymous_redirect = anonymous.get(
            f"{BASE_URL}/authorize",
            params={"client_id": "missing-client"},
            allow_redirects=False,
            timeout=10,
        )
        expect_status("GET /authorize missing client rejected before login", anonymous_redirect, 401)
        check(
            "authorize_missing_client_unauthorized_client",
            expect_json(anonymous_redirect).get("error") == "unauthorized_client",
        )

        duplicate = anonymous.get(
            f"{BASE_URL}/authorize?client_id=a&client_id=b",
            allow_redirects=False,
            timeout=10,
        )
        expect_status("GET /authorize duplicate parameter", duplicate, 400)

        send_code = user.post(
            f"{BASE_URL}/auth/send-code",
            json={"email": USER_EMAIL},
            timeout=10,
        )
        expect_status("POST /auth/send-code", send_code, 200)
        verification_code = smtp_sink.wait_for_code()

        registered = expect_json(
            expect_status(
                "POST /auth/register",
                user.post(
                    f"{BASE_URL}/auth/register",
                    json={
                        "email": USER_EMAIL,
                        "verification_code": verification_code,
                        "password": USER_PASSWORD,
                    },
                    timeout=10,
                ),
                201,
            )
        )
        user_id = registered["id"]

        login(user, USER_EMAIL, USER_PASSWORD, "POST /auth/login user")
        me = expect_json(
            expect_status("GET /auth/me", user.get(f"{BASE_URL}/auth/me", timeout=10), 200)
        )
        check("auth_me_user", me["id"] == user_id and me["email"] == USER_EMAIL)

        valkey_client = redis.Redis.from_url(VALKEY_URL, decode_responses=True)
        malformed_session = requests.Session()
        malformed_sid = secrets.token_urlsafe(32)
        valkey_client.set(f"oauth:session:{malformed_sid}", "not-json", ex=300)
        malformed_session.cookies.set(SESSION_COOKIE_NAME, malformed_sid)
        expect_status(
            "GET /auth/me malformed session is unauthenticated",
            malformed_session.get(f"{BASE_URL}/auth/me", timeout=10),
            401,
        )
        check(
            "malformed_session_deleted",
            valkey_client.get(f"oauth:session:{malformed_sid}") is None,
        )

        csrf = expect_json(
            expect_status("GET /auth/csrf", user.get(f"{BASE_URL}/auth/csrf", timeout=10), 200)
        )
        check("csrf_refresh_body", bool(csrf.get("csrf_token")))

        updated_me = expect_json(
            expect_status(
                "PATCH /auth/me",
                user.patch(
                    f"{BASE_URL}/auth/me",
                    json={"display_name": "Full E2E User"},
                    headers=csrf_header(user),
                    timeout=10,
                ),
                200,
            )
        )
        check("profile_updated", updated_me["display_name"] == "Full E2E User")

        png_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
        avatar_upload = expect_json(
            expect_status(
                "POST /auth/me/avatar",
                user.post(
                    f"{BASE_URL}/auth/me/avatar",
                    files={"avatar": ("avatar.png", png_bytes, "image/png")},
                    headers=csrf_header(user),
                    timeout=10,
                ),
                200,
            )
        )
        check("avatar_url_set", bool(avatar_upload.get("avatar_url")))

        avatar_get = expect_status(
            "GET /auth/me/avatar",
            user.get(f"{BASE_URL}/auth/me/avatar", timeout=10),
            200,
        )
        check("avatar_content_type", avatar_get.headers.get("content-type") == "image/png")

        avatar_cross_site = user.get(
            f"{BASE_URL}/auth/me/avatar",
            headers={"sec-fetch-site": "cross-site"},
            timeout=10,
        )
        expect_status("GET /auth/me/avatar cross-site rejected", avatar_cross_site, 403)

        expect_status(
            "DELETE /auth/me/avatar",
            user.delete(
                f"{BASE_URL}/auth/me/avatar",
                headers=csrf_header(user),
                timeout=10,
            ),
            200,
        )
        expect_status(
            "GET /auth/me/avatar after delete",
            user.get(f"{BASE_URL}/auth/me/avatar", timeout=10),
            404,
        )

        expect_status(
            "GET /auth/me/applications initial",
            user.get(f"{BASE_URL}/auth/me/applications", timeout=10),
            200,
        )
        expect_status(
            "GET /auth/me/access-requests initial",
            user.get(f"{BASE_URL}/auth/me/access-requests", timeout=10),
            200,
        )

        login(admin, ADMIN_EMAIL, ADMIN_PASSWORD, "POST /auth/login admin")
        admin_users = expect_json(
            expect_status(
                "GET /admin/users",
                admin.get(f"{BASE_URL}/admin/users", params={"page": 1, "page_size": 50}, timeout=10),
                200,
            )
        )
        check("admin_users_contains_user", any(item["id"] == user_id for item in admin_users["items"]))

        patched_user = expect_json(
            expect_status(
                "PATCH /admin/users/{user_id}",
                admin.patch(
                    f"{BASE_URL}/admin/users/{user_id}",
                    json={"role": "user", "admin_level": 0, "is_active": True},
                    headers=csrf_header(admin),
                    timeout=10,
                ),
                200,
            )
        )
        check("admin_patch_user_shape", patched_user["id"] == user_id)

        public_client = create_client(
            admin,
            {
                "client_name": "Public Full E2E",
                "client_type": "public",
                "redirect_uris": [CLIENT_REDIRECT_URI],
                "scopes": ["openid", "profile", "email", "offline_access"],
                "allowed_audiences": [DEFAULT_AUDIENCE],
                "grant_types": ["authorization_code", "refresh_token"],
                "token_endpoint_auth_method": "none",
                "jwks": None,
            },
            "POST /admin/clients public",
        )
        public_client_id = public_client["client_id"]

        secret_client = create_client(
            admin,
            {
                "client_name": "Secret Full E2E",
                "client_type": "confidential",
                "redirect_uris": [],
                "scopes": ["profile"],
                "allowed_audiences": [DEFAULT_AUDIENCE],
                "grant_types": ["client_credentials"],
                "token_endpoint_auth_method": "client_secret_post",
                "jwks": None,
            },
            "POST /admin/clients client_secret_post",
        )
        secret_client_id = secret_client["client_id"]
        secret_client_secret = secret_client["client_secret"]

        private_key = ed25519.Ed25519PrivateKey.generate()
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ps_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ec_key = ec.generate_private_key(ec.SECP256R1())
        jwks_without_kid = admin.post(
            f"{BASE_URL}/admin/clients",
            json={
                "client_name": "Invalid JWKS Full E2E",
                "client_type": "confidential",
                "redirect_uris": [],
                "scopes": ["profile"],
                "allowed_audiences": [DEFAULT_AUDIENCE],
                "grant_types": ["client_credentials"],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks": {"keys": [ed25519_public_jwk(private_key)]},
            },
            headers=csrf_header(admin),
            timeout=10,
        )
        expect_status("POST /admin/clients private_key_jwt jwks kid required", jwks_without_kid, 400)

        jwk_with_private_material = ed25519_public_jwk(private_key, "private-key-material-e2e")
        jwk_with_private_material["d"] = b64url(
            private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        private_jwk_response = admin.post(
            f"{BASE_URL}/admin/clients",
            json={
                "client_name": "Private Material JWKS Full E2E",
                "client_type": "confidential",
                "redirect_uris": [],
                "scopes": ["profile"],
                "allowed_audiences": [DEFAULT_AUDIENCE],
                "grant_types": ["client_credentials"],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks": {"keys": [jwk_with_private_material]},
            },
            headers=csrf_header(admin),
            timeout=10,
        )
        expect_status(
            "POST /admin/clients private_key_jwt private jwk rejected",
            private_jwk_response,
            400,
        )

        private_client = create_client(
            admin,
            {
                "client_name": "Private JWT Full E2E",
                "client_type": "confidential",
                "redirect_uris": [],
                "scopes": ["profile"],
                "allowed_audiences": [DEFAULT_AUDIENCE],
                "grant_types": ["client_credentials"],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks": {"keys": [ed25519_public_jwk(private_key, "private-key-jwt-e2e")]},
            },
            "POST /admin/clients private_key_jwt",
        )
        private_client_id = private_client["client_id"]

        multi_alg_private_client = create_client(
            admin,
            {
                "client_name": "Private JWT Multi Alg Full E2E",
                "client_type": "confidential",
                "redirect_uris": [],
                "scopes": ["profile"],
                "allowed_audiences": [DEFAULT_AUDIENCE],
                "grant_types": ["client_credentials"],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks": {
                    "keys": [
                        rsa_public_jwk(rsa_key, "private-key-jwt-rs256-e2e", "RS256"),
                        ec_public_jwk(ec_key, "private-key-jwt-es256-e2e"),
                        rsa_public_jwk(ps_key, "private-key-jwt-ps256-e2e", "PS256"),
                    ]
                },
            },
            "POST /admin/clients private_key_jwt RS256 ES256 PS256",
        )
        multi_alg_private_client_id = multi_alg_private_client["client_id"]

        private_auth_client = create_client(
            admin,
            {
                "client_name": "Private JWT Auth Code Full E2E",
                "client_type": "confidential",
                "redirect_uris": [CLIENT_REDIRECT_URI],
                "scopes": ["openid", "profile", "email"],
                "allowed_audiences": [DEFAULT_AUDIENCE],
                "grant_types": ["authorization_code"],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks": {
                    "keys": [
                        ed25519_public_jwk(private_key, "private-key-jwt-e2e"),
                        rsa_public_jwk(rsa_key, "private-key-jwt-rs256-e2e", "RS256"),
                    ]
                },
            },
            "POST /admin/clients private_key_jwt authorization_code",
        )
        private_auth_client_id = private_auth_client["client_id"]

        par_confidential_unauthenticated = requests.post(
            f"{BASE_URL}/par",
            data={
                "response_type": "code",
                "client_id": secret_client_id,
                "redirect_uri": CLIENT_REDIRECT_URI,
                "scope": "profile",
                "code_challenge": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                "code_challenge_method": "S256",
            },
            timeout=10,
        )
        expect_status("POST /par confidential unauthenticated rejected", par_confidential_unauthenticated, 401)

        par_with_request_uri = requests.post(
            f"{BASE_URL}/par",
            data={
                "response_type": "code",
                "client_id": public_client_id,
                "redirect_uri": CLIENT_REDIRECT_URI,
                "scope": "openid",
                "state": "par-request-uri",
                "request_uri": "urn:ietf:params:oauth:request_uri:external",
                "code_challenge": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                "code_challenge_method": "S256",
            },
            timeout=10,
        )
        expect_status("POST /par request_uri rejected", par_with_request_uri, 400)

        par_unknown = requests.post(
            f"{BASE_URL}/par",
            data={
                "response_type": "code",
                "client_id": public_client_id,
                "redirect_uri": CLIENT_REDIRECT_URI,
                "scope": "openid",
                "state": "par-unknown",
                "unexpected": "value",
                "code_challenge": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                "code_challenge_method": "S256",
            },
            timeout=10,
        )
        expect_status("POST /par unsupported parameter rejected", par_unknown, 400)

        par_verifier, par_challenge = pkce_pair()
        par = expect_json(
            expect_status(
                "POST /par public",
                requests.post(
                    f"{BASE_URL}/par",
                    data={
                        "response_type": "code",
                        "client_id": public_client_id,
                        "redirect_uri": CLIENT_REDIRECT_URI,
                        "scope": "openid profile email offline_access",
                        "state": "par-flow",
                        "nonce": "nonce-par-flow",
                        "code_challenge": par_challenge,
                        "code_challenge_method": "S256",
                    },
                    timeout=10,
                ),
                201,
            )
        )
        check("par_request_uri_shape", par["request_uri"].startswith("urn:ietf:params:oauth:request_uri:"))
        par_conflict = user.get(
            f"{BASE_URL}/authorize",
            params={
                "client_id": public_client_id,
                "request_uri": par["request_uri"],
                "scope": "openid",
            },
            allow_redirects=False,
            timeout=10,
        )
        expect_status("GET /authorize PAR parameter override rejected", par_conflict, 400)
        par = expect_json(
            expect_status(
                "POST /par public second",
                requests.post(
                    f"{BASE_URL}/par",
                    data={
                        "response_type": "code",
                        "client_id": public_client_id,
                        "redirect_uri": CLIENT_REDIRECT_URI,
                        "scope": "openid profile email offline_access",
                        "state": "par-flow",
                        "nonce": "nonce-par-flow",
                        "code_challenge": par_challenge,
                        "code_challenge_method": "S256",
                    },
                    timeout=10,
                ),
                201,
            )
        )
        par_authorize = user.get(
            f"{BASE_URL}/authorize",
            params={"client_id": public_client_id, "request_uri": par["request_uri"]},
            allow_redirects=False,
            timeout=10,
        )
        expect_status("GET /authorize PAR", par_authorize, 302)
        par_request_id = consent_request_from_redirect(par_authorize, "GET /authorize PAR")
        par_code, par_verifier = approve_authorization(user, par_request_id, par_verifier, state="par-flow")
        par_tokens = token_plain(
            {
                "grant_type": "authorization_code",
                "client_id": public_client_id,
                "code": par_code,
                "code_verifier": par_verifier,
                "redirect_uri": CLIENT_REDIRECT_URI,
            },
            "POST /token PAR authorization_code",
        )
        check("par_token_issued", bool(par_tokens.get("access_token")) and bool(par_tokens.get("id_token")))
        refresh_race_form = {
            "grant_type": "refresh_token",
            "client_id": public_client_id,
            "refresh_token": par_tokens["refresh_token"],
        }

        def redeem_refresh_race() -> tuple[int, dict[str, Any]]:
            response = requests.post(f"{BASE_URL}/token", data=refresh_race_form, timeout=10)
            try:
                return response.status_code, response.json()
            except ValueError:
                return response.status_code, {"raw": response.text}

        with ThreadPoolExecutor(max_workers=2) as pool:
            refresh_race_results = list(pool.map(lambda _: redeem_refresh_race(), range(2)))
        refresh_successes = [body for status, body in refresh_race_results if status == 200]
        refresh_rejections = [body for status, body in refresh_race_results if status == 400]
        check(
            "refresh_token_reuse_race_single_success",
            len(refresh_successes) == 1 and len(refresh_rejections) == 1,
            refresh_race_results,
        )
        check(
            "refresh_token_reuse_race_invalid_grant",
            refresh_rejections[0].get("error") == "invalid_grant",
            refresh_rejections,
        )
        refresh_after_race = requests.post(
            f"{BASE_URL}/token",
            data={
                "grant_type": "refresh_token",
                "client_id": public_client_id,
                "refresh_token": refresh_successes[0]["refresh_token"],
            },
            timeout=10,
        )
        expect_status("POST /token refresh family revoked after reuse race", refresh_after_race, 400)
        check(
            "refresh_token_reuse_race_revokes_family",
            expect_json(refresh_after_race).get("error") == "invalid_grant",
        )
        par_reuse = user.get(
            f"{BASE_URL}/authorize",
            params={"client_id": public_client_id, "request_uri": par["request_uri"]},
            allow_redirects=False,
            timeout=10,
        )
        expect_status("GET /authorize PAR request_uri read once", par_reuse, 400)

        jar_verifier, jar_challenge = pkce_pair()
        jar_token = authorization_request_object(
            private_auth_client_id,
            private_key,
            code_challenge=jar_challenge,
            state="jar-flow",
        )
        jar_authorize = user.get(
            f"{BASE_URL}/authorize",
            params={"request": jar_token},
            allow_redirects=False,
            timeout=10,
        )
        expect_status("GET /authorize JAR", jar_authorize, 302)
        jar_request_id = consent_request_from_redirect(jar_authorize, "GET /authorize JAR")
        jar_code, jar_verifier = approve_authorization(user, jar_request_id, jar_verifier, state="jar-flow")
        jar_tokens = token_plain(
            {
                "grant_type": "authorization_code",
                "code": jar_code,
                "code_verifier": jar_verifier,
                "redirect_uri": CLIENT_REDIRECT_URI,
                "client_assertion_type": CLIENT_ASSERTION_TYPE,
                "client_assertion": client_assertion(private_auth_client_id, private_key),
            },
            "POST /token JAR authorization_code private_key_jwt",
        )
        check("jar_token_issued", bool(jar_tokens.get("access_token")) and bool(jar_tokens.get("id_token")))
        jar_replay = user.get(
            f"{BASE_URL}/authorize",
            params={"request": jar_token},
            allow_redirects=False,
            timeout=10,
        )
        expect_status("GET /authorize JAR jti replay rejected", jar_replay, 400)

        jar_rs_verifier, jar_rs_challenge = pkce_pair()
        jar_rs_token = authorization_request_object(
            private_auth_client_id,
            rsa_key,
            code_challenge=jar_rs_challenge,
            state="jar-rs256-flow",
            algorithm="RS256",
            kid="private-key-jwt-rs256-e2e",
        )
        jar_rs_authorize = user.get(
            f"{BASE_URL}/authorize",
            params={"request": jar_rs_token},
            allow_redirects=False,
            timeout=10,
        )
        expect_status("GET /authorize JAR RS256", jar_rs_authorize, 302)
        jar_rs_request_id = consent_request_from_redirect(jar_rs_authorize, "GET /authorize JAR RS256")
        jar_rs_code, jar_rs_verifier = approve_authorization(
            user,
            jar_rs_request_id,
            jar_rs_verifier,
            state="jar-rs256-flow",
        )
        jar_rs_tokens = token_plain(
            {
                "grant_type": "authorization_code",
                "code": jar_rs_code,
                "code_verifier": jar_rs_verifier,
                "redirect_uri": CLIENT_REDIRECT_URI,
                "client_assertion_type": CLIENT_ASSERTION_TYPE,
                "client_assertion": client_assertion(
                    private_auth_client_id,
                    rsa_key,
                    algorithm="RS256",
                    kid="private-key-jwt-rs256-e2e",
                ),
            },
            "POST /token JAR RS256 authorization_code private_key_jwt",
        )
        check("jar_rs256_token_issued", bool(jar_rs_tokens.get("access_token")))

        jar_none = authorization_request_object(
            private_auth_client_id,
            private_key,
            code_challenge=jar_challenge,
            state="jar-none",
            algorithm="none",
        )
        expect_status(
            "GET /authorize JAR alg none rejected",
            user.get(
                f"{BASE_URL}/authorize",
                params={"request": jar_none},
                allow_redirects=False,
                timeout=10,
            ),
            400,
        )
        jar_bad_aud = authorization_request_object(
            private_auth_client_id,
            private_key,
            code_challenge=jar_challenge,
            state="jar-bad-aud",
            audience="https://wrong-audience.example",
        )
        expect_status(
            "GET /authorize JAR audience mismatch rejected",
            user.get(
                f"{BASE_URL}/authorize",
                params={"request": jar_bad_aud},
                allow_redirects=False,
                timeout=10,
            ),
            400,
        )

        jar_conflict_verifier, jar_conflict_challenge = pkce_pair()
        jar_conflict_jti = str(uuid.uuid4())
        jar_conflict = authorization_request_object(
            private_auth_client_id,
            private_key,
            code_challenge=jar_conflict_challenge,
            state="jar-conflict",
            jti=jar_conflict_jti,
        )
        expect_status(
            "GET /authorize JAR outer conflict rejected",
            user.get(
                f"{BASE_URL}/authorize",
                params={"request": jar_conflict, "state": "conflicting-outer-state"},
                allow_redirects=False,
                timeout=10,
            ),
            400,
        )
        jar_conflict_reuse = user.get(
            f"{BASE_URL}/authorize",
            params={"request": jar_conflict},
            allow_redirects=False,
            timeout=10,
        )
        expect_status("GET /authorize JAR conflict does not consume jti", jar_conflict_reuse, 302)
        jar_conflict_request_id = consent_request_from_redirect(
            jar_conflict_reuse,
            "GET /authorize JAR conflict retry",
        )
        _jar_conflict_code, _jar_conflict_verifier = approve_authorization(
            user,
            jar_conflict_request_id,
            jar_conflict_verifier,
            state="jar-conflict",
        )

        par_jar_verifier, par_jar_challenge = pkce_pair()
        par_jar = authorization_request_object(
            private_auth_client_id,
            private_key,
            code_challenge=par_jar_challenge,
            state="par-jar-flow",
        )
        par_jar_response = expect_json(
            expect_status(
                "POST /par JAR private_key_jwt",
                requests.post(
                    f"{BASE_URL}/par",
                    data={
                        "request": par_jar,
                        "client_assertion_type": CLIENT_ASSERTION_TYPE,
                        "client_assertion": client_assertion(
                            private_auth_client_id,
                            private_key,
                            audience_path="/par",
                        ),
                    },
                    timeout=10,
                ),
                201,
            )
        )
        par_jar_authorize = user.get(
            f"{BASE_URL}/authorize",
            params={"request_uri": par_jar_response["request_uri"]},
            allow_redirects=False,
            timeout=10,
        )
        expect_status("GET /authorize PAR JAR", par_jar_authorize, 302)
        par_jar_request_id = consent_request_from_redirect(par_jar_authorize, "GET /authorize PAR JAR")
        par_jar_code, par_jar_verifier = approve_authorization(
            user,
            par_jar_request_id,
            par_jar_verifier,
            state="par-jar-flow",
        )
        par_jar_tokens = token_plain(
            {
                "grant_type": "authorization_code",
                "code": par_jar_code,
                "code_verifier": par_jar_verifier,
                "redirect_uri": CLIENT_REDIRECT_URI,
                "client_assertion_type": CLIENT_ASSERTION_TYPE,
                "client_assertion": client_assertion(private_auth_client_id, private_key),
            },
            "POST /token PAR JAR authorization_code private_key_jwt",
        )
        check("par_jar_token_issued", bool(par_jar_tokens.get("access_token")))

        expect_status(
            "POST /introspect public client rejected",
            requests.post(
                f"{BASE_URL}/introspect",
                data={"token": "dummy-token", "client_id": public_client_id},
                timeout=10,
            ),
            401,
        )

        lower_basic = "basic " + base64.b64encode(
            f"{secret_client_id}:{secret_client_secret}".encode("utf-8")
        ).decode("ascii")
        expect_status(
            "POST /token lowercase basic plus body credential rejected",
            requests.post(
                f"{BASE_URL}/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": secret_client_id,
                    "client_secret": secret_client_secret,
                    "scope": "profile",
                },
                headers={"Authorization": lower_basic},
                timeout=10,
            ),
            400,
        )
        expect_status(
            "POST /introspect lowercase basic plus body credential rejected",
            requests.post(
                f"{BASE_URL}/introspect",
                data={"token": "dummy-token", "client_id": secret_client_id},
                headers={"Authorization": lower_basic},
                timeout=10,
            ),
            400,
        )
        expect_status(
            "POST /revoke lowercase basic plus body credential rejected",
            requests.post(
                f"{BASE_URL}/revoke",
                data={"token": "dummy-token", "client_id": secret_client_id},
                headers={"Authorization": lower_basic},
                timeout=10,
            ),
            400,
        )
        malformed_basic = "Basic not-base64 with-space"
        expect_status(
            "POST /token malformed basic plus body credential rejected",
            requests.post(
                f"{BASE_URL}/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": secret_client_id,
                    "client_secret": secret_client_secret,
                    "scope": "profile",
                },
                headers={"Authorization": malformed_basic},
                timeout=10,
            ),
            400,
        )
        expect_status(
            "POST /introspect malformed basic plus body credential rejected",
            requests.post(
                f"{BASE_URL}/introspect",
                data={"token": "dummy-token", "client_id": secret_client_id},
                headers={"Authorization": malformed_basic},
                timeout=10,
            ),
            400,
        )
        expect_status(
            "POST /revoke malformed basic plus body credential rejected",
            requests.post(
                f"{BASE_URL}/revoke",
                data={"token": "dummy-token", "client_id": secret_client_id},
                headers={"Authorization": malformed_basic},
                timeout=10,
            ),
            400,
        )

        admin_clients = expect_json(
            expect_status(
                "GET /admin/clients",
                admin.get(f"{BASE_URL}/admin/clients", params={"page": 1, "page_size": 100}, timeout=10),
                200,
            )
        )
        check("admin_clients_contains_created", admin_clients["total"] >= 3)

        expect_status(
            "GET /admin/clients/{client_id}",
            admin.get(f"{BASE_URL}/admin/clients/{public_client_id}", timeout=10),
            200,
        )
        patched_client = expect_json(
            expect_status(
                "PATCH /admin/clients/{client_id}",
                admin.patch(
                    f"{BASE_URL}/admin/clients/{public_client_id}",
                    json={"client_name": "Public Full E2E Updated", "is_active": True},
                    headers=csrf_header(admin),
                    timeout=10,
                ),
                200,
            )
        )
        check("admin_patch_client_shape", patched_client["client_name"] == "Public Full E2E Updated")

        _prompt_verifier, prompt_challenge = pkce_pair()
        prompt_none = requests.get(
            f"{BASE_URL}/authorize",
            params={
                "response_type": "code",
                "client_id": public_client_id,
                "redirect_uri": CLIENT_REDIRECT_URI,
                "scope": "openid",
                "state": "prompt-none",
                "prompt": "none",
                "code_challenge": prompt_challenge,
                "code_challenge_method": "S256",
            },
            allow_redirects=False,
            timeout=10,
        )
        expect_status("GET /authorize prompt=none unauthenticated", prompt_none, 302)
        check("prompt_none_login_required", location_query(prompt_none).get("error") == ["login_required"])

        prompt_login = user.get(
            f"{BASE_URL}/authorize",
            params={
                "response_type": "code",
                "client_id": public_client_id,
                "redirect_uri": CLIENT_REDIRECT_URI,
                "scope": "openid",
                "state": "prompt-login",
                "prompt": "login",
                "code_challenge": prompt_challenge,
                "code_challenge_method": "S256",
            },
            allow_redirects=False,
            timeout=10,
        )
        expect_status("GET /authorize prompt=login", prompt_login, 302)
        prompt_login_location = prompt_login.headers.get("Location", "")
        check(
            "prompt_login_redirects_to_frontend_auth",
            prompt_login_location.startswith("http://127.0.0.1:3000/auth?next=")
            and "prompt%3Dlogin" not in prompt_login_location,
            prompt_login_location,
        )

        time.sleep(1)
        max_age = user.get(
            f"{BASE_URL}/authorize",
            params={
                "response_type": "code",
                "client_id": public_client_id,
                "redirect_uri": CLIENT_REDIRECT_URI,
                "scope": "openid",
                "state": "max-age",
                "max_age": "0",
                "code_challenge": prompt_challenge,
                "code_challenge_method": "S256",
            },
            allow_redirects=False,
            timeout=10,
        )
        expect_status("GET /authorize max_age expired", max_age, 302)
        check(
            "max_age_redirects_to_frontend_auth",
            max_age.headers.get("Location", "").startswith("http://127.0.0.1:3000/auth?next="),
            max_age.headers.get("Location"),
        )

        bad_response_type = user.get(
            f"{BASE_URL}/authorize",
            params={
                "response_type": "token",
                "client_id": public_client_id,
                "redirect_uri": CLIENT_REDIRECT_URI,
                "scope": "openid",
                "state": "bad-response-type",
                "code_challenge": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                "code_challenge_method": "S256",
            },
            allow_redirects=False,
            timeout=10,
        )
        expect_status("GET /authorize unsupported response_type", bad_response_type, 302)
        check(
            "authorize_unsupported_response_type_error",
            location_query(bad_response_type).get("error") == ["unsupported_response_type"],
        )

        deny_request_id, _deny_verifier = authorize_request(
            user, public_client_id, state="deny-flow", nonce=None
        )
        deny_response = user.post(
            f"{BASE_URL}/authorize/decision",
            data={
                "request_id": deny_request_id,
                "decision": "deny",
                "csrf_token": user.cookies.get("nazo_oauth_csrf"),
            },
            allow_redirects=False,
            timeout=10,
        )
        expect_status("POST /authorize/decision deny", deny_response, 302)
        check("authorize_deny_error", location_query(deny_response).get("error") == ["access_denied"])

        dpop_key = ed25519.Ed25519PrivateKey.generate()
        missing_request_id, missing_verifier = authorize_request(
            user,
            public_client_id,
            state="missing-redirect-flow",
        )
        missing_code, missing_verifier = approve_authorization(
            user,
            missing_request_id,
            missing_verifier,
            state="missing-redirect-flow",
        )
        missing_redirect_form = {
            "grant_type": "authorization_code",
            "client_id": public_client_id,
            "code": missing_code,
            "code_verifier": missing_verifier,
        }
        nonce = request_dpop_nonce(missing_redirect_form, dpop_key)
        missing_redirect_response = requests.post(
            f"{BASE_URL}/token",
            data=missing_redirect_form,
            headers={"DPoP": dpop_proof("POST", f"{ISSUER_URL}/token", dpop_key, nonce=nonce)},
            timeout=10,
        )
        expect_status("POST /token redirect_uri required", missing_redirect_response, 400)
        check(
            "token_redirect_uri_required_error",
            expect_json(missing_redirect_response).get("error") == "invalid_grant",
        )

        request_id, verifier = authorize_request(user, public_client_id, state="approve-flow")
        code, verifier = approve_authorization(user, request_id, verifier, state="approve-flow")
        token_form = {
            "grant_type": "authorization_code",
            "client_id": public_client_id,
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": CLIENT_REDIRECT_URI,
        }
        nonce = request_dpop_nonce(
            token_form, dpop_key
        )
        token_response = token_with_dpop(
            token_form,
            dpop_key,
            nonce,
            "POST /token authorization_code DPoP",
        )
        access_token = token_response["access_token"]
        refresh_token = token_response["refresh_token"]
        check("id_token_issued", bool(token_response.get("id_token")))

        userinfo_no_nonce = requests.get(
            f"{BASE_URL}/userinfo",
            headers={
                "Authorization": f"DPoP {access_token}",
                "DPoP": dpop_proof("GET", f"{ISSUER_URL}/userinfo", dpop_key, access_token=access_token),
            },
            timeout=10,
        )
        expect_status("GET /userinfo DPoP nonce challenge", userinfo_no_nonce, 401)
        userinfo_nonce = userinfo_no_nonce.headers.get("DPoP-Nonce")
        check("userinfo_nonce_header", bool(userinfo_nonce))
        check(
            "userinfo_nonce_www_authenticate",
            'error="use_dpop_nonce"' in userinfo_no_nonce.headers.get("WWW-Authenticate", ""),
            userinfo_no_nonce.headers,
        )
        userinfo = expect_json(
            expect_status(
                "GET /userinfo",
                requests.get(
                    f"{BASE_URL}/userinfo",
                    headers={
                        "Authorization": f"DPoP {access_token}",
                        "DPoP": dpop_proof(
                            "GET",
                            f"{ISSUER_URL}/userinfo",
                            dpop_key,
                            nonce=userinfo_nonce,
                            access_token=access_token,
                        ),
                    },
                    timeout=10,
                ),
                200,
            )
        )
        check(
            "userinfo_claims",
            userinfo.get("sub") == user_id
            and userinfo.get("email") == USER_EMAIL
            and userinfo.get("email_verified") is True,
        )

        nonce = request_dpop_nonce(
            {
                "grant_type": "refresh_token",
                "client_id": public_client_id,
                "refresh_token": refresh_token,
            },
            dpop_key,
        )
        refreshed = token_with_dpop(
            {
                "grant_type": "refresh_token",
                "client_id": public_client_id,
                "refresh_token": refresh_token,
            },
            dpop_key,
            nonce,
            "POST /token refresh_token DPoP",
        )
        rotated_refresh_token = refreshed["refresh_token"]
        refreshed_access_token = refreshed["access_token"]
        check("refresh_token_rotated", rotated_refresh_token != refresh_token)

        introspected = expect_json(
            expect_status(
                "POST /introspect active",
                requests.post(
                    f"{BASE_URL}/introspect",
                    data={
                        "token": refreshed_access_token,
                        "client_id": secret_client_id,
                        "client_secret": secret_client_secret,
                    },
                    timeout=10,
                ),
                200,
            )
        )
        check("introspect_active", introspected.get("active") is True)

        expect_status(
            "POST /revoke access token",
            requests.post(
                f"{BASE_URL}/revoke",
                data={"token": refreshed_access_token, "client_id": public_client_id},
                timeout=10,
            ),
            200,
        )
        introspected_after_revoke = expect_json(
            expect_status(
                "POST /introspect inactive",
                requests.post(
                    f"{BASE_URL}/introspect",
                    data={
                        "token": refreshed_access_token,
                        "client_id": secret_client_id,
                        "client_secret": secret_client_secret,
                    },
                    timeout=10,
                ),
                200,
            )
        )
        check("introspect_inactive_after_revoke", introspected_after_revoke.get("active") is False)

        replay_request_id, replay_verifier = authorize_request(
            user, public_client_id, state="code-replay-flow"
        )
        replay_code, replay_verifier = approve_authorization(
            user, replay_request_id, replay_verifier, state="code-replay-flow"
        )
        replay_key = ed25519.Ed25519PrivateKey.generate()
        replay_form = {
            "grant_type": "authorization_code",
            "client_id": public_client_id,
            "code": replay_code,
            "code_verifier": replay_verifier,
            "redirect_uri": CLIENT_REDIRECT_URI,
        }
        replay_nonce = request_dpop_nonce(replay_form, replay_key)
        replay_tokens = token_with_dpop(
            replay_form,
            replay_key,
            replay_nonce,
            "POST /token authorization_code replay baseline",
        )
        replay_access_token = replay_tokens["access_token"]
        replay_refresh_form = {
            "grant_type": "refresh_token",
            "client_id": public_client_id,
            "refresh_token": replay_tokens["refresh_token"],
        }
        replay_refresh_nonce = request_dpop_nonce(replay_refresh_form, replay_key)
        replay_userinfo_nonce_response = requests.get(
            f"{BASE_URL}/userinfo",
            headers={
                "Authorization": f"DPoP {replay_access_token}",
                "DPoP": dpop_proof(
                    "GET",
                    f"{ISSUER_URL}/userinfo",
                    replay_key,
                    access_token=replay_access_token,
                ),
            },
            timeout=10,
        )
        expect_status(
            "GET /userinfo replay token nonce challenge",
            replay_userinfo_nonce_response,
            401,
        )
        replay_userinfo_nonce = replay_userinfo_nonce_response.headers.get("DPoP-Nonce")
        check("userinfo_replay_token_nonce_header", bool(replay_userinfo_nonce))
        replay_nonce = request_dpop_nonce(replay_form, replay_key)
        replay_response = requests.post(
            f"{BASE_URL}/token",
            data=replay_form,
            headers={"DPoP": dpop_proof("POST", f"{ISSUER_URL}/token", replay_key, nonce=replay_nonce)},
            timeout=10,
        )
        expect_status("POST /token authorization_code replay rejected", replay_response, 400)
        check(
            "authorization_code_replay_error",
            expect_json(replay_response).get("error") == "invalid_grant",
        )
        replay_userinfo_after_revoke = expect_json(
            expect_status(
                "GET /userinfo access token revoked after code replay",
                requests.get(
                    f"{BASE_URL}/userinfo",
                    headers={
                        "Authorization": f"DPoP {replay_access_token}",
                        "DPoP": dpop_proof(
                            "GET",
                            f"{ISSUER_URL}/userinfo",
                            replay_key,
                            nonce=replay_userinfo_nonce,
                            access_token=replay_access_token,
                        ),
                    },
                    timeout=10,
                ),
                401,
            )
        )
        check(
            "userinfo_revoked_after_code_replay_error",
            replay_userinfo_after_revoke.get("error") == "invalid_token",
        )
        replay_refresh_after_revoke = expect_json(
            expect_status(
                "POST /token refresh token revoked after code replay",
                requests.post(
                    f"{BASE_URL}/token",
                    data=replay_refresh_form,
                    headers={
                        "DPoP": dpop_proof(
                            "POST",
                            f"{ISSUER_URL}/token",
                            replay_key,
                            nonce=replay_refresh_nonce,
                        )
                    },
                    timeout=10,
                ),
                400,
            )
        )
        check(
            "refresh_token_revoked_after_code_replay_error",
            replay_refresh_after_revoke.get("error") == "invalid_grant",
        )

        concurrent_request_id, concurrent_verifier = authorize_request(
            user,
            public_client_id,
            state="concurrent-code-flow",
            nonce=None,
        )
        concurrent_code, concurrent_verifier = approve_authorization(
            user,
            concurrent_request_id,
            concurrent_verifier,
            state="concurrent-code-flow",
        )
        concurrent_form = {
            "grant_type": "authorization_code",
            "client_id": public_client_id,
            "code": concurrent_code,
            "code_verifier": concurrent_verifier,
            "redirect_uri": CLIENT_REDIRECT_URI,
        }

        def redeem_concurrent_code() -> tuple[int, dict[str, Any]]:
            response = requests.post(f"{BASE_URL}/token", data=concurrent_form, timeout=10)
            try:
                return response.status_code, response.json()
            except ValueError:
                return response.status_code, {"raw": response.text}

        with ThreadPoolExecutor(max_workers=2) as pool:
            concurrent_results = list(pool.map(lambda _: redeem_concurrent_code(), range(2)))
        success_results = [body for status, body in concurrent_results if status == 200]
        rejected_results = [body for status, body in concurrent_results if status == 400]
        check(
            "near_concurrent_authorization_code_single_success",
            len(success_results) == 1 and len(rejected_results) == 1,
            concurrent_results,
        )
        check(
            "near_concurrent_authorization_code_busy_invalid_grant",
            rejected_results[0].get("error") == "invalid_grant",
            rejected_results,
        )
        concurrent_access_token = success_results[0]["access_token"]
        replay_after_concurrent = requests.post(
            f"{BASE_URL}/token",
            data=concurrent_form,
            timeout=10,
        )
        expect_status("POST /token authorization_code post-success replay rejected", replay_after_concurrent, 400)
        concurrent_userinfo_after_replay = expect_json(
            expect_status(
                "GET /userinfo revoked after post-success code replay",
                requests.get(
                    f"{BASE_URL}/userinfo",
                    headers={"Authorization": f"Bearer {concurrent_access_token}"},
                    timeout=10,
                ),
                401,
            )
        )
        check(
            "post_success_code_replay_revoked_access_token",
            concurrent_userinfo_after_replay.get("error") == "invalid_token",
        )

        secret_cc = expect_json(
            expect_status(
                "POST /token client_credentials client_secret_post",
                requests.post(
                    f"{BASE_URL}/token",
                    data={
                        "grant_type": "client_credentials",
                        "client_id": secret_client_id,
                        "client_secret": secret_client_secret,
                        "scope": "profile",
                    },
                    timeout=10,
                ),
                200,
            )
        )
        check("client_secret_post_access_token", bool(secret_cc.get("access_token")))

        for algorithm, key, public_jwk in [
            ("RS256", rsa_key, rsa_public_jwk(rsa_key, "dpop-rs256-e2e", "RS256")),
            ("ES256", ec_key, ec_public_jwk(ec_key, "dpop-es256-e2e")),
            ("PS256", ps_key, rsa_public_jwk(ps_key, "dpop-ps256-e2e", "PS256")),
        ]:
            dpop_client_credentials_form = {
                "grant_type": "client_credentials",
                "client_id": secret_client_id,
                "client_secret": secret_client_secret,
                "scope": "profile",
            }
            nonce = request_dpop_nonce(
                dpop_client_credentials_form,
                key,
                algorithm=algorithm,
                public_jwk=public_jwk,
            )
            alg_dpop_token = token_with_dpop(
                dpop_client_credentials_form,
                key,
                nonce,
                f"POST /token client_credentials DPoP {algorithm}",
                algorithm=algorithm,
                public_jwk=public_jwk,
            )
            check(f"dpop_{algorithm.lower()}_access_token", bool(alg_dpop_token.get("access_token")))

        assertion_jti = str(uuid.uuid4())
        assertion = client_assertion(private_client_id, private_key, jti=assertion_jti)
        private_cc = expect_json(
            expect_status(
                "POST /token private_key_jwt",
                requests.post(
                    f"{BASE_URL}/token",
                    data={
                        "grant_type": "client_credentials",
                        "client_assertion_type": CLIENT_ASSERTION_TYPE,
                        "client_assertion": assertion,
                        "scope": "profile",
                    },
                    timeout=10,
                ),
                200,
            )
        )
        check("private_key_jwt_access_token", bool(private_cc.get("access_token")))
        replay = requests.post(
            f"{BASE_URL}/token",
            data={
                "grant_type": "client_credentials",
                "client_assertion_type": CLIENT_ASSERTION_TYPE,
                "client_assertion": assertion,
                "scope": "profile",
            },
            timeout=10,
        )
        expect_status("POST /token private_key_jwt replay rejected", replay, 401)

        for algorithm, key, kid in [
            ("RS256", rsa_key, "private-key-jwt-rs256-e2e"),
            ("ES256", ec_key, "private-key-jwt-es256-e2e"),
            ("PS256", ps_key, "private-key-jwt-ps256-e2e"),
        ]:
            alg_response = expect_json(
                expect_status(
                    f"POST /token private_key_jwt {algorithm}",
                    requests.post(
                        f"{BASE_URL}/token",
                        data={
                            "grant_type": "client_credentials",
                            "client_assertion_type": CLIENT_ASSERTION_TYPE,
                            "client_assertion": client_assertion(
                                multi_alg_private_client_id,
                                key,
                                algorithm=algorithm,
                                kid=kid,
                            ),
                            "scope": "profile",
                        },
                        timeout=10,
                    ),
                    200,
                )
            )
            check(f"private_key_jwt_{algorithm.lower()}_access_token", bool(alg_response.get("access_token")))

        applications = expect_json(
            expect_status(
                "GET /auth/me/applications after authorization",
                user.get(f"{BASE_URL}/auth/me/applications", timeout=10),
                200,
            )
        )
        check("applications_has_public_client", applications["total"] >= 1)

        grants = expect_json(
            expect_status(
                "GET /admin/grants",
                admin.get(f"{BASE_URL}/admin/grants", params={"page": 1, "page_size": 100}, timeout=10),
                200,
            )
        )
        check("admin_grants_has_public_client", any(g["client_id"] == public_client_id for g in grants["items"]))

        revoked_grant = expect_json(
            expect_status(
                "POST /admin/grants/revoke",
                admin.post(
                    f"{BASE_URL}/admin/grants/revoke",
                    json={"user_id": user_id, "client_id": public_client_id},
                    headers=csrf_header(admin),
                    timeout=10,
                ),
                200,
            )
        )
        check("admin_revoke_grant_removed", revoked_grant["removed_grants"] >= 1)

        first_request = expect_json(
            expect_status(
                "POST /auth/me/access-requests reject target",
                user.post(
                    f"{BASE_URL}/auth/me/access-requests",
                    json={
                        "site_name": "Reject Target",
                        "site_url": "https://reject.example",
                        "request_description": "Reject target for full e2e",
                    },
                    headers=csrf_header(user),
                    timeout=10,
                ),
                201,
            )
        )
        first_request_id = first_request["id"]
        expect_status(
            "GET /admin/access-requests",
            admin.get(
                f"{BASE_URL}/admin/access-requests",
                params={"status": 0, "q": "Reject", "page": 1, "page_size": 20},
                timeout=10,
            ),
            200,
        )
        rejected = expect_json(
            expect_status(
                "POST /admin/access-requests/{request_id}/reject",
                admin.post(
                    f"{BASE_URL}/admin/access-requests/{first_request_id}/reject",
                    json={"admin_note": "Rejected by full e2e"},
                    headers=csrf_header(admin),
                    timeout=10,
                ),
                200,
            )
        )
        check("access_request_rejected", rejected["status"] == 2)

        second_request = expect_json(
            expect_status(
                "POST /auth/me/access-requests approve target",
                user.post(
                    f"{BASE_URL}/auth/me/access-requests",
                    json={
                        "site_name": "Approve Target",
                        "site_url": "https://approve.example",
                        "request_description": "Approve target for full e2e",
                    },
                    headers=csrf_header(user),
                    timeout=10,
                ),
                201,
            )
        )
        second_request_id = second_request["id"]
        approved = expect_json(
            expect_status(
                "POST /admin/access-requests/{request_id}/approve",
                admin.post(
                    f"{BASE_URL}/admin/access-requests/{second_request_id}/approve",
                    json={
                        "client_name": "Approved Request Client",
                        "client_type": "confidential",
                        "redirect_uris": ["https://approve.example/callback"],
                        "scopes": ["openid", "profile", "email"],
                        "allowed_audiences": [DEFAULT_AUDIENCE],
                        "grant_types": ["authorization_code"],
                        "token_endpoint_auth_method": "client_secret_post",
                        "jwks": None,
                    },
                    headers=csrf_header(admin),
                    timeout=10,
                ),
                200,
            )
        )
        check("access_request_approved", approved["status"] == 1)

        access_requests = expect_json(
            expect_status(
                "GET /auth/me/access-requests after resolution",
                user.get(f"{BASE_URL}/auth/me/access-requests", timeout=10),
                200,
            )
        )
        check("user_access_requests_total", access_requests["total"] >= 2)

        valkey = redis.Redis.from_url(VALKEY_URL, decode_responses=True)
        delivery_keys = valkey.keys(f"oauth:client_delivery:{user_id}:*")
        check("delivery_key_created", len(delivery_keys) == 1, delivery_keys)
        delivery_token = delivery_keys[0].split(":")[-1]
        delivery = expect_json(
            expect_status(
                "GET /auth/me/access-delivery",
                user.get(
                    f"{BASE_URL}/auth/me/access-delivery",
                    params={"token": delivery_token},
                    timeout=10,
                ),
                200,
            )
        )
        check(
            "access_delivery_read_once_payload",
            delivery["request_id"] == second_request_id and delivery.get("client_secret"),
        )
        expect_status(
            "GET /auth/me/access-delivery read once",
            user.get(
                f"{BASE_URL}/auth/me/access-delivery",
                params={"token": delivery_token},
                timeout=10,
            ),
            404,
        )

        expect_status(
            "POST /auth/logout",
            user.post(f"{BASE_URL}/auth/logout", timeout=10),
            200,
        )
        expect_status(
            "GET /auth/me after logout",
            user.get(f"{BASE_URL}/auth/me", timeout=10),
            401,
        )

    finally:
        smtp.stop()


if __name__ == "__main__":
    run()
    print(json.dumps({"ok": True, "checks": checks}, ensure_ascii=False, indent=2))
