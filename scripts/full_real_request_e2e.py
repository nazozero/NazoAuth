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
from cryptography.hazmat.primitives.asymmetric import ed25519


BASE_URL = os.environ.get("E2E_BASE_URL", "http://nazo-oauth-e2e-server:8000")
DATABASE_URL = os.environ.get(
    "E2E_DATABASE_URL",
    "postgresql://postgres:postgres@nazo-oauth-e2e-postgres:5432/oauth",
)
VALKEY_URL = os.environ.get("E2E_VALKEY_URL", "redis://nazo-oauth-e2e-valkey:6379/0")

ADMIN_EMAIL = "admin-full-e2e@example.com"
ADMIN_PASSWORD = "AdminPassword-2026"
USER_EMAIL = "user-full-e2e@example.com"
USER_PASSWORD = "UserPassword-2026"
CLIENT_REDIRECT_URI = "http://client.example/callback"
DEFAULT_AUDIENCE = "resource://default"
CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


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


def dpop_proof(
    method: str,
    url: str,
    key: ed25519.Ed25519PrivateKey,
    *,
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
        ed25519_private_pem(key),
        algorithm="EdDSA",
        headers={"typ": "dpop+jwt", "jwk": ed25519_public_jwk(key)},
    )


def client_assertion(
    client_id: str,
    key: ed25519.Ed25519PrivateKey,
    *,
    jti: str | None = None,
) -> str:
    claims = {
        "iss": client_id,
        "sub": client_id,
        "aud": f"{BASE_URL}/token",
        "iat": now(),
        "exp": now() + 120,
        "jti": jti or str(uuid.uuid4()),
    }
    return jwt.encode(
        claims,
        ed25519_private_pem(key),
        algorithm="EdDSA",
        headers={"typ": "JWT", "kid": "private-key-jwt-e2e"},
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


def seed_prerequisites() -> None:
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


def request_dpop_nonce(
    form: dict[str, str],
    key: ed25519.Ed25519PrivateKey,
    path: str = "/token",
) -> str:
    url = f"{BASE_URL}{path}"
    response = requests.post(
        url,
        data=form,
        headers={"DPoP": dpop_proof("POST", url, key)},
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
    key: ed25519.Ed25519PrivateKey,
    nonce: str,
    check_name: str,
) -> dict[str, Any]:
    response = requests.post(
        f"{BASE_URL}/token",
        data=form,
        headers={"DPoP": dpop_proof("POST", f"{BASE_URL}/token", key, nonce=nonce)},
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
            and "email_verified" in discovery["claims_supported"],
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
                "Origin": "http://frontend.example",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "authorization,content-type,dpop,x-csrf-token",
            },
            timeout=10,
        )
        check("OPTIONS /token CORS", cors.status_code < 400, cors.text)
        check(
            "CORS allow origin",
            cors.headers.get("access-control-allow-origin") == "http://frontend.example",
        )

        anonymous_redirect = anonymous.get(
            f"{BASE_URL}/authorize",
            params={"client_id": "missing-client"},
            allow_redirects=False,
            timeout=10,
        )
        expect_status("GET /authorize anonymous redirect", anonymous_redirect, 302)

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

        request_id, verifier = authorize_request(user, public_client_id, state="approve-flow")
        code, verifier = approve_authorization(user, request_id, verifier, state="approve-flow")

        dpop_key = ed25519.Ed25519PrivateKey.generate()
        missing_redirect_form = {
            "grant_type": "authorization_code",
            "client_id": public_client_id,
            "code": code,
            "code_verifier": verifier,
        }
        nonce = request_dpop_nonce(missing_redirect_form, dpop_key)
        missing_redirect_response = requests.post(
            f"{BASE_URL}/token",
            data=missing_redirect_form,
            headers={"DPoP": dpop_proof("POST", f"{BASE_URL}/token", dpop_key, nonce=nonce)},
            timeout=10,
        )
        expect_status("POST /token redirect_uri required", missing_redirect_response, 400)
        check(
            "token_redirect_uri_required_error",
            expect_json(missing_redirect_response).get("error") == "invalid_grant",
        )

        nonce = request_dpop_nonce(
            {**missing_redirect_form, "redirect_uri": CLIENT_REDIRECT_URI}, dpop_key
        )
        token_response = token_with_dpop(
            {**missing_redirect_form, "redirect_uri": CLIENT_REDIRECT_URI},
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
                "DPoP": dpop_proof("GET", f"{BASE_URL}/userinfo", dpop_key, access_token=access_token),
            },
            timeout=10,
        )
        expect_status("GET /userinfo DPoP nonce challenge", userinfo_no_nonce, 400)
        userinfo_nonce = userinfo_no_nonce.headers.get("DPoP-Nonce")
        check("userinfo_nonce_header", bool(userinfo_nonce))
        userinfo = expect_json(
            expect_status(
                "GET /userinfo",
                requests.get(
                    f"{BASE_URL}/userinfo",
                    headers={
                        "Authorization": f"DPoP {access_token}",
                        "DPoP": dpop_proof(
                            "GET",
                            f"{BASE_URL}/userinfo",
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
                    data={"token": refreshed_access_token, "client_id": public_client_id},
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
                    data={"token": refreshed_access_token, "client_id": public_client_id},
                    timeout=10,
                ),
                200,
            )
        )
        check("introspect_inactive_after_revoke", introspected_after_revoke.get("active") is False)

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
