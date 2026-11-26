"""Prepare real user-grant fixtures with native credentials, outside the measured window."""
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import random
import secrets
import sys
from tempfile import TemporaryDirectory
import time
from urllib.parse import parse_qs, urlencode, urlsplit

from api import Api
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils
from html.parser import HTMLParser

os.umask(0o077)
ROOT = Path("/tmp")
ISSUER = "http://localhost:8080"
REALM = "/realms/api-audit/protocol/openid-connect"
CONFIG = {
    "nazo": ("oidc-bench-nazo", "/authorize", "/token", "nazo.json"),
    "keycloak": ("oidc-bench-keycloak", REALM + "/auth", REALM + "/token", "keycloak.json"),
    "hydra": ("oidc-bench-hydra", "/oauth2/auth", "/oauth2/token", "hydra.json"),
}


def b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def unb64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def signed_token(token, keys):
    header, claims, signature = token.split(".")
    meta = json.loads(unb64(header))
    key = next(k for k in keys if k.get("kid") == meta.get("kid"))
    content, sig = f"{header}.{claims}".encode(), unb64(signature)

    def number(field):
        return int.from_bytes(unb64(key[field]), "big")

    alg = meta["alg"]
    if alg == "RS256":
        rsa.RSAPublicNumbers(number("e"), number("n")).public_key().verify(
            sig, content, padding.PKCS1v15(), hashes.SHA256())
    elif alg == "ES256":
        pk = ec.EllipticCurvePublicNumbers(number("x"), number("y"), ec.SECP256R1()).public_key()
        der = utils.encode_dss_signature(int.from_bytes(sig[:32]), int.from_bytes(sig[32:]))
        pk.verify(der, content, ec.ECDSA(hashes.SHA256()))
    elif alg == "EdDSA" and key["crv"] == "Ed25519":
        ed25519.Ed25519PublicKey.from_public_bytes(unb64(key["x"])).verify(sig, content)
    else:
        raise RuntimeError(f"unexpected JWS algorithm {alg}")
    return meta, json.loads(unb64(claims))


def verify_grant(browser, value):
    api, issuer, discovery_path = browser.discovery()
    discovery, _, _ = api.call("GET", discovery_path)
    assert discovery["issuer"] == issuer

    def discovered_path(field):
        url = urlsplit(discovery[field])
        assert (url.scheme, url.netloc) == (urlsplit(issuer).scheme, urlsplit(issuer).netloc)
        return url.path + ("?" + url.query if url.query else "")

    keys, _, _ = api.call("GET", discovered_path("jwks_uri"))
    access = value["access_token"]
    identity, claims = signed_token(value["id_token"], keys["keys"])
    audience = claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]
    assert claims["exp"] > time.time() and claims["iss"] == issuer
    assert browser.client in audience and claims["nonce"] == browser.last_nonce
    if access.count(".") == 2:
        access_meta, access_claims = signed_token(access, keys["keys"])
        assert access_claims["exp"] > time.time() and access_claims["iss"] == issuer
        representation = "JWS:" + access_meta["alg"]
    else:
        representation = "JWE" if access.count(".") == 4 else "opaque"
    info, _, _ = api.call("GET", discovered_path("userinfo_endpoint"), headers={"Authorization": "Bearer " + access})
    assert info["sub"] == claims["sub"]
    return dict(access_token_format=representation, id_token_alg=identity["alg"], id_token_verified=True,
                access_token_userinfo_verified=True, id_token_claim_keys=sorted(claims),
                userinfo_claim_keys=sorted(info), token_type=value.get("token_type"))


def query_param(url, key):
    try:
        return parse_qs(urlsplit(url).query)[key][0]
    except (TypeError, KeyError):
        raise RuntimeError(f"authorization redirect missing {key}") from None


def own_path(address):
    url = urlsplit(address)
    assert f"{url.scheme}://{url.netloc}" == ISSUER
    return url.path + ("?" + url.query if url.query else "")


def callback_code(address, callback, state):
    actual = urlsplit(address)
    allowed = urlsplit(callback)
    assert (actual.scheme, actual.netloc, actual.path) == (allowed.scheme, allowed.netloc, allowed.path)
    assert query_param(address, "state") == state
    return query_param(address, "code")


class KeycloakForm(HTMLParser):
    action = None

    def handle_starttag(self, tag, attrs):
        fields = dict(attrs)
        if tag == "form" and fields.get("id") == "kc-form-login":
            self.action = fields.get("action")


class Browser:
    def __init__(self, peer, account, client, redirect):
        self.peer, self.account, self.client, self.redirect = peer, account, client, redirect
        self.host, self.authorize_path, self.token_path, _ = CONFIG[peer]
        self.public = Api(self.host)
        self.token = Api(self.host)
        self.admin = Api(self.host, 8081) if peer == "hydra" else None
        if peer == "nazo":
            self.public.login(account)

    def query(self, scope):
        verifier, state = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
        self.last_nonce = secrets.token_urlsafe(24)
        fields = {"response_type": "code", "client_id": self.client, "redirect_uri": self.redirect,
                  "scope": scope, "state": state, "nonce": self.last_nonce,
                  "code_challenge_method": "S256", "code_challenge": b64(hashlib.sha256(verifier.encode()).digest())}
        return self.authorize_path + "?" + urlencode(fields), verifier, state

    def authorization(self, scope, allow_login=False):
        path, verifier, state = self.query(scope)
        _, location, status = self.public.call("GET", path, expected=(200, 302, 303))
        if self.peer == "nazo" and not location.startswith(self.redirect + "?"):
            _, location, _ = self.public.form("POST", "/authorize/decision", {
                "request_id": query_param(location, "request_id"), "decision": "approve",
                "csrf_token": self.public.cookies["nazo_oauth_csrf"],
            }, expected=(302, 303))
        if self.peer == "keycloak" and not (location and location.startswith(self.redirect + "?")):
            for _ in range(4):
                if status == 200 or not location or not location.startswith(ISSUER + "/"):
                    break
                _, location, status = self.public.call("GET", own_path(location), expected=(200, 302, 303))
            if status == 200:
                if not allow_login:
                    raise RuntimeError("authenticated authorization demanded a new login")
                form = KeycloakForm()
                form.feed(self.public.last_body.decode())
                assert form.action
                _, location, _ = self.public.form("POST", own_path(form.action), {
                    "username": self.account["email"], "password": self.account["password"],
                }, expected=(302, 303))
        if self.peer == "hydra":
            challenge = query_param(location, "login_challenge")
            login, _, _ = self.admin.call("PUT", "/admin/oauth2/auth/requests/login/accept?" + urlencode({
                "login_challenge": challenge,
            }), {"subject": self.account["email"], "remember": True, "remember_for": 3600})
            _, location, _ = self.public.call("GET", own_path(login["redirect_to"]), expected=(302, 303))
            challenge = query_param(location, "consent_challenge")
            consent, _, _ = self.admin.call("PUT", "/admin/oauth2/auth/requests/consent/accept?" + urlencode({
                "consent_challenge": challenge,
            }), {"grant_scope": scope.split(), "remember": True, "remember_for": 3600})
            _, location, _ = self.public.call("GET", own_path(consent["redirect_to"]), expected=(302, 303))
        return callback_code(location, self.redirect, state), verifier

    def exchange(self, fields, expected=(200,)):
        return self.token.form("POST", self.token_path, fields, expected=expected)

    def discovery(self):
        realm = "/realms/api-audit" if self.peer == "keycloak" else ""
        return self.token, ISSUER + realm, realm + "/.well-known/openid-configuration"

    def fixture(self, flow, scope, auth):
        if flow == "authorize":
            path, verifier, state = self.query(scope)
            if os.environ.get("BENCH_SILENT") == "1":
                path += "&prompt=none"
            cookie = "; ".join(f"{k}={v}" for k, v in self.public.cookies.items())
            return {"method": "GET", "url": f"http://{self.host}:8080{path}", "operation": flow,
                    "headers": [("Host", "localhost:8080"), ("Cookie", cookie)] +
                               ([("X-CSRF-Token", self.public.cookies["nazo_oauth_csrf"])] if self.peer == "nazo" else []),
                    "authorize": {"peer": self.peer, "redirect": self.redirect, "state": state,
                                  "token_url": f"http://{self.host}:8080{self.token_path}",
                                  "token_fields": list(dict(auth, code_verifier=verifier, redirect_uri=self.redirect,
                                                            grant_type="authorization_code").items()),
                                  "csrf": self.public.cookies.get("nazo_oauth_csrf", "")}}
        code, verifier = self.authorization(scope)
        fields = exchange_fields(auth, self.redirect, code, verifier)
        return {"method": "POST", "url": f"http://{self.host}:8080{self.token_path}", "operation": flow,
                "headers": [("Host", "localhost:8080"), ("Content-Type", "application/x-www-form-urlencoded")],
                "body": urlencode(fields)}


def exchange_fields(auth, redirect, code, verifier):
    return dict(auth, grant_type="authorization_code", redirect_uri=redirect, code=code, code_verifier=verifier)


def prepare(peer, flow, total, users_count, target, rate=None):
    if peer in CONFIG:
        _, _, _, name = CONFIG[peer]
        config = json.loads((ROOT / name).read_bytes())
        factory = Browser
    else:
        from native_protocol import NativeBrowser, native_config
        config = native_config(peer)
        factory = NativeBrowser
    assert len(config["users"]) >= users_count
    client = config["clients"]["oidc"]
    auth = {"client_id": client, "client_secret": config["client_secrets"][client]}
    offline_grant = flow == "refresh" and peer in ("nazo", "hydra", "keycloak")
    scope = "openid profile offline_access" if offline_grant else "openid profile"
    if peer == "hydra" and flow == "authorize":
        raise RuntimeError("Hydra's external authentication is a separate workload")
    start = time.time()
    probe = factory(peer, config["users"][0], client, config["redirect_uri"])
    code, verifier = probe.authorization(scope, allow_login=True)
    grant, _, _ = probe.exchange(exchange_fields(auth, probe.redirect, code, verifier))
    proof = dict(scope=scope, access_ttl=grant["expires_in"], **verify_grant(probe, grant))
    code_ttl = 600 if peer == "hydra" else 60
    preparation_budget = min(120, code_ttl - (4 if rate else 28))
    expires = time.monotonic() + preparation_budget if flow == "exchange" else None

    def lane(index):
        browser = factory(peer, config["users"][index], client, config["redirect_uri"])
        browser.authorization(scope, allow_login=True)
        requests = []
        for slot in range(index, total, users_count):
            if expires is not None and time.monotonic() >= expires:
                raise RuntimeError("prepared-code TTL budget exhausted before all one-time codes were available")
            earliest_issued = time.time() if flow == "exchange" else None
            requests.append((slot, browser.fixture(flow, scope, auth), earliest_issued))
        return requests

    started = time.time()
    with ThreadPoolExecutor(max_workers=min(16, users_count)) as pool:
        if flow == "userinfo":
            def userinfo_fixture(index):
                browser = factory(peer, config["users"][index], client, config["redirect_uri"])
                code, verifier = browser.authorization(scope, allow_login=True)
                grant, _, _ = browser.exchange(exchange_fields(auth, browser.redirect, code, verifier))
                api, issuer, discovery_path = browser.discovery()
                doc, _, _ = api.call("GET", discovery_path)
                uri = urlsplit(doc["userinfo_endpoint"])
                trusted = urlsplit(issuer)
                assert (uri.scheme, uri.netloc) == (trusted.scheme, trusted.netloc)
                headers = {"Authorization": "Bearer " + grant["access_token"]}
                info, _, _ = api.call("GET", uri.path, headers=headers)
                expected_subject = json.loads(unb64(grant["id_token"].split(".")[1]))["sub"]
                assert expected_subject == info["sub"]
                base = getattr(browser, "base", None)
                if not base:
                    headers["Host"] = "localhost:8080"
                return {"method": "GET", "url": (base or f"http://{browser.host}:8080") + uri.path,
                        "headers": list(headers.items()), "operation": flow, "userinfo_subject": expected_subject}
            requests = list(pool.map(userinfo_fixture, range(users_count)))
            assert len({r["userinfo_subject"] for r in requests}) == users_count
        elif flow == "refresh":
            # Cover half a second of standalone arrivals, twice the refresh P99 budget.
            # Mixed workloads keep their fixed pool and call this function without a rate.
            families = max(8, ((rate or 0) + 2 * users_count - 1) // (2 * users_count))
            if maximum := os.environ.get("BENCH_REFRESH_MAX_FAMILIES"):
                families = min(families, int(maximum))

            def initial_refresh(browser):
                code, verifier = browser.authorization(scope, allow_login=True)
                grant, _, _ = browser.exchange(exchange_fields(auth, browser.redirect, code, verifier))
                fields = dict(auth, grant_type="refresh_token")
                active, _, _ = browser.exchange(dict(fields, refresh_token=grant["refresh_token"]))
                assert active["refresh_token"] and active["refresh_token"] != grant["refresh_token"]
                base = getattr(browser, "base", None)
                return {"method": "POST", "url": (base or f"http://{browser.host}:8080") + browser.token_path,
                        "headers": [] if base else [("Host", "localhost:8080")],
                        "operation": flow, "previous_refresh": active["refresh_token"],
                        "refresh_form": list(fields.items())}
            def build_lane(user):
                browser = factory(peer, user, client, config["redirect_uri"])
                return [initial_refresh(browser) for _ in range(families)]

            lanes = list(pool.map(build_lane, config["users"][:users_count]))
            requests = [request for family in zip(*lanes, strict=True) for request in family]
            assert len({r["previous_refresh"] for r in requests}) == users_count * families
            proof["fixture_contract"] = "rotating-family-pool"
            proof["families_per_user"] = families
        else:
            prepared = sorted(item for items in pool.map(lane, range(users_count)) for item in items)
            requests = [r for _, r, _ in prepared]
            assert len(requests) == total
            if flow == "exchange" and rate:
                proof["latest_safe_start_epoch"] = min(t + code_ttl - slot / rate - 2 for slot, _, t in prepared)
    target.write_text(json.dumps(requests))
    return dict(proof, users=users_count, fixtures=len(requests), fixture_ready_epoch=time.time(),
                fixture_oldest_upper_age_seconds=round(time.time()-started, 3),
                preparation_seconds=round(time.time()-start, 3),
                code_ttl_seconds=code_ttl)


def prepare_mixed(peer, total, users, target):
    batch = ["machine"] * 6 + ["introspect"] * 10 + ["exchange"] * 2 + ["refresh", "authorize"]
    assert total % len(batch) == 0
    count = {op: batch.count(op) * total // len(batch) for op in set(batch)}
    start = time.time()
    cohorts = {}
    data = {op: json.loads((ROOT / f"goose-mixed-{op}.json").read_bytes()) for op in ("machine", "introspect")}
    with TemporaryDirectory(prefix="goose-mixed-") as directory:
        dest = Path(directory) / "requests.json"
        for flow in ("refresh", "authorize", "exchange"):
            cohorts[flow] = prepare(peer, flow, count[flow], users, dest)
            data[flow] = json.loads(dest.read_bytes())
    used = dict.fromkeys(data, 0)
    rand = random.Random(19716)
    requests = []
    for _ in range(total // len(batch)):
        rand.shuffle(batch)
        for op in batch:
            requests.append(data[op][used[op] % len(data[op])])
            used[op] += 1
    target.write_text(json.dumps(requests))
    exchange = cohorts["exchange"]
    return dict(plan=count, seed=19716, users=users, fixtures=total,
                fixture_ready_epoch=exchange["fixture_ready_epoch"],
                fixture_oldest_upper_age_seconds=exchange["fixture_oldest_upper_age_seconds"],
                code_ttl_seconds=exchange["code_ttl_seconds"], preparation_seconds=round(time.time()-start, 3),
                cohort_proof=cohorts)


if __name__ == "__main__":
    peer, flow, total, users, path = sys.argv[1:]
    if flow == "mixed-core":
        proof = prepare_mixed(peer, int(total), int(users), Path(path))
    else:
        rate = int(os.environ["BENCH_RATE"]) if os.environ.get("BENCH_RATE") else None
        proof = prepare(peer, flow, int(total), int(users), Path(path), rate)
    print(json.dumps(proof, indent=2))
