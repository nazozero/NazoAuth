"""Authorize through each service's native session and OAuth APIs."""
import hashlib
import hmac
from http.client import HTTPConnection, HTTPSConnection
import json
import os
import re
import secrets
import ssl
import subprocess
import time
from urllib.parse import urlencode, urlsplit

from api import Api, ApiError
from protocol_fixtures import ROOT, b64, callback_code, exchange_fields

REDIRECT = "https://client.example.test/callback"
KANIDM = "https://kanidm.bench.test:8443"
RAUTHY = "http://rauthy.bench.test:8080"
BENCH_USER_AGENT = "oauth-goose-bench/0.19.2"


class AuthConnection(HTTPSConnection):
    def getresponse(self):
        response = super().getresponse()
        self.auth_session = response.getheader("x-kanidm-auth-session-id")
        return response


class NativeApi(Api):
    def __init__(self, base):
        url = urlsplit(base)
        self.cookies = {}
        self.csrf = None
        self.base = base
        self.host = url.netloc
        if url.scheme == "https":
            context = ssl.create_default_context(cafile=str(ROOT / "goose-kanidm-root.pem"))
            self.conn = AuthConnection(url.hostname, url.port, timeout=10, context=context)
        else:
            self.conn = HTTPConnection(url.hostname, url.port, timeout=10)

    def call(self, method, path, payload=None, expected=(200,), headers=None):
        opts = {"Host": self.host}
        if self.base == RAUTHY:
            opts["User-Agent"] = BENCH_USER_AGENT
        if self.csrf:
            opts["X-CSRF-Token"] = self.csrf
        return super().call(method, path, payload, expected, {**opts, **(headers or {})})


def totp(binding):
    step = binding["step"]
    if time.time() % step >= step - 2:
        time.sleep(2)
    counter = int(time.time()) // step
    mac = hmac.digest(bytes(binding["secret"]), counter.to_bytes(8, "big"), binding["algo"])
    off = mac[-1] & 15
    return (int.from_bytes(mac[off:off + 4], "big") & 0x7fffffff) % 10 ** binding["digits"]


def kanidm_login(api, account, privileged=False):
    headers = {}
    second_factor = account.get("totp")
    steps = [{"init2": {"username": account["email"], "issue": "token", "privileged": privileged}},
             {"begin": "passwordmfa" if second_factor else "password"}]
    if second_factor:
        steps.append({"cred": {"totp": totp(second_factor)}})
    steps.append({"cred": {"password": account["password"]}})
    for step in steps:
        data, _, _ = api.call("POST", "/v1/auth", {"step": step}, headers=headers)
        if session := api.conn.auth_session:
            headers["x-kanidm-auth-session-id"] = session
    return {"Authorization": "Bearer " + data["state"]["success"]}


def rauthy_fields(client, redirect, scope):
    verifier = secrets.token_urlsafe(32)
    params = {"client_id": client, "redirect_uri": redirect, "scopes": scope.split() or None,
              "state": secrets.token_urlsafe(24), "nonce": secrets.token_urlsafe(24),
              "code_challenge_method": "S256", "code_challenge": b64(hashlib.sha256(verifier.encode()).digest())}
    return params, verifier


def rauthy_login(api, account, fields):
    session, _, _ = api.call("POST", "/auth/v1/oidc/session", expected=(200, 201))
    api.csrf = session["csrf_token"]
    api.call("POST", "/auth/v1/pow")
    solution = subprocess.run([str(ROOT / "goose-rauthy-pow")], input=api.last_body,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True, timeout=20).stdout.decode().strip()
    _, location, _ = api.call("POST", "/auth/v1/oidc/authorize", {
        **fields, "email": account["email"], "password": account["password"], "pow": solution,
    }, (202,))
    return location


def configure_kanidm(user_count):
    api = NativeApi(KANIDM)
    password = re.search(r'new_password\s*[:=]\s*"([^"]+)"', (ROOT / "extra-kanidm-recovery").read_text()).group(1)
    auth = kanidm_login(api, {"email": "idm_admin", "password": password}, privileged=True)
    client, group = "goose-oidc", "gooseoidcusers"
    client_path, group_path = "/v1/oauth2/" + client, "/v1/group/" + group
    if not api.call("GET", client_path, headers=auth)[0]:
        api.call("POST", "/v1/oauth2/_basic", {"attrs": {"name": [client], "displayname": [client],
                 "oauth2_rs_origin_landing": ["https://client.example.test"], "oauth2_strict_redirect_uri": ["true"]}}, headers=auth)
        api.call("POST", client_path + "/_attr/oauth2_rs_origin", [REDIRECT], headers=auth)
    if not api.call("GET", group_path, headers=auth)[0]:
        api.call("POST", "/v1/group", {"attrs": {"name": [group]}}, headers=auth)

    users = []
    for i in range(user_count):
        name = f"goose-oidc-{i:03d}"
        password = "aP3!" + secrets.token_urlsafe(30)
        path = "/v1/person/" + name
        if not api.call("GET", path, headers=auth)[0]:
            api.call("POST", "/v1/person", {"attrs": {"name": [name], "displayname": [name]}}, headers=auth)
        session, _ = api.call("GET", path + "/_credential/_update", headers=auth)[0]
        api.call("POST", "/v1/credential/_update", [{"password": password}, session])
        registration = api.call("POST", "/v1/credential/_update", ["totpgenerate", session])[0]
        binding = registration["mfaregstate"]["TotpCheck"]
        verified = api.call("POST", "/v1/credential/_update", [{"totpverify": [totp(binding), "Benchmark"]}, session])[0]
        assert verified["can_commit"], "Kanidm MFA credential setup must be committable"
        api.call("POST", "/v1/credential/_commit", session)
        account = {"email": name, "password": password, "totp": binding}
        account["session_headers"] = kanidm_login(NativeApi(KANIDM), account)
        users.append(account)
    api.call("PUT", group_path + "/_attr/member", [user["email"] for user in users], headers=auth)
    api.call("POST", client_path + "/_scopemap/" + group, ["openid", "profile"], headers=auth)
    secret = api.call("GET", client_path + "/_basic_secret", headers=auth)[0]
    return client, secret, users


def configure_rauthy(user_count):
    api = NativeApi(RAUTHY)
    auth = {"Authorization": "API-Key bench$" + (ROOT / "extra-rauthy-api").read_text().strip()}
    client = "goose-oidc"
    collection = "/auth/v1/clients"
    path = collection + "/" + client
    current, _, status = api.call("GET", path, expected=(200, 404), headers=auth)
    if status == 404:
        api.call("POST", collection, {"id": client, "name": client, "confidential": True, "redirect_uris": [REDIRECT]},
                 expected=(200, 201), headers=auth)
        current, _, _ = api.call("GET", path, headers=auth)
    current.update(enabled=True, confidential=True, redirect_uris=[REDIRECT],
                   flows_enabled=["authorization_code", "refresh_token"], access_token_alg="RS256",
                   id_token_alg="RS256", scopes=["openid", "profile"], default_scopes=["openid", "profile"],
                   challenges=["S256"], force_mfa=current.get("force_mfa", False),
                   auth_code_lifetime=60, access_token_lifetime=300)
    try:
        api.call("PUT", path, current, headers=auth)
    except ApiError as error:
        reply = api.last_body.decode(errors="replace")
        message = (json.loads(reply).get("message", "") if reply.startswith("{") else reply).splitlines()
        if message and re.match(r"^(Json deserialize error|validation error|Validation error)", message[0]):
            raise RuntimeError(f"Rauthy client configuration returned {error.status}: {message[0][:160]}") from None
        raise
    secret = api.call("POST", path + "/secret", headers=auth)[0]["secret"]
    user_admin = rauthy_user_admin(api)
    collection = "/auth/v1/users"
    # Reuse existing user IDs if dataset creation was interrupted after provisioning.
    existing, _, _ = api.call("GET", collection + "?page_size=100", expected=(200, 206), headers=user_admin)
    by_email = {record["email"]: record["id"] for record in existing} if isinstance(existing, list) else {}
    users = []
    for i in range(user_count):
        email = f"goose-oidc-{i:03d}@bench.test"
        password = "aP3!" + secrets.token_urlsafe(30)
        fields = {"email": email, "family_name": "Benchmark", "given_name": "OAuth",
                  "language": "en", "roles": ["user"]}
        uid = by_email.get(email)
        if not uid:
            registered, location, _ = api.call("POST", collection, fields, expected=(200, 201), headers=user_admin)
            uid = (registered or {}).get("id") or location.rstrip("/").rsplit("/", 1)[-1]
        api.call("PUT", f"{collection}/{uid}", dict(fields, password=password, enabled=True, email_verified=True),
                 expected=(200, 202, 204), headers=user_admin)
        users.append({"email": email, "password": password})
    return client, secret, users


def rauthy_user_admin(api):
    """Enroll a benchmark-owned test authenticator through the native password-verified ceremony."""
    key_path = ROOT / "goose-rauthy-user-management"
    if not key_path.exists():
        import sys
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from fido2.cose import ES256
        from fido2.webauthn import Aaguid, AttestationObject, AttestedCredentialData, AuthenticatorData, CollectedClientData
        from protocol_fixtures import unb64

        admin = json.loads((ROOT / "goose-rauthy-admin.json").read_bytes())
        params, _ = rauthy_fields("rauthy", RAUTHY + "/auth/v1/oidc/callback", "")
        rauthy_login(api, admin, params)
        session, _, _ = api.call("GET", "/auth/v1/oidc/sessioninfo")
        user = "/auth/v1/users/" + session["user_id"]
        token, _, _ = api.call("POST", user + "/mfa_token", {"password": admin["password"]})
        label = "CNB Benchmark Key"
        path = user + "/webauthn/register/"
        options, _, _ = api.call("POST", path + "start", {"passkey_name": label, "mfa_mod_token_id": token["id"]})
        options = options["publicKey"]
        rp = options["rp"]["id"]
        assert rp == urlsplit(RAUTHY).hostname
        assert options.get("attestation", "none") == "none"
        key = ec.generate_private_key(ec.SECP256R1())
        credential_id = secrets.token_bytes(32)
        credential = AttestedCredentialData.create(Aaguid.NONE, credential_id, ES256.from_cryptography_key(key.public_key()))
        flags = AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.UV | AuthenticatorData.FLAG.AT
        authenticator = AuthenticatorData.create(hashlib.sha256(rp.encode()).digest(), flags, 0, credential)
        client = CollectedClientData.create("webauthn.create", unb64(options["challenge"]), RAUTHY)
        attestation = AttestationObject.create("none", authenticator, {})
        data = {"id": b64(credential_id), "rawId": b64(credential_id), "type": "public-key",
                "response": {"attestationObject": b64(attestation), "clientDataJSON": b64(client)},
                "clientExtensionResults": {}}
        private = ROOT / "goose-rauthy-virtual-passkey.json"
        private.write_text(json.dumps({"credential": b64(credential_id), "key": key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()}))
        api.call("POST", path + "finish", {"passkey_name": label, "data": data}, (200, 201))
        api.call("POST", "/auth/v1/api_keys", {"name": "goose-bench-users", "exp": int(time.time()) + 14400,
                 "access": [{"group": "Users", "access_rights": ["read", "create", "update"]}]})
        secret = api.last_body.decode().strip()
        assert secret.startswith("goose-bench-users$")
        key_path.write_text(secret)
    return {"Authorization": "API-Key " + key_path.read_text().strip()}


def native_config(peer, users_count=32):
    path = ROOT / f"goose-protocol-{peer}-config.json"
    if path.exists():
        return json.loads(path.read_bytes())
    setup = {"kanidm": configure_kanidm, "rauthy": configure_rauthy}[peer]
    client, secret, users = setup(users_count)
    config = dict(users=users, clients={"oidc": client}, client_secrets={client: secret}, redirect_uri=REDIRECT)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(config))
    temporary.replace(path)
    return config


class NativeBrowser:
    def __init__(self, peer, account, client, redirect):
        self.peer, self.account, self.client, self.redirect = peer, account, client, redirect
        self.base = KANIDM if peer == "kanidm" else RAUTHY
        self.token_path = "/oauth2/token" if peer == "kanidm" else "/auth/v1/oidc/token"
        self.client_http = NativeApi(self.base)
        self.token = NativeApi(self.base)
        self.session_headers = account["session_headers"] if peer == "kanidm" else {}

    def authorization_request(self, scope):
        fields, verifier = rauthy_fields(self.client, self.redirect, scope)
        self.last_nonce = fields["nonce"]
        if self.peer == "kanidm":
            fields["scope"] = " ".join(fields.pop("scopes"))
            path = "/oauth2/authorise?" + urlencode(dict(fields, response_type="code"))
            return "GET", path, None, fields, verifier
        return "POST", "/auth/v1/oidc/authorize/refresh", fields, fields, verifier

    def authorization(self, scope, allow_login=False):
        method, path, body, fields, verifier = self.authorization_request(scope)
        if self.peer == "kanidm":
            value, location, status = self.client_http.call(method, path, body, (200, 302, 303), self.session_headers)
            if status == 200:
                consent = value["ConsentRequested"]["consent_token"]
                _, location, _ = self.client_http.call("POST", "/oauth2/authorise/permit", json.dumps(consent),
                                                       (200, 302, 303), dict(self.session_headers, **{"Content-Type": "application/json"}))
        elif self.client_http.csrf is None and allow_login:
            location = rauthy_login(self.client_http, self.account, fields)
        else:
            _, location, _ = self.client_http.call(method, path, body, (202,))
        return callback_code(location, self.redirect, fields["state"]), verifier

    def exchange(self, fields, expected=(200,)):
        return self.token.form("POST", self.token_path, fields, expected=expected)

    def discovery(self):
        if self.peer == "kanidm":
            path = "/oauth2/openid/" + self.client
            return self.token, self.base + path, path + "/.well-known/openid-configuration"
        path = "/auth/v1/"
        return self.token, self.base + path, path + ".well-known/openid-configuration"

    def fixture(self, flow, scope, auth):
        token_url = self.base + self.token_path
        if flow == "authorize":
            method, path, body, fields, verifier = self.authorization_request(scope)
            if self.peer == "kanidm" and os.environ.get("BENCH_SILENT") == "1":
                path += "&prompt=none"
            headers = list(self.session_headers.items())
            if body is not None:
                headers = [("Content-Type", "application/json"), ("X-CSRF-Token", self.client_http.csrf),
                           ("User-Agent", BENCH_USER_AGENT),
                           ("Cookie", "; ".join(f"{k}={v}" for k, v in self.client_http.cookies.items()))]
            extra = {}
            if self.peer == "rauthy" and os.environ.get("BENCH_SILENT") == "1":
                extra["rauthy_refresh_body"] = json.dumps(body)
                query = dict(fields, response_type="code", prompt="none", scope=" ".join(fields["scopes"]))
                del query["scopes"]
                method, path, body = "GET", "/auth/v1/oidc/authorize?" + urlencode(query), None
                headers = [(k, v) for k, v in headers if k in ("User-Agent", "Cookie")]
            return dict(method=method, url=self.base + path, headers=headers, body=json.dumps(body) if body else "",
                        operation=flow, authorize=dict(**extra, peer=self.peer, redirect=self.redirect,
                        state=fields["state"], token_url=token_url, csrf="", token_fields=list(dict(
                        auth, code_verifier=verifier, redirect_uri=self.redirect, grant_type="authorization_code").items())))
        code, verifier = self.authorization(scope)
        fields = exchange_fields(auth, self.redirect, code, verifier)
        return dict(method="POST", url=token_url, headers=[("Content-Type", "application/x-www-form-urlencoded")],
                    body=urlencode(fields), operation=flow)
