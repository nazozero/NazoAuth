"""Provision the sixteen-client dataset through existing benchmark management APIs."""
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys
from urllib.parse import quote
from urllib.request import HTTPSHandler, build_opener

from api import Api
from urllib.error import HTTPError
from urllib.request import Request

ROOT = Path("/tmp")
PEER = sys.argv[1]
BASE = ROOT / f"goose8-{PEER}.json"
REDIRECT = "https://bench.test/callback"
IDS = [f"goose-machine-{i:02d}" for i in range(16)]
os.umask(0o077)


def provision_nazo():
    api = Api()
    actor = json.loads((ROOT / "actor.json").read_bytes())
    api.login(actor)
    clients = []
    for label in IDS:
        value, _, _ = api.call("POST", "/admin/clients", {
            "client_name": label, "client_type": "confidential", "redirect_uris": [REDIRECT],
            "allowed_audiences": ["resource://default"], "scopes": ["profile"],
            "grant_types": ["client_credentials"], "token_endpoint_auth_method": "client_secret_basic",
        }, (201,))
        clients.append({"id": value["client_id"], "secret": value["client_secret"]})
    return clients


def provision_hydra():
    api = Api("oidc-bench-hydra", 8081)
    clients = []
    for label in IDS:
        value, _, _ = api.call("POST", "/admin/clients", {
            "client_name": label, "scope": "profile", "grant_types": ["client_credentials"],
            "token_endpoint_auth_method": "client_secret_basic", "redirect_uris": [REDIRECT],
        }, (201,))
        clients.append({"id": value["client_id"], "secret": value["client_secret"]})
    return clients


def provision_keycloak():
    api = Api("oidc-bench-keycloak")
    bootstrap = json.loads((ROOT / "peer-bootstrap.json").read_bytes())
    token, _, _ = api.form("POST", "/realms/master/protocol/openid-connect/token", {
        "grant_type": "client_credentials", "client_id": bootstrap["client_id"], "client_secret": bootstrap["secret"],
    })
    headers = {"Authorization": "Bearer " + token["access_token"]}
    path = "/admin/realms/api-audit/clients"
    clients = []
    for label in IDS:
        _, location, _ = api.call("POST", path, {
            "clientId": label, "protocol": "openid-connect", "enabled": True, "publicClient": False,
            "standardFlowEnabled": False, "directAccessGrantsEnabled": False, "serviceAccountsEnabled": True,
            "clientAuthenticatorType": "client-secret", "redirectUris": [REDIRECT],
        }, expected=(201, 409), headers=headers)
        if location:
            internal = location.rstrip("/").rsplit("/", 1)[-1]
        else:
            existing, _, _ = api.call("GET", path + "?clientId=" + quote(label), headers=headers)
            internal = next(x["id"] for x in existing if x["clientId"] == label)
        detail = f"{path}/{internal}"
        scopes, _, _ = api.call("GET", detail + "/default-client-scopes", headers=headers)
        for scope in scopes:
            if scope["name"] == "email":
                api.call("DELETE", detail + "/default-client-scopes/" + scope["id"], expected=(204,), headers=headers)
        mapper = detail + "/protocol-mappers/models"
        mappings, _, _ = api.call("GET", mapper, headers=headers)
        if not any(m["name"] == "machine token audience" for m in mappings):
            api.call("POST", mapper, {
                "name": "machine token audience", "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "config": {"included.client.audience": label, "access.token.claim": "true",
                           "introspection.token.claim": "true", "id.token.claim": "false"},
            }, expected=(201,), headers=headers)
        secret, _, _ = api.call("GET", detail + "/client-secret", headers=headers)
        clients.append({"id": label, "secret": secret["value"]})
    return clients


def http_api(base, ca=None):
    opener = build_opener(HTTPSHandler(context=ssl.create_default_context(cafile=ca)))
    def invoke(path, method="GET", data=None, headers=None, statuses=(200,)):
        hdr = dict(headers or {})
        if data is not None:
            hdr["Content-Type"] = "application/json"
        req = Request(base + path, json.dumps(data).encode() if data is not None else None, hdr, method=method)
        try:
            with opener.open(req, timeout=8) as response:
                status = response.status
                body = response.read()
                doc = json.loads(body) if body else None
        except HTTPError as error:
            status, doc = error.code, None
        if status not in statuses:
            raise RuntimeError(f"{method} {path} returned {status}")
        return doc
    return invoke


def provision_rauthy():
    api = http_api("http://rauthy.bench.test:8080")
    auth = {"Authorization": "API-Key bench$" + (ROOT / "extra-rauthy-api").read_text().strip()}
    path = "/auth/v1/clients"
    clients = []
    for label in IDS:
        detail = path + "/" + label
        current = api(detail, headers=auth, statuses=(200, 404))
        if not current:
            api(path, "POST", {"id": label, "name": label, "confidential": True, "redirect_uris": [REDIRECT]}, auth)
            current = api(detail, headers=auth)
        current.update(enabled=True, flows_enabled=["client_credentials"], access_token_alg="RS256",
                       scopes=["profile"], default_scopes=["profile"], access_token_lifetime=300)
        api(detail, "PUT", current, auth)
        secret = api(detail + "/secret", "POST", headers=auth)
        clients.append({"id": label, "secret": secret["secret"]})
    return clients


def provision_kanidm():
    from urllib.request import Request, urlopen
    base = "https://kanidm.bench.test:8443"
    ca = "/tmp/goose-kanidm-root.pem"
    api = http_api(base, ca)
    password = re.search(r'new_password\s*[:=]\s*"([^"]+)"', (ROOT / "extra-kanidm-recovery").read_text()).group(1)
    context = ssl.create_default_context(cafile=ca)
    headers = {"Content-Type": "application/json"}
    for step in [{"init2": {"username": "idm_admin", "issue": "token", "privileged": True}},
                 {"begin": "password"}, {"cred": {"password": password}}]:
        req = Request(base + "/v1/auth", json.dumps({"step": step}).encode(), headers, method="POST")
        with urlopen(req, context=context, timeout=5) as response:
            state = json.load(response)["state"]
            if session := response.headers.get("x-kanidm-auth-session-id"):
                headers["x-kanidm-auth-session-id"] = session
    auth = {"Authorization": "Bearer " + state["success"]}
    group = "/v1/group/gooseclients"
    if not api(group, headers=auth):
        api("/v1/group", "POST", {"attrs": {"name": ["gooseclients"]}}, auth)
    clients = []
    for label in IDS:
        path = "/v1/oauth2/" + label
        if not api(path, headers=auth):
            api("/v1/oauth2/_basic", "POST", {"attrs": {"name": [label], "displayname": [label],
                "oauth2_rs_origin_landing": ["https://bench.test"], "oauth2_strict_redirect_uri": ["true"]}}, auth)
        secret = api(path + "/_basic_secret", headers=auth)
        clients.append({"id": label, "secret": secret})
    api(group + "/_attr/member", "PUT", IDS, auth)
    for label in IDS:
        api(f"/v1/oauth2/{label}/_scopemap/gooseclients", "POST", ["profile"], auth)
    return clients


subprocess.run([sys.executable, "/tmp/prepare-replay-profiles.py", PEER], check=True, stdout=subprocess.DEVNULL)
if not BASE.exists():
    profile = json.loads((ROOT / "goose-profile.json").read_bytes())
    profile["clients"] = {
        "nazo": provision_nazo, "keycloak": provision_keycloak, "hydra": provision_hydra,
        "rauthy": provision_rauthy, "kanidm": provision_kanidm,
    }[PEER]()
    temp = BASE.with_suffix(".tmp")
    temp.write_text(json.dumps(profile))
    temp.replace(BASE)
assert len(json.loads(BASE.read_bytes())["clients"]) == 16
