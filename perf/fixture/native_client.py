"""Provision clients via product APIs and verify the exact operation before each load."""
import base64
import json
import os
from pathlib import Path
import re
import ssl
import sys
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

os.umask(0o077)
peer = sys.argv[1]
client = "benchmachine"
base = {"rauthy": "http://rauthy.bench.test:8080", "kanidm": "https://kanidm.bench.test:8443"}[peer]
ca = ssl.create_default_context(cafile="/tmp/extra-ca.pem")
state = Path("/tmp/extra-" + peer + "-client.json")


def call(url, method="GET", data=None, headers=None, form=False, optional=False):
    headers = dict(headers or {})
    if data is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
        data = (urlencode(data) if form else json.dumps(data)).encode()
    try:
        with urlopen(Request(url, data, headers, method=method), context=ca, timeout=10) as r:
            raw = r.read()
            return (json.loads(raw) if raw else None), r.headers
    except HTTPError as e:
        if optional and e.code == 404:
            return None, {}
        # Do not log tokens or credentials.
        raise RuntimeError(f"{method} {urlsplit(url).path} returned HTTP {e.code}") from None


def rauthy():
    auth = {"Authorization": "API-Key bench$" + Path("/tmp/extra-rauthy-api").read_text().strip()}
    url = base + "/auth/v1/clients"
    existing, _ = call(url + "/" + client, headers=auth, optional=True)
    if not existing:
        call(url, "POST", {"id": client, "name": "Benchmark", "confidential": True,
                           "redirect_uris": ["https://bench.test/callback"]}, auth)
    doc, _ = call(url + "/" + client, headers=auth)
    doc.update(enabled=True, flows_enabled=["client_credentials"], access_token_alg="RS256",
               scopes=["profile"], default_scopes=["profile"], access_token_lifetime=300)
    call(url + "/" + client, "PUT", doc, auth)
    secret, _ = call(url + "/" + client + "/secret", "POST", headers=auth)
    return secret["secret"]


def kanidm():
    log = Path("/tmp/extra-kanidm-recovery").read_text()
    password = re.search(r'new_password\s*[:=]\s*"([^"]+)"', log).group(1)
    auth = {}
    for step in [{"init2": {"username": "idm_admin", "issue": "token", "privileged": True}},
                 {"begin": "password"}, {"cred": {"password": password}}]:
        answer, headers = call(base + "/v1/auth", "POST", {"step": step}, auth)
        if headers.get("x-kanidm-auth-session-id"):
            auth["x-kanidm-auth-session-id"] = headers["x-kanidm-auth-session-id"]
    auth = {"Authorization": "Bearer " + answer["state"]["success"]}
    def api(path, method="GET", data=None):
        return call(base + "/v1/" + path, method, data, auth, optional=(method == "GET"))[0]
    if not api("oauth2/" + client):
        api("oauth2/_basic", "POST", {"attrs": {"name": [client], "displayname": ["Benchmark"],
             "oauth2_rs_origin_landing": ["https://bench.test"], "oauth2_strict_redirect_uri": ["true"]}})
    if not api("group/benchclients"):
        api("group", "POST", {"attrs": {"name": ["benchclients"]}})
    api("group/benchclients/_attr/member", "PUT", [client])
    api("oauth2/" + client + "/_scopemap/benchclients", "POST", ["profile"])
    return api("oauth2/" + client + "/_basic_secret")



if not state.exists():
    state.write_text(json.dumps(rauthy() if peer == "rauthy" else kanidm()))
