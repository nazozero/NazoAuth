"""Prepare introspection requests and verify the subject of every user token."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
import random
import ssl
import sys
import time
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, build_opener
from fixtures import NoRedirect, auth as basic_auth, call, form
from protocol_fixtures import ROOT, browser_config, keycloak_client, exchange_fields, signed_token

os.umask(0o077)
peer = sys.argv[1]
config, factory = browser_config(peer)
client = config["clients"]["oidc"]
secret = config["client_secrets"][client]
if peer == "keycloak":
    client, secret = keycloak_client(config["redirect_uri"])
credentials = {"client_id": client, "client_secret": secret}
profile = json.loads((ROOT / f"goose8-{peer}.json").read_bytes())

headers = list(profile.get("headers", {}).items())
if peer != "nazo" and not profile.get("admin_introspection"):
    headers.extend(basic_auth({"id": client, "secret": secret}))

def lane(account):
    browser = factory(peer, account, client, config["redirect_uri"])
    api, issuer, path = browser.discovery()
    doc, _, _ = api.call("GET", path)
    assert doc["issuer"] == issuer
    keys, _, _ = api.call("GET", urlsplit(doc["jwks_uri"]).path)
    opener = build_opener(HTTPSHandler(context=ssl.create_default_context(cafile=profile.get("ca"))), NoRedirect())
    requests = []
    for index in range(16):
        code, verifier = browser.authorization("openid profile", allow_login=index == 0)
        grant, _, _ = browser.exchange(exchange_fields(credentials, browser.redirect, code, verifier))
        _, claims = signed_token(grant["id_token"], keys["keys"])
        assert claims["exp"] > time.time() and claims["iss"] == issuer and claims["nonce"] == browser.last_nonce
        assert client in ([claims["aud"]] if isinstance(claims["aud"], str) else claims["aud"])
        tok = grant["access_token"]
        if peer == "nazo":
            _, access = signed_token(tok, keys["keys"])
            assert access["subject_type"] == "user" and access["sub"] == claims["sub"]
        info, _, _ = api.call("GET", urlsplit(doc["userinfo_endpoint"]).path, headers={"Authorization": "Bearer " + tok})
        assert info["sub"] == claims["sub"]
        fields = {"token": tok, "token_type_hint": "access_token"}
        if peer == "nazo":
            fields.update(credentials)
        req = form("introspect", profile["introspect"], fields, headers)
        status, state = call(opener, req)
        assert status == 200 and state["active"] is True and state["sub"] == info["sub"]
        requests.append(req)
    return info["sub"], requests


with ThreadPoolExecutor(max_workers=4) as pool:
    lanes = list(pool.map(lane, config["users"][:32]))
assert len({sub for sub, _ in lanes}) == 32
requests = [req for _, batch in lanes for req in batch]
assert len(requests) == len({req["body"] for req in requests}) == 512
random.Random(19716).shuffle(requests)
dest = ROOT / "goose8-fixtures"
dest.mkdir(exist_ok=True)
(dest / "introspect.json").write_text(json.dumps(requests))
print(json.dumps(dict(subject_type="user",users=32,tokens=len(requests),all_introspected_active=True)))
