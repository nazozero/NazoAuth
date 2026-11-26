"""Prepare user-token introspection through real OAuth and validate the token kind."""
from concurrent.futures import ThreadPoolExecutor
import os
import random
from urllib.parse import urlencode
from protocol_fixtures import Browser, ROOT, exchange_fields, json, signed_token, verify_grant

os.umask(0o077)
config = json.loads((ROOT / "nazo.json").read_bytes())
client = config["clients"]["oidc"]
auth = {"client_id": client, "client_secret": config["client_secrets"][client]}
def lane(user):
    browser = Browser("nazo", user, client, config["redirect_uri"])
    api, _, discovery_path = browser.discovery()
    discovery, _, _ = api.call("GET", discovery_path)
    from urllib.parse import urlsplit
    jwks, _, _ = api.call("GET", urlsplit(discovery["jwks_uri"]).path)
    path = urlsplit(discovery["introspection_endpoint"]).path
    requests = []
    for _ in range(16):
        code, verifier = browser.authorization("openid profile")
        grant, _, _ = browser.exchange(exchange_fields(auth, browser.redirect, code, verifier))
        token = grant["access_token"]
        _, claims = signed_token(token, jwks["keys"])
        assert claims["subject_type"] == "user"
        fields = dict(auth, token=token, token_type_hint="access_token")
        state, _, _ = api.form("POST", path, fields)
        assert state["active"] is True and state["sub"] == claims["sub"]
        requests.append({"operation": "introspect", "method": "POST", "url": f"http://{browser.host}:8080{path}",
                         "headers": [("Host", "localhost:8080"), ("Content-Type", "application/x-www-form-urlencoded")],
                         "body": urlencode(fields)})
    return requests
with ThreadPoolExecutor(max_workers=16) as pool:
    requests = [request for cohort in pool.map(lane, config["users"][:32]) for request in cohort]
assert len(requests) == len({request["body"] for request in requests}) == 512
random.Random(19716).shuffle(requests)
(ROOT / "goose8-fixtures").mkdir(exist_ok=True)
(ROOT / "goose8-fixtures/introspect.json").write_text(json.dumps(requests))
print(json.dumps({"subject_type":"user","users":32,"tokens":len(requests),"all_introspected_active":True}))
