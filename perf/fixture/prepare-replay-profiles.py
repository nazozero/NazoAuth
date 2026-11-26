"""Use the existing machine-token replay's provisioned identities for protocol preflight."""
import json
import os
from pathlib import Path
import sys
import ssl
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


peer = sys.argv[1]
root = Path("/tmp")
specs = {
    "nazo": ("http://oidc-bench-nazo:8080", "/token", "/introspect", "/jwks.json"),
    "keycloak": ("http://oidc-bench-keycloak:8080", "/realms/api-audit/protocol/openid-connect/token",
                 "/realms/api-audit/protocol/openid-connect/token/introspect",
                 "/realms/api-audit/protocol/openid-connect/certs"),
    "hydra": ("http://oidc-bench-hydra:8080", "/oauth2/token",
              "http://oidc-bench-hydra:8081/admin/oauth2/introspect", "/.well-known/jwks.json"),
    "rauthy": ("http://rauthy.bench.test:8080", "/auth/v1/oidc/token", "/auth/v1/oidc/introspect",
               "/auth/v1/oidc/jwks"),
    "kanidm": ("https://kanidm.bench.test:8443", "/oauth2/token", "/oauth2/token/introspect", None),
}
origin, token, introspect, jwks = specs[peer]
if peer in ("rauthy", "kanidm"):
    client_id = "benchmachine"
    secret = json.loads((root / f"extra-{peer}-client.json").read_text())
else:
    state = json.loads((root / ("nazo.json" if peer == "nazo" else f"{peer}.json")).read_text())
    client_id = state["clients"].get("machine_basic") or state["clients"]["machine"]
    secret = state["client_secrets"][client_id]

discovery = {
    "nazo": "/.well-known/openid-configuration",
    "keycloak": "/realms/api-audit/.well-known/openid-configuration",
    "hydra": "/.well-known/openid-configuration",
    "rauthy": "/auth/v1/.well-known/openid-configuration",
    "kanidm": f"/oauth2/openid/{client_id}/.well-known/openid-configuration",
}[peer]
context = ssl.create_default_context(cafile="/tmp/goose-kanidm-root.pem" if peer == "kanidm" else None)
headers = {"Host": "localhost:8080"} if peer in ("nazo", "keycloak", "hydra") else {}
with urlopen(Request(origin + discovery, headers=headers), context=context, timeout=4) as response:
    metadata = json.load(response)
token = urlsplit(metadata.get("token_endpoint", token)).path
if peer != "hydra":
    introspect = urlsplit(metadata.get("introspection_endpoint", introspect)).path
if jwks:
    jwks = urlsplit(metadata.get("jwks_uri", jwks)).path
capabilities = {key: value for key, value in metadata.items() if key.endswith("_supported")}
for key in ("token_endpoint", "introspection_endpoint", "revocation_endpoint", "userinfo_endpoint",
            "registration_endpoint", "end_session_endpoint", "pushed_authorization_request_endpoint",
            "device_authorization_endpoint", "backchannel_authentication_endpoint"):
    capabilities[key] = key in metadata
print(json.dumps(capabilities, indent=2))

profile = {
    "token": origin + token,
    "introspect": introspect if "://" in introspect else origin + introspect,
    "scope": "profile",
    "jwks": origin + jwks if jwks else None,
    "clients": [{"id": client_id, "secret": secret}],
    "headers": headers,
    "token_auth": "form" if peer == "rauthy" else "basic",
    "admin_introspection": peer == "hydra",
    "ca": "/tmp/goose-kanidm-root.pem" if peer == "kanidm" else None,
}
os.umask(0o077)
(root / "goose-profile.json").write_text(json.dumps(profile))
