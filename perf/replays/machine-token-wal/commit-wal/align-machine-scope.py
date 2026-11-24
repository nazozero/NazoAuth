"""Match the dedicated Keycloak machine client's granted scope to the other peers."""
import json
from pathlib import Path
from urllib.parse import quote

from api import Api

api = Api("oauthbench-kc-flow")
client = json.loads(Path("/tmp/keycloak.json").read_text())["clients"]["machine"]
bootstrap = json.loads(Path("/tmp/commit-kc-bootstrap.json").read_text())
auth, _, _ = api.form("POST", "/realms/master/protocol/openid-connect/token", {
    "grant_type": "client_credentials", "client_id": bootstrap["client_id"],
    "client_secret": bootstrap["secret"],
})
headers = {"Authorization": "Bearer " + auth["access_token"]}
base = "/admin/realms/api-audit/clients"
clients, _, _ = api.call("GET", base + "?clientId=" + quote(client), headers=headers)
internal, = [c["id"] for c in clients if c["clientId"] == client]
path = f"{base}/{internal}/default-client-scopes"
scopes, _, _ = api.call("GET", path, headers=headers)
for scope in scopes:
    if scope["name"] == "email":
        api.call("DELETE", path + "/" + scope["id"], expected=(204,), headers=headers)
