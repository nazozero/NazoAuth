"""Read event storage settings using the existing benchmark realm's admin API."""

import json
from pathlib import Path
from api import Api

api = Api("oauthbench-kc-flow")
bootstrap = json.loads(Path("/tmp/commit-kc-bootstrap.json").read_text())
credential, _, _ = api.form(
    "POST",
    "/realms/master/protocol/openid-connect/token",
    {
        "grant_type": "client_credentials",
        "client_id": bootstrap["client_id"],
        "client_secret": bootstrap["secret"],
    },
)
headers = {"Authorization": "Bearer " + credential["access_token"]}
config, _, _ = api.call("GET", "/admin/realms/api-audit/events/config", headers=headers)
print(
    json.dumps(
        {
            k: config.get(k)
            for k in (
                "eventsEnabled",
                "adminEventsEnabled",
                "eventsListeners",
                "enabledEventTypes",
            )
        }
    )
)
