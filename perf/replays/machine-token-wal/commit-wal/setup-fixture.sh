#!/usr/bin/env bash
# Prepare the API-owned fixture on an empty dedicated replay host.
set -euo pipefail
cd "$(dirname "$0")/.."
source <(awk '/^case /{exit} {print}' retest.sh)
test -x commit-wal/out/control
infra
source private/secrets.env
mkdir -p out
cp commit-wal/out/control out/nazoauth-revised
bootstrap_nazo revised
# Keycloak's provisioner takes a client/user blueprint from the NazoAuth API.
docker exec "$prep" cp /tmp/revised.json /tmp/baseline.json
bootstrap_keycloak
bootstrap_hydra
stop_apps
docker stop -t 5 "$wrk" >/dev/null
cp -an bench/. transaction-comparison/bench/
(cd peer-comparison && python3 prepare-peers.py)
(cd commit-wal && python3 prepare-harness.py)
