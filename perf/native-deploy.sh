#!/usr/bin/env bash
R=ghcr.io/sebadob/rauthy@sha256:d733b7580f53c1601c286b5504853b2774e70245f5f9427d9bcda32496b753ee
K=kanidm/server@sha256:77198131f28116203e105d2e42214203757d113a694f35de545669e75db5c96f
net=oidc-bench
exists() { docker inspect "$1" >/dev/null 2>&1; }

if ! test -f private/pg.pass; then openssl rand -hex 32 >private/pg.pass; fi
if ! exists oidc-bench-rauthy-db; then
  pg_image=$(docker inspect --format '{{.Config.Image}}' oidc-bench-postgres)
  mapfile -t cmd < <(docker inspect oidc-bench-postgres | jq -r '.[0].Config.Cmd[]')
  shm=$(docker inspect --format '{{.HostConfig.ShmSize}}' oidc-bench-postgres)
  docker create --name oidc-bench-rauthy-db --shm-size "$shm" --network "$net" --entrypoint /affinity \
    -e POSTGRES_USER=rauthy -e POSTGRES_DB=rauthy -e POSTGRES_PASSWORD="$(cat private/pg.pass)" \
    -v oidc-bench-rauthy-db-data:/var/lib/postgresql "$pg_image" "${cmd[@]}" >/dev/null
  install_tools oidc-bench-rauthy-db
fi
docker start oidc-bench-rauthy-db >/dev/null
if ! exists oidc-bench-rauthy; then
  if [[ ! -s private/rauthy.env ]]; then
    if [[ ! -s private/rauthy-api ]]; then openssl rand -hex 40 >private/rauthy-api; fi
    policy=$(printf '%s' '{"name":"bench","access":[{"group":"Clients","access_rights":["read","create","update"]},{"group":"Secrets","access_rights":["read"]}]}' | base64 -w0)
    cat >private/rauthy.env.tmp <<ENV
HQL_SECRET_RAFT=$(openssl rand -hex 32)
HQL_SECRET_API=$(openssl rand -hex 32)
ENC_KEYS=bench/$(openssl rand -base64 32)
BOOTSTRAP_API_KEY=$policy
BOOTSTRAP_API_KEY_SECRET=$(cat private/rauthy-api)
BOOTSTRAP_ADMIN_PASSWORD_PLAIN=$(openssl rand -hex 32)
PG_PASSWORD=$(cat private/pg.pass)
ENV
    mv private/rauthy.env.tmp private/rauthy.env
  fi
  docker create --name oidc-bench-rauthy --network "$net" --network-alias rauthy.bench.test --entrypoint /affinity \
    --env-file private/rauthy.env -e LOG_LEVEL=warn -e LOG_LEVEL_ACCESS=off -e EVENT_GENERATE_TOKEN_ISSUED=false \
    -e HIQLITE=false -e PG_HOST=oidc-bench-rauthy-db -e PG_USER=rauthy -e PG_DB_NAME=rauthy \
    -e PG_TLS=disable -e PG_MAX_CONN=32 -e HQL_NODE_ID=1 -e ENC_KEY_ACTIVE=bench \
    -e BOOTSTRAP_ADMIN_EMAIL=admin@bench.test \
    -e PUB_URL=rauthy.bench.test:8080 -e LISTEN_SCHEME=http -e RP_ID=rauthy.bench.test \
    -e RP_ORIGIN=http://rauthy.bench.test:8080 \
    "$R" "$BENCH_APP_CPUS" /app/rauthy serve >/dev/null
  install_tools oidc-bench-rauthy
fi
if ! exists oidc-bench-kanidm; then
  bash "$PERF/fixture/tls.sh" private/tls kanidm.bench.test
  cp private/tls/server.pem private/kanidm.crt
  cp private/tls/server.key private/kanidm.key
  cat >private/server.toml <<'CONFIG'
version = "2"
bindaddress = "0.0.0.0:8443"
domain = "kanidm.bench.test"
origin = "https://kanidm.bench.test:8443"
db_path = "/data/kanidm.db"
tls_chain = "/data/kanidm.crt"
tls_key = "/data/kanidm.key"
http_server_versions = "1"
CONFIG
  docker create --name oidc-bench-kanidm --network "$net" --network-alias kanidm.bench.test \
    --entrypoint /affinity -v oidc-bench-kanidm-data:/data "$K" "$BENCH_APP_CPUS" /sbin/kanidmd server -c /data/server.toml >/dev/null
  install_tools oidc-bench-kanidm
  for f in server.toml kanidm.crt kanidm.key; do docker cp "private/$f" "oidc-bench-kanidm:/data/$f"; done
fi
docker start oidc-bench-rauthy oidc-bench-kanidm >/dev/null
for c in "$prep" oidc-bench-goose; do
  docker cp private/tls/ca.pem "$c:/tmp/goose-kanidm-root.pem"
done
docker cp private/tls/ca.pem "$prep:/tmp/extra-ca.pem"
docker cp private/rauthy-api oidc-bench-fixture:/tmp/extra-rauthy-api


python3 - <<'PY'
import json
from pathlib import Path
keys=dict(line.split("=",1) for line in Path("private/rauthy.env").read_text().splitlines())
Path("private/rauthy-admin.json").write_text(json.dumps({"email":"admin@bench.test","password":keys["BOOTSTRAP_ADMIN_PASSWORD_PLAIN"]}))
PY
docker cp private/rauthy-admin.json "$prep:/tmp/goose-rauthy-admin.json"
for peer in rauthy kanidm; do
  saved="private/$peer-client.json"
  if [[ -s $saved ]]; then
    docker cp "$saved" "oidc-bench-fixture:/tmp/extra-$peer-client.json"
  elif [[ $peer == kanidm ]]; then
    for _ in {1..60}; do
      if docker exec oidc-bench-kanidm /sbin/kanidmd recover-account idm_admin -c /data/server.toml >private/kanidm-recovery 2>&1 && grep -q new_password private/kanidm-recovery; then break; fi
      sleep 1
    done
    docker cp private/kanidm-recovery oidc-bench-fixture:/tmp/extra-kanidm-recovery
  fi
  ready=false
  for _ in {1..60}; do
    if docker exec oidc-bench-fixture python3 /tmp/native_client.py "$peer" >"results/$peer-proof.json" 2>"private/$peer-setup.err"; then ready=true; break; fi
    sleep 1
  done
  [[ $ready == true ]] || { tail -2 "private/$peer-setup.err" >&2; exit 1; }
  docker cp "oidc-bench-fixture:/tmp/extra-$peer-client.json" "$saved"
done
docker stop -t 15 oidc-bench-rauthy oidc-bench-kanidm >/dev/null
