#!/usr/bin/env bash
# Sourced by bench.sh after selecting the CPU topology.
net=oidc-bench
pg=oidc-bench-postgres
vk=oidc-bench-valkey
prep=oidc-bench-fixture
kc=oidc-bench-keycloak
hy=oidc-bench-hydra
pg_image=postgres@sha256:0115267ab5a509022df9319c77be365cef335adb71556c75f60f5360ee247e71
vk_image=valkey/valkey@sha256:bf09d58e96d6b4524a15396b65b242bbe18beebbcc15a04d8ee75ddac62fae0b
kc_image=quay.io/keycloak/keycloak@sha256:7e66a96e4739239070aeaf72e4c5decf0f7f682cfc725b9f7ea2b336eaba38b3
hy_image=oryd/hydra@sha256:ff67c7fb5f95074fa53374d41151713554960504b340cd3f95b09e65deaea2a9
app_image=oidc-bench-app
fixture_image=oidc-bench-tools
install_tools() {
  docker cp "$WORK/build/affinity" "$1:/affinity"
  docker cp "$WORK/build/sample-cpu" "$1:/sample-cpu"
}
stop_apps() {
  for c in oidc-bench-nazo "$kc" "$hy" oidc-bench-rauthy oidc-bench-kanidm; do
    if [[ $(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null || :) == true ]]; then
      docker stop -t 8 "$c" >/dev/null
    fi
  done
}
ready() {
  local host=$1 path=$2 attempt
  for ((attempt=0;attempt<100;attempt++)); do
    [[ $(docker inspect -f '{{.State.Running}}' "$host") == true ]] || break
    if docker exec "$prep" /affinity "$BENCH_CONTROL_CPU" python3 -c \
      'from http.client import HTTPConnection; import sys; c=HTTPConnection(sys.argv[1],8080,timeout=2); c.request("GET",sys.argv[2],headers={"Host":"localhost:8080"}); assert c.getresponse().status==200' \
      "$host" "$path" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  docker logs --tail 18 "$host" >&2
  return 1
}
generate_secrets() {
  if [[ -e private/secrets.env ]]; then return 0; fi
  for key in pg_password nazo_password keycloak_password hydra_password kc_secret hydra_secret pepper admin_password; do
    printf '%s=%s\n' "$key" "$(openssl rand -hex 24)"
  done >private/secrets.env
  printf 'signing_key=%s\n' "$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')" >>private/secrets.env
}
init_db_role() {
  local role=$1 password=$2
  # Database roles are infrastructure. Product data enters only through product CLI and HTTP APIs.
  docker exec -i "$pg" psql -v ON_ERROR_STOP=1 -U postgres -d postgres \
    -v role="$role" -v password="$password" <<'SQL' >/dev/null
SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD %L', :'role', :'password')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname=:'role') \gexec
SQL
}
infra() {
  generate_secrets
  source private/secrets.env
  docker network inspect "$net" >/dev/null 2>&1 || docker network create "$net" >/dev/null
  if ! docker container inspect "$pg" >/dev/null 2>&1; then
    docker create --name "$pg" --network "$net" --shm-size 2g --entrypoint /affinity \
      -e POSTGRES_PASSWORD="$pg_password" "$pg_image" "$BENCH_PG_CPUS" \
      /usr/local/bin/docker-entrypoint.sh postgres -c max_connections=128 -c shared_buffers=1GB \
      -c max_wal_size=8GB -c checkpoint_timeout=5min -c checkpoint_completion_target=0.9 >/dev/null
    install_tools "$pg"
    docker start "$pg" >/dev/null
    for ((i=0;i<60;i++)); do
      if docker exec "$pg" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1; then break; fi
      sleep 1
    done
    docker exec "$pg" pg_isready -h 127.0.0.1 -U postgres
    init_db_role nazoauth "$nazo_password"
    docker exec "$pg" createdb -U postgres nazo_ready
    for role in keycloak hydra; do
      variable="${role}_password"
      init_db_role "$role" "${!variable}"
      docker exec "$pg" createdb -U postgres -O "$role" "${role}_retest"
    done
  fi
  if ! docker container inspect "$vk" >/dev/null 2>&1; then
    docker create --name "$vk" --network "$net" --entrypoint /affinity "$vk_image" \
      "$BENCH_VK_CPUS" /usr/local/bin/docker-entrypoint.sh valkey-server --save '' --appendonly no >/dev/null
    install_tools "$vk"
    docker start "$vk" >/dev/null
  fi
  if ! docker container inspect oidc-bench-goose >/dev/null 2>&1; then
    local network_args=()
    if [[ ${BENCH_NETWORK:-base} == wide ]]; then
      network_args=(--sysctl 'net.ipv4.ip_local_port_range=1024 65535' --sysctl net.ipv4.tcp_tw_reuse=1)
    fi
    docker create --name oidc-bench-goose "${network_args[@]}" --network "$net" --entrypoint /affinity oidc-bench-goose-image "$BENCH_CONTROL_CPU" sleep infinity >/dev/null
    install_tools oidc-bench-goose
  fi
  docker start oidc-bench-goose >/dev/null
  if ! docker container inspect "$prep" >/dev/null 2>&1; then
    docker create --name "$prep" --network container:oidc-bench-goose --entrypoint /affinity "$fixture_image" "$BENCH_CONTROL_CPU" sleep infinity >/dev/null
    install_tools "$prep"
  fi
  docker start "$prep" >/dev/null
}
product_config() {
  local db=nazo_ready vk_db=2 epoch=019c8ca2-30a6-7000-8000-00000000e102
  cat >"private/nazo.env" <<EOF
BIND=0.0.0.0:8080
DATA_DIR=/var/lib/nazo_oauth
DEPLOYMENT_ID=oidc-benchmark
ISSUER=http://localhost:8080
PUBLIC_BASE_URL=http://localhost:8080
DATABASE_URL=postgresql://nazoauth:$nazo_password@$pg:5432/$db
DATABASE_MAX_CONNECTIONS=32
OAUTH_TOKEN_IP_RATE_LIMIT_ENABLED=false
VALKEY_URL=redis://$vk:6379/$vk_db
VALKEY_STATE_EPOCH=$epoch
CLIENT_SECRET_PEPPER=$pepper
SIGNING_KEY_ENCRYPTION_KEY_ID=benchmark-key
SIGNING_KEY_ENCRYPTION_KEY=$signing_key
TRANSPORT_MODE=trusted-proxy
TRUSTED_PROXY_CIDRS=172.16.0.0/12
CLIENT_IP_HEADER_MODE=x-forwarded-for
MTLS_CERTIFICATE_SOURCE=rfc9440
COOKIE_SECURE=false
AVATAR_OBJECT_STORE=local
AUTHORIZATION_SERVER_PROFILE=oauth2-baseline
AUDIT_ANCHOR_MODE=disabled
SECURITY_AUDIT_REQUIRE_LEAST_PRIVILEGE=true
AUTH_RATE_LIMIT_MAX_REQUESTS=1000000000
TOKEN_RATE_LIMIT_MAX_REQUESTS=1000000000
TOKEN_MANAGEMENT_RATE_LIMIT_MAX_REQUESTS=1000000000
ACCESS_TOKEN_TTL_SECONDS=300
RUST_LOG=warn
EOF
  printf '{"schema":1,"email":"perf-admin@example.test","password":"%s"}\n' "$admin_password" >private/admin.json
}
bootstrap_nazo() {
  local name=oidc-bench-nazo url init volume
  init="oidc-bench-init"
  url="postgresql://postgres:$pg_password@$pg:5432/nazo_ready"
  volume=oidc-bench-data
  docker volume inspect "$volume" >/dev/null 2>&1 || docker volume create "$volume" >/dev/null
  product_config
  if ! docker container inspect "$name" >/dev/null 2>&1; then
    docker create --name "$name" --network "$net" -v "$volume:/var/lib/nazo_oauth" \
      --log-opt max-size=16m --log-opt max-file=2 --env-file "private/nazo.env" \
      --entrypoint /affinity "$app_image" "$BENCH_APP_CPUS" /usr/local/bin/nazoauth server >/dev/null
    install_tools "$name"
    docker cp "out/nazoauth" "$name:/usr/local/bin/nazoauth"
  fi
  if [[ ! -e "results/nazo-fixtures.json" ]]; then
    if ! docker container inspect "$init" >/dev/null 2>&1; then
      docker create --name "$init" --network "$net" --env-file "private/nazo.env" -v "$volume:/var/lib/nazo_oauth" \
        --entrypoint /affinity "$app_image" "$BENCH_CONTROL_CPU" sleep infinity >/dev/null
      install_tools "$init"
      docker cp "out/nazoauth" "$init:/usr/local/bin/nazoauth"
      docker start "$init" >/dev/null
    fi
    docker cp private/admin.json "$init:/admin.json"
    docker exec -e DATABASE_URL="$url" -e NAZOAUTH_MIGRATION_RUNTIME_ROLE=nazoauth "$init" \
      /affinity "$BENCH_CONTROL_CPU" /usr/local/bin/nazoauth migrate
    docker exec -e DATABASE_URL="$url" "$init" /affinity "$BENCH_CONTROL_CPU" /usr/local/bin/nazoauth tenant-bootstrap
    docker exec -e NAZOAUTH_ADMIN_PROVISION_FILE=/admin.json \
      -e NAZOAUTH_ADMIN_PROVISION_OPERATION_ID=hotpath-admin \
      -e NAZOAUTH_ADMIN_PROVISION_DEPLOYMENT_ID="oidc-benchmark" "$init" \
      /affinity "$BENCH_CONTROL_CPU" /usr/local/bin/nazoauth admin-provision >private/admin-receipt.json
    docker rm -f "$init" >/dev/null
    stop_apps
    docker start "$vk" "$name" >/dev/null
    ready "$name" /health
    docker cp private/admin.json "$prep:/tmp/api-bench-admin.json"
    docker exec "$prep" /affinity "$BENCH_CONTROL_CPU" python3 /tmp/provision.py
    docker exec "$prep" cp /tmp/state.json "/tmp/nazo.json"
    docker cp "$prep:/tmp/provenance.json" "results/nazo-fixtures.json"
    docker stop -t 8 "$name" >/dev/null
  fi
}
bootstrap_keycloak() {
  if [[ -e results/keycloak-fixtures.json ]]; then return 0; fi
  stop_apps
  docker stop -t 4 "$vk" >/dev/null
  if ! docker container inspect "$kc" >/dev/null 2>&1; then
    docker create --name "$kc" --network "$net" --entrypoint /affinity \
      -e KC_DB=postgres -e "KC_DB_URL=jdbc:postgresql://$pg:5432/keycloak_retest" \
      -e KC_DB_USERNAME=keycloak -e "KC_DB_PASSWORD=$keycloak_password" \
      -e KC_DB_POOL_MAX_SIZE=32 -e KC_BOOTSTRAP_ADMIN_CLIENT_ID=perf-bootstrap \
      -e "KC_BOOTSTRAP_ADMIN_CLIENT_SECRET=$kc_secret" \
      -e JAVA_OPTS_KC_HEAP='-Xms512m -Xmx4g' -e JAVA_OPTS_APPEND='-XX:ActiveProcessorCount=16' \
      "$kc_image" "$BENCH_APP_CPUS" /opt/keycloak/bin/kc.sh start --http-enabled=true --http-port=8080 \
      --hostname=http://localhost:8080 >/dev/null
    install_tools "$kc"
  fi
  docker start "$kc" >/dev/null
  ready "$kc" /realms/master/.well-known/openid-configuration
  printf '{"client_id":"perf-bootstrap","secret":"%s"}\n' "$kc_secret" >private/keycloak.json
  docker cp private/keycloak.json "$prep:/tmp/peer-bootstrap.json"
  docker exec "$prep" cp /tmp/nazo.json /tmp/state.json
  docker exec "$prep" /affinity "$BENCH_CONTROL_CPU" python3 /tmp/provision-peer.py keycloak >results/keycloak-fixtures.json.tmp
  docker exec "$prep" cp /tmp/peer-state.json /tmp/keycloak.json
  docker exec "$prep" cp /tmp/keycloak.json /tmp/state.json
  mv results/keycloak-fixtures.json.tmp results/keycloak-fixtures.json
  docker stop -t 8 "$kc" >/dev/null
}
bootstrap_hydra() {
  if [[ -e results/hydra-fixtures.json ]]; then return 0; fi
  stop_apps
  docker stop -t 4 "$vk" >/dev/null
  local dsn="postgresql://hydra:$hydra_password@$pg:5432/hydra_retest?sslmode=disable&max_conns=32&max_idle_conns=32"
  if ! docker container inspect "$hy" >/dev/null 2>&1; then
    docker run --rm --network "$net" -e DSN="$dsn" "$hy_image" migrate sql up -e --yes
    docker create --name "$hy" --network "$net" --entrypoint /affinity \
      -e DSN="$dsn" -e SECRETS_SYSTEM="$hydra_secret" \
      -e URLS_SELF_ISSUER=http://localhost:8080 \
      -e URLS_LOGIN=https://fixture.example.test/login \
      -e URLS_CONSENT=https://fixture.example.test/consent \
      -e URLS_LOGOUT=https://fixture.example.test/logout \
      -e SERVE_PUBLIC_PORT=8080 -e SERVE_ADMIN_PORT=8081 \
      -e STRATEGIES_ACCESS_TOKEN=jwt -e TTL_ACCESS_TOKEN=5m -e LOG_LEVEL=warn \
      "$hy_image" "$BENCH_APP_CPUS" hydra serve all --dev >/dev/null
    install_tools "$hy"
  fi
  docker start "$hy" >/dev/null
  ready "$hy" /.well-known/openid-configuration
  docker exec "$prep" cp /tmp/nazo.json /tmp/state.json
  docker exec "$prep" /affinity "$BENCH_CONTROL_CPU" python3 /tmp/provision-peer.py hydra >results/hydra-fixtures.json.tmp
  docker exec "$prep" cp /tmp/peer-state.json /tmp/hydra.json
  docker exec "$prep" cp /tmp/hydra.json /tmp/state.json
  docker exec "$prep" python3 /tmp/hydra_signing.py
  mv results/hydra-fixtures.json.tmp results/hydra-fixtures.json
  docker stop -t 8 "$hy" >/dev/null
}
