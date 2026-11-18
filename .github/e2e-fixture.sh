#!/usr/bin/env bash
set -euo pipefail

configure() {
  mkdir -p runtime/e2e/avatars runtime/e2e/secrets runtime/e2e/bootstrap runtime/e2e/instance runtime/e2e/runtime-primary runtime/e2e/runtime-signed
  cp .github/e2e-runtime.yml runtime/e2e/.env.yaml
  mfa_totp_key="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')"
  signing_key="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')"
  {
    echo 'MFA_TOTP_ENCRYPTION_KEY_ID: "e2e-ephemeral-v1"'
    printf 'MFA_TOTP_ENCRYPTION_KEY: "%s"\n' "$mfa_totp_key"
    echo 'SIGNING_KEY_ENCRYPTION_KEY_ID: "e2e-signing-root"'
    printf 'SIGNING_KEY_ENCRYPTION_KEY: "%s"\n' "$signing_key"
  } >> runtime/e2e/.env.yaml
  cp runtime/e2e/.env.yaml runtime/e2e/.env-signed.yaml
  sed -i 's/RUNTIME_INSTANCE_ID: "e2e-primary"/RUNTIME_INSTANCE_ID: "e2e-signed"/' runtime/e2e/.env-signed.yaml
}

start_dependencies() {
  docker network create nazo-oauth-e2e-net
  docker run -d --name nazo-oauth-e2e-postgres --network nazo-oauth-e2e-net \
    -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=oauth "$POSTGRES_IMAGE"
  docker run -d --name nazo-oauth-e2e-valkey --network nazo-oauth-e2e-net "$VALKEY_IMAGE"
  ready=false
  for _ in $(seq 1 60); do
    if docker run --rm --network nazo-oauth-e2e-net -e PGPASSWORD=postgres "$POSTGRES_IMAGE" \
      sh -lc 'pg_isready -h nazo-oauth-e2e-postgres -U postgres -d oauth && psql -h nazo-oauth-e2e-postgres -U postgres -d oauth -c "select 1" >/dev/null'
    then
      ready=true
      break
    fi
    sleep 2
  done
  [ "$ready" = "true" ]
}

start_server() {
  app_password="$(openssl rand -hex 24)"
  docker exec nazo-oauth-e2e-postgres psql -U postgres -d oauth -v ON_ERROR_STOP=1 \
    -c "CREATE ROLE nazoauth_e2e_app LOGIN PASSWORD '$app_password' NOSUPERUSER NOBYPASSRLS NOINHERIT"
  docker exec -i nazo-oauth-e2e-postgres psql -U postgres -d oauth -v ON_ERROR_STOP=1 <<'SQL'
REVOKE ALL ON DATABASE oauth FROM PUBLIC;
GRANT CONNECT ON DATABASE oauth TO postgres, nazoauth_e2e_app;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
SQL
  docker run --rm --name nazo-oauth-e2e-migrate --network nazo-oauth-e2e-net \
    --user "$(id -u):$(id -g)" \
    --cap-drop ALL --security-opt no-new-privileges --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
    -e NAZOAUTH_MIGRATION_RUNTIME_ROLE=nazoauth_e2e_app \
    -v "$PWD/runtime/e2e/.env.yaml:/app/.env.yaml:ro" \
    -v "$PWD/runtime/e2e/secrets:/var/lib/nazo_oauth/secrets" \
    nazo-oauth-e2e:latest nazoauth migrate
  docker run --rm --name nazo-oauth-e2e-tenant-bootstrap --network nazo-oauth-e2e-net \
    --user "$(id -u):$(id -g)" \
    --cap-drop ALL --security-opt no-new-privileges --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
    -v "$PWD/runtime/e2e/.env.yaml:/app/.env.yaml:ro" \
    -v "$PWD/runtime/e2e/secrets:/var/lib/nazo_oauth/secrets" \
    nazo-oauth-e2e:latest nazoauth tenant-bootstrap
  docker exec -i nazo-oauth-e2e-postgres psql -U postgres -d oauth -v ON_ERROR_STOP=1 <<'SQL'
WITH changed AS (
    UPDATE runtime_module_desired_states
    SET desired_mode = 'enabled',
        revision = revision + 1,
        reason = 'RFC 9967 CI fixture',
        updated_at = CURRENT_TIMESTAMP
    WHERE tenant_id = '00000000-0000-0000-0000-000000000001'
      AND module_id = 'scim_security_events'
      AND desired_mode = 'disabled'
    RETURNING tenant_id, module_id, revision, actor_id, reason, updated_at
)
INSERT INTO runtime_module_state_events (
    event_id, tenant_id, module_id, event_type, revision, instance_id, actor_id,
    reason, before_state, after_state, outcome_code, occurred_at
)
SELECT
    uuidv7(), tenant_id, module_id, 'desired_state_changed', revision, NULL, actor_id,
    reason, 'disabled', 'enabled', NULL, updated_at
FROM changed;
SQL
  test "$(
    docker exec -e PGPASSWORD="$app_password" nazo-oauth-e2e-postgres \
      psql -h 127.0.0.1 -U nazoauth_e2e_app -d oauth -At -v ON_ERROR_STOP=1 \
      -c 'SELECT policy_satisfied FROM public.nazo_security_audit_shared_privilege_preflight(true, true, false)'
  )" = "t"
  sed -i \
    "s#postgresql://postgres:postgres@#postgresql://nazoauth_e2e_app:${app_password}@#" \
    runtime/e2e/.env.yaml runtime/e2e/.env-signed.yaml
  docker run -d --name nazo-oauth-e2e-server --network nazo-oauth-e2e-net \
    --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges \
    -e NAZO_RUNTIME_INSTANCE_ID=e2e-primary \
    -v "$PWD/runtime/e2e/.env.yaml:/app/.env.yaml:ro" \
    -v "$PWD/runtime/e2e/secrets:/var/lib/nazo_oauth/secrets" \
    -v "$PWD/runtime/e2e/bootstrap:/var/lib/nazo_oauth/bootstrap" \
    -v "$PWD/runtime/e2e/avatars:/var/lib/nazo_oauth/tenants/00000000-0000-0000-0000-000000000001/avatars" \
    -v "$PWD/runtime/e2e/instance:/var/lib/nazo_oauth/instance" \
    -v "$PWD/runtime/e2e/runtime-primary:/var/lib/nazo_oauth/runtime-instance" \
    nazo-oauth-e2e:latest nazoauth server
  docker run -d --name nazo-oauth-e2e-server-signed --network nazo-oauth-e2e-net \
    --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges \
    -e NAZO_RUNTIME_INSTANCE_ID=e2e-signed \
    -v "$PWD/runtime/e2e/.env-signed.yaml:/app/.env.yaml:ro" \
    -v "$PWD/runtime/e2e/secrets:/var/lib/nazo_oauth/secrets" \
    -v "$PWD/runtime/e2e/bootstrap:/var/lib/nazo_oauth/bootstrap" \
    -v "$PWD/runtime/e2e/avatars:/var/lib/nazo_oauth/tenants/00000000-0000-0000-0000-000000000001/avatars" \
    -v "$PWD/runtime/e2e/instance:/var/lib/nazo_oauth/instance" \
    -v "$PWD/runtime/e2e/runtime-signed:/var/lib/nazo_oauth/runtime-instance" \
    nazo-oauth-e2e:latest nazoauth server
}

wait_for_servers() {
  ready=false
  for _ in $(seq 1 60); do
    if docker run --rm --network nazo-oauth-e2e-net \
      nazo-oauth-e2e-runner:latest python -c \
      'import urllib.request; headers={"Host":"127.0.0.1:8000"}; urllib.request.urlopen(urllib.request.Request("http://nazo-oauth-e2e-server:8000/health", headers=headers), timeout=2).read(); urllib.request.urlopen(urllib.request.Request("http://nazo-oauth-e2e-server-signed:8000/health", headers=headers), timeout=2).read()'
    then
      ready=true
      break
    fi
    sleep 2
  done
  if [ "$ready" != "true" ]; then
    docker inspect nazo-oauth-e2e-server nazo-oauth-e2e-server-signed
    docker logs nazo-oauth-e2e-server || true
    docker logs nazo-oauth-e2e-server-signed || true
    exit 1
  fi
}

cleanup() {
  docker rm -f nazo-oauth-rfc9967-runner nazo-oauth-e2e-runner nazo-oauth-e2e-server nazo-oauth-e2e-server-signed nazo-oauth-e2e-postgres nazo-oauth-e2e-valkey 2>/dev/null || true
  docker network rm nazo-oauth-e2e-net 2>/dev/null || true
}

case "${1:-}" in
  configure) configure ;;
  start-dependencies) start_dependencies ;;
  start-server) start_server ;;
  wait-for-servers) wait_for_servers ;;
  cleanup) cleanup ;;
  *) echo "Usage: $0 {configure|start-dependencies|start-server|wait-for-servers|cleanup}" >&2; exit 2 ;;
esac
