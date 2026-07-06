#!/usr/bin/env sh
set -eu

if [ "${CNB_CAPACITY_SKIP_BOOTSTRAP:-0}" != "1" ]; then
  . ./perf/cnb_bootstrap.sh
  install_capacity_dependencies
  docker compose version >/dev/null
fi

rates="${HYDRA_APP_CPU_RATES:-1000,2000}"
duration="${HYDRA_APP_CPU_DURATION:-2m}"
app_cpus="${HYDRA_APP_CPUS:-1}"
app_taskset="${HYDRA_APP_TASKSET:-}"
suffix="${HYDRA_APP_CPU_SUFFIX:-hydra-app-cpu-${app_cpus}core-smoke}"
hydra_image_tag="${HYDRA_IMAGE_TAG:-v26.2.0}"
public_host_port="${HYDRA_PUBLIC_HOST_PORT:-18082}"
admin_host_port="${HYDRA_ADMIN_HOST_PORT:-18083}"
report="docs/performance-hydra-comparison-${suffix}.md"
results="perf/results/${suffix}.json"
nazoauth_results="${NAZOAUTH_APP_CPU_RESULTS:-perf/results/capacity-app-cpu-1core-smoke.json}"

mkdir -p docs perf/results

project="$(printf 'nazoauth-%s-%s' "${CNB_BUILD_ID:-local}" "${suffix}" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9_-' '-' | cut -c1-63)"
override="perf/results/docker-compose.${suffix}.yml"

cat >"${override}" <<EOF
services:
  hydra:
    cpus: "${app_cpus}"
EOF

if [ -n "${app_taskset}" ]; then
  cat >>"${override}" <<EOF
    build:
      context: .
      dockerfile: perf/hydra/Containerfile.taskset
      args:
        HYDRA_IMAGE_TAG: "${hydra_image_tag}"
    image: nazoauth-hydra-taskset:${hydra_image_tag}
    entrypoint: ["/usr/local/bin/taskset", "-c", "${app_taskset}", "hydra"]
EOF
fi

compose() {
  COMPOSE_PROJECT_NAME="${project}" HYDRA_IMAGE_TAG="${hydra_image_tag}" HYDRA_PUBLIC_HOST_PORT="${public_host_port}" HYDRA_ADMIN_HOST_PORT="${admin_host_port}" \
    docker compose -p "${project}" -f docker-compose.hydra.perf.yml -f "${override}" "$@"
}

wait_for_hydra() {
  python3 - "$public_host_port" <<'PY'
import sys
import time
import urllib.request

port = sys.argv[1]
url = f"http://127.0.0.1:{port}/.well-known/openid-configuration"
deadline = time.time() + 180
last_error = None
while time.time() < deadline:
    try:
        with urllib.request.urlopen(url, timeout=3) as response:
            if response.status == 200:
                print("hydra ready")
                raise SystemExit
    except Exception as exc:
        last_error = exc
        time.sleep(2)
raise RuntimeError(f"Hydra did not become ready: {last_error}")
PY
}

create_hydra_client() {
  docker run --rm \
    --network "${project}_hydra_net" \
    "docker.io/oryd/hydra:${hydra_image_tag}" \
    create oauth2-client \
    --endpoint "http://hydra:4445/" \
    --id "perf-client-credentials" \
    --secret "perf-client-secret" \
    --grant-type "client_credentials" \
    --response-type "token" \
    --scope "profile" \
    --token-endpoint-auth-method "client_secret_post" \
    --access-token-strategy "jwt" \
    --format "json" >/dev/null
}

sample_stats() {
  stats_file="$1"
  while :; do
    ids="$(compose ps -q hydra hydra-postgres 2>/dev/null | tr '\n' ' ')"
    if [ -n "${ids}" ]; then
      # shellcheck disable=SC2086
      docker stats --no-stream --format '{{json .}}' ${ids} >>"${stats_file}" 2>/dev/null || true
    fi
    sleep 2
  done
}

run_point() {
  rate="$1"
  summary="perf/results/${suffix}-${rate}.summary.json"
  stats="perf/results/${suffix}-${rate}.docker-stats.ndjson"
  : >"${stats}"

  echo "hydra app-cpu smoke: rate=${rate}/s duration=${duration} app_cpus=${app_cpus} app_taskset=${app_taskset:-disabled}"
  compose down -v --remove-orphans >/dev/null 2>&1 || true
  compose up -d
  wait_for_hydra
  create_hydra_client

  sample_stats "${stats}" &
  sampler_pid="$!"
  set +e
  docker run --rm \
    --user "$(id -u):$(id -g)" \
    --network "${project}_hydra_net" \
    -v "$PWD/perf/oauth_competitor:/scripts:ro" \
    -v "$PWD/perf/results:/results" \
    -e BASE_URL="http://hydra:4444" \
    -e TOKEN_PATH="/oauth2/token" \
    -e OAUTH_CLIENT_ID="perf-client-credentials" \
    -e OAUTH_CLIENT_SECRET="perf-client-secret" \
    -e OAUTH_SCOPE="profile" \
    -e PERF_RATE="${rate}" \
    -e PERF_DURATION="${duration}" \
    -e PERF_PRE_ALLOCATED_VUS="${HYDRA_APP_CPU_PRE_ALLOCATED_VUS:-512}" \
    -e PERF_MAX_VUS="${HYDRA_APP_CPU_MAX_VUS:-512}" \
    "docker.io/grafana/k6:${K6_IMAGE_TAG:-2.1.0}" \
    run --summary-export "/results/${suffix}-${rate}.summary.json" /scripts/client_credentials.js
  status="$?"
  set -e
  kill "${sampler_pid}" >/dev/null 2>&1 || true
  wait "${sampler_pid}" 2>/dev/null || true
  compose down -v --remove-orphans
  if [ "${status}" -ne 0 ]; then
    echo "Hydra k6 point reported a non-zero result: rate=${rate}/s status=${status}; keeping summary and continuing" >&2
  fi
  if [ ! -f "${summary}" ]; then
    echo "Hydra k6 summary missing after rate=${rate}/s; cannot continue" >&2
    exit "${status}"
  fi
}

old_ifs="${IFS}"
IFS=","
for rate in ${rates}; do
  IFS="${old_ifs}"
  run_point "${rate}"
  IFS=","
done
IFS="${old_ifs}"

python3 perf/oauth_competitor_app_cpu_compare.py \
  --summary-dir perf/results \
  --results-path "${results}" \
  --report-path "${report}" \
  --nazoauth-results "${nazoauth_results}" \
  --suffix "${suffix}" \
  --duration "${duration}" \
  --rates "${rates}" \
  --app-cpus "${app_cpus}" \
  --app-taskset "${app_taskset:-disabled}" \
  --provider-name "Ory Hydra" \
  --provider-key "hydra" \
  --provider-image "docker.io/oryd/hydra:${hydra_image_tag}" \
  --provider-service "hydra" \
  --postgres-service "hydra-postgres" \
  --compose-file "docker-compose.hydra.perf.yml" \
  --token-path "/oauth2/token" \
  --scope "profile"

if [ "${HYDRA_APP_CPU_COMMIT:-0}" = "1" ]; then
  git config user.name "${CNB_GIT_USER_NAME:-NazoAuth Capacity Bot}"
  git config user.email "${CNB_GIT_USER_EMAIL:-nazoauth-capacity-bot@noreply.cnb.cool}"
  git add "${report}"
  git add -f "${results}"
  git commit -m "Record Hydra app CPU smoke benchmark"
  git push origin "HEAD:${CNB_BRANCH:-$(git branch --show-current)}"
fi
