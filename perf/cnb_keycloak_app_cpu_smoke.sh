#!/usr/bin/env sh
set -eu

if [ "${CNB_CAPACITY_SKIP_BOOTSTRAP:-0}" != "1" ]; then
  . ./perf/cnb_bootstrap.sh
  install_capacity_dependencies
  docker compose version >/dev/null
fi

rates="${KEYCLOAK_APP_CPU_RATES:-100,250,500}"
duration="${KEYCLOAK_APP_CPU_DURATION:-2m}"
app_cpus="${KEYCLOAK_APP_CPUS:-1}"
app_taskset="${KEYCLOAK_APP_TASKSET:-}"
suffix="${KEYCLOAK_APP_CPU_SUFFIX:-keycloak-app-cpu-${app_cpus}vcpu-smoke}"
keycloak_image_tag="${KEYCLOAK_IMAGE_TAG:-26.6.4}"
host_port="${KEYCLOAK_HOST_PORT:-18081}"
report="docs/performance-keycloak-comparison-${suffix}.md"
results="perf/results/${suffix}.json"
nazoauth_results="${NAZOAUTH_APP_CPU_RESULTS:-perf/results/capacity-app-cpu-1vcpu-smoke.json}"

export KEYCLOAK_APP_TASKSET="${app_taskset}"

mkdir -p docs perf/results

project="$(printf 'nazoauth-%s-%s' "${CNB_BUILD_ID:-local}" "${suffix}" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9_-' '-' | cut -c1-63)"
override="perf/results/docker-compose.${suffix}.yml"

cat >"${override}" <<EOF
services:
  keycloak:
    cpus: "${app_cpus}"
EOF

if [ -n "${app_taskset}" ]; then
  cat >>"${override}" <<EOF
    build:
      context: .
      dockerfile: perf/keycloak/Containerfile.taskset
      args:
        KEYCLOAK_IMAGE_TAG: "${keycloak_image_tag}"
    image: nazoauth-keycloak-taskset:${keycloak_image_tag}
    entrypoint: ["/usr/local/bin/taskset", "-c", "${app_taskset}", "/opt/keycloak/bin/kc.sh"]
EOF
fi

compose() {
  COMPOSE_PROJECT_NAME="${project}" KEYCLOAK_IMAGE_TAG="${keycloak_image_tag}" KEYCLOAK_HOST_PORT="${host_port}" \
    docker compose -p "${project}" -f docker-compose.keycloak.perf.yml -f "${override}" "$@"
}

wait_for_keycloak() {
  python3 - "$host_port" <<'PY'
import sys
import time
import urllib.error
import urllib.request

port = sys.argv[1]
url = f"http://127.0.0.1:{port}/realms/perf/.well-known/openid-configuration"
deadline = time.time() + 180
last_error = None
while time.time() < deadline:
    try:
        with urllib.request.urlopen(url, timeout=3) as response:
            if response.status == 200:
                print("keycloak ready")
                raise SystemExit
    except Exception as exc:
        last_error = exc
        time.sleep(2)
raise RuntimeError(f"Keycloak did not become ready: {last_error}")
PY
}

sample_stats() {
  stats_file="$1"
  while :; do
    ids="$(compose ps -q keycloak keycloak-postgres 2>/dev/null | tr '\n' ' ')"
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

  echo "keycloak app-cpu smoke: rate=${rate}/s duration=${duration} app_cpus=${app_cpus} app_taskset=${app_taskset:-disabled}"
  compose down -v --remove-orphans >/dev/null 2>&1 || true
  compose up -d
  wait_for_keycloak

  sample_stats "${stats}" &
  sampler_pid="$!"
  set +e
  docker run --rm \
    --user "$(id -u):$(id -g)" \
    --network "${project}_keycloak_net" \
    -v "$PWD/perf/keycloak:/scripts:ro" \
    -v "$PWD/perf/results:/results" \
    -e BASE_URL="http://keycloak:8080" \
    -e KEYCLOAK_REALM="perf" \
    -e KEYCLOAK_CLIENT_ID="perf-client-credentials" \
    -e KEYCLOAK_CLIENT_SECRET="perf-client-secret" \
    -e PERF_RATE="${rate}" \
    -e PERF_DURATION="${duration}" \
    -e PERF_PRE_ALLOCATED_VUS="${KEYCLOAK_APP_CPU_PRE_ALLOCATED_VUS:-512}" \
    -e PERF_MAX_VUS="${KEYCLOAK_APP_CPU_MAX_VUS:-512}" \
    "docker.io/grafana/k6:${K6_IMAGE_TAG:-2.1.0}" \
    run --summary-export "/results/${suffix}-${rate}.summary.json" /scripts/client_credentials.js
  status="$?"
  set -e
  kill "${sampler_pid}" >/dev/null 2>&1 || true
  wait "${sampler_pid}" 2>/dev/null || true
  compose down -v --remove-orphans
  if [ "${status}" -ne 0 ]; then
    echo "Keycloak k6 point reported a non-zero result: rate=${rate}/s status=${status}; keeping summary and continuing" >&2
  fi
  if [ ! -f "${summary}" ]; then
    echo "Keycloak k6 summary missing after rate=${rate}/s; cannot continue" >&2
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

python3 perf/keycloak_app_cpu_compare.py \
  --summary-dir perf/results \
  --results-path "${results}" \
  --report-path "${report}" \
  --nazoauth-results "${nazoauth_results}" \
  --suffix "${suffix}" \
  --duration "${duration}" \
  --rates "${rates}" \
  --app-cpus "${app_cpus}" \
  --keycloak-image-tag "${keycloak_image_tag}"

if [ "${KEYCLOAK_APP_CPU_COMMIT:-0}" = "1" ]; then
  git config user.name "${CNB_GIT_USER_NAME:-NazoAuth Capacity Bot}"
  git config user.email "${CNB_GIT_USER_EMAIL:-nazoauth-capacity-bot@noreply.cnb.cool}"
  git add "${report}"
  git add -f "${results}"
  git commit -m "Record Keycloak app CPU smoke benchmark"
  git push origin "HEAD:${CNB_BRANCH:-$(git branch --show-current)}"
fi
