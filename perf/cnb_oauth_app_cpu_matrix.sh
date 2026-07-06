#!/usr/bin/env sh
set -eu

echo "oauth app-cpu comparison matrix started $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
. ./perf/cnb_bootstrap.sh
install_capacity_dependencies
docker compose version >/dev/null

mkdir -p docs perf/results

duration="${OAUTH_APP_CPU_MATRIX_DURATION:-2m}"
max_vus="${OAUTH_APP_CPU_MATRIX_MAX_VUS:-16384}"
commit_enabled="${OAUTH_APP_CPU_MATRIX_COMMIT:-0}"

git config user.name "${CNB_GIT_USER_NAME:-NazoAuth Capacity Bot}"
git config user.email "${CNB_GIT_USER_EMAIL:-nazoauth-capacity-bot@noreply.cnb.cool}"

taskset_for_cores() {
  python3 - "$1" <<'PY'
import sys
from pathlib import Path

needed = int(sys.argv[1])
allowed = ""
for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
    if line.startswith("Cpus_allowed_list:"):
        allowed = line.split(":", 1)[1].strip()
        break
if not allowed:
    processor_count = Path("/proc/cpuinfo").read_text(encoding="utf-8").count("processor\t:") or 1
    allowed = f"0-{max(0, processor_count - 1)}"

cpus: list[int] = []
for part in allowed.split(","):
    part = part.strip()
    if not part:
        continue
    if "-" in part:
        start, end = [int(value) for value in part.split("-", 1)]
        cpus.extend(range(start, end + 1))
    else:
        cpus.append(int(part))
cpus = sorted(set(cpus))
if len(cpus) < needed:
    raise SystemExit(f"need {needed} CPU(s), found {len(cpus)} allowed CPU(s): {allowed}")
selected = cpus[:needed]

ranges: list[str] = []
start = previous = selected[0]
for value in selected[1:]:
    if value == previous + 1:
        previous = value
        continue
    ranges.append(f"{start}-{previous}" if start != previous else str(start))
    start = previous = value
ranges.append(f"{start}-{previous}" if start != previous else str(start))
print(",".join(ranges))
PY
}

push_matrix_commit() {
  branch="${CNB_BRANCH:-$(git branch --show-current 2>/dev/null || echo main)}"
  for attempt in 1 2 3; do
    if git push origin "HEAD:${branch}"; then
      return 0
    fi
    sleep $((attempt * 10))
  done
  git push origin "HEAD:${branch}"
}

commit_paths() {
  message="$1"
  shift
  if [ "${commit_enabled}" != "1" ]; then
    return 0
  fi
  for path in "$@"; do
    if [ -e "${path}" ]; then
      case "${path}" in
        perf/results/*) git add -f "${path}" ;;
        *) git add "${path}" ;;
      esac
    fi
  done
  if git diff --cached --quiet; then
    echo "No changes to commit for ${message}."
    return 0
  fi
  git commit -m "${message}"
  push_matrix_commit
}

run_nazoauth_stage() {
  cores="$1"
  rates="$2"
  taskset_cpus="$3"
  suffix="app-cpu-taskset-${cores}core-oauth-compare"
  log_path="perf/results/${suffix}.log"

  echo "running NazoAuth stage cores=${cores} rates=${rates} taskset=${taskset_cpus} log=${log_path}"
  (
    export CNB_CAPACITY_SKIP_BOOTSTRAP=1
    export CNB_CAPACITY_COMMIT=0
    export CAPACITY_CHECKPOINT_COMMIT=0
    export APP_CPU_CAPACITY_DURATION="${duration}"
    export APP_CPU_CAPACITY_RATES="${rates}"
    export APP_CPU_CAPACITY_SCENARIO="token_only_client_credentials"
    export APP_CPU_CAPACITY_INSTANCES="1"
    export APP_CPU_CAPACITY_APP_CPUS="${cores}"
    export APP_CPU_CAPACITY_APP_TASKSET="${taskset_cpus}"
    export APP_CPU_CAPACITY_MAX_VUS="${max_vus}"
    export APP_CPU_CAPACITY_SUFFIX="${suffix}"
    ./perf/cnb_app_cpu_capacity_smoke.sh
  ) 2>&1 | tee "${log_path}"

  commit_paths \
    "Record NazoAuth ${cores}-core app CPU comparison baseline" \
    "docs/performance-capacity-curve-${suffix}.md" \
    "perf/results/capacity-${suffix}.json" \
    "perf/results/cnb-environment-${suffix}.md"
}

run_keycloak_stage() {
  cores="$1"
  rates="$2"
  taskset_cpus="$3"
  suffix="keycloak-app-cpu-taskset-${cores}core-oauth-compare"
  nazo_suffix="app-cpu-taskset-${cores}core-oauth-compare"
  log_path="perf/results/${suffix}.log"

  echo "running Keycloak stage cores=${cores} rates=${rates} taskset=${taskset_cpus} log=${log_path}"
  (
    export CNB_CAPACITY_SKIP_BOOTSTRAP=1
    export KEYCLOAK_APP_CPU_DURATION="${duration}"
    export KEYCLOAK_APP_CPU_RATES="${rates}"
    export KEYCLOAK_APP_CPUS="${cores}"
    export KEYCLOAK_APP_TASKSET="${taskset_cpus}"
    export KEYCLOAK_APP_CPU_SUFFIX="${suffix}"
    export KEYCLOAK_APP_CPU_PRE_ALLOCATED_VUS="${max_vus}"
    export KEYCLOAK_APP_CPU_MAX_VUS="${max_vus}"
    export NAZOAUTH_APP_CPU_RESULTS="perf/results/capacity-${nazo_suffix}.json"
    ./perf/cnb_keycloak_app_cpu_smoke.sh
  ) 2>&1 | tee "${log_path}"

  commit_paths \
    "Record Keycloak ${cores}-core app CPU comparison" \
    "docs/performance-keycloak-comparison-${suffix}.md" \
    "perf/results/${suffix}.json"
}

run_hydra_stage() {
  cores="$1"
  rates="$2"
  taskset_cpus="$3"
  suffix="hydra-app-cpu-taskset-${cores}core-oauth-compare"
  nazo_suffix="app-cpu-taskset-${cores}core-oauth-compare"
  log_path="perf/results/${suffix}.log"

  echo "running Ory Hydra stage cores=${cores} rates=${rates} taskset=${taskset_cpus} log=${log_path}"
  (
    export CNB_CAPACITY_SKIP_BOOTSTRAP=1
    export HYDRA_APP_CPU_DURATION="${duration}"
    export HYDRA_APP_CPU_RATES="${rates}"
    export HYDRA_APP_CPUS="${cores}"
    export HYDRA_APP_TASKSET="${taskset_cpus}"
    export HYDRA_APP_CPU_SUFFIX="${suffix}"
    export HYDRA_APP_CPU_PRE_ALLOCATED_VUS="${max_vus}"
    export HYDRA_APP_CPU_MAX_VUS="${max_vus}"
    export NAZOAUTH_APP_CPU_RESULTS="perf/results/capacity-${nazo_suffix}.json"
    ./perf/cnb_hydra_app_cpu_smoke.sh
  ) 2>&1 | tee "${log_path}"

  commit_paths \
    "Record Ory Hydra ${cores}-core app CPU comparison" \
    "docs/performance-hydra-comparison-${suffix}.md" \
    "perf/results/${suffix}.json"
}

run_stage() {
  cores="$1"
  rates="$2"
  taskset_cpus="$(taskset_for_cores "${cores}")"
  echo "oauth app-cpu stage cores=${cores} rates=${rates} taskset=${taskset_cpus}"
  run_nazoauth_stage "${cores}" "${rates}" "${taskset_cpus}"
  run_keycloak_stage "${cores}" "${rates}" "${taskset_cpus}"
  run_hydra_stage "${cores}" "${rates}" "${taskset_cpus}"
}

run_stage 1 "${OAUTH_APP_CPU_MATRIX_1_CORE_RATES:-1000,2000}"
run_stage 2 "${OAUTH_APP_CPU_MATRIX_2_CORE_RATES:-1000,2000,4000}"
run_stage 4 "${OAUTH_APP_CPU_MATRIX_4_CORE_RATES:-1000,2000,4000,10000}"

echo "oauth app-cpu comparison matrix finished $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
