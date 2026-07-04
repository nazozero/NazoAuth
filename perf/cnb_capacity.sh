#!/usr/bin/env sh
set -eu

if [ "${CNB_CAPACITY_SKIP_BOOTSTRAP:-0}" != "1" ]; then
  apk add --no-cache coreutils git jq python3 >/dev/null
  docker compose version >/dev/null
fi

SCENARIOS="${CAPACITY_SCENARIOS:-token_only_client_credentials,oidc_cold_login_refresh,oidc_logged_in_authorization_code,oidc_refresh_only,fapi2_full_security}"
REPORT_SUFFIX="${CAPACITY_REPORT_SUFFIX:-full}"
DURATION="${CAPACITY_DURATION:-30m}"
INSTANCES="${CAPACITY_INSTANCES:-1,2,4}"
REPORT="docs/performance-capacity-curve-${REPORT_SUFFIX}.md"
ENV_REPORT="perf/results/cnb-environment-${REPORT_SUFFIX}.md"
COMPOSE_PROJECT_NAME="$(printf 'nazoauth-%s-%s' "${CNB_BUILD_ID:-local}" "${REPORT_SUFFIX}" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9_-' '-' | cut -c1-63)"
export COMPOSE_PROJECT_NAME

mkdir -p docs perf/results

if [ -n "${PERF_CPUSET:-}" ]; then
  PERF_COMPOSE_OVERRIDE="perf/results/docker-compose.cpuset-${REPORT_SUFFIX}.yml"
  export PERF_COMPOSE_OVERRIDE
  cat >"${PERF_COMPOSE_OVERRIDE}" <<EOF
services:
  postgres:
    cpuset: "${PERF_CPUSET}"
  valkey:
    cpuset: "${PERF_CPUSET}"
  nazoauth:
    cpuset: "${PERF_CPUSET}"
  keyset:
    cpuset: "${PERF_CPUSET}"
  migrate:
    cpuset: "${PERF_CPUSET}"
  perf:
    cpuset: "${PERF_CPUSET}"
EOF
fi

{
  echo "## Test Environment"
  echo
  echo "| Field | Value |"
  echo "| --- | --- |"
  echo "| CNB repo | ${CNB_REPO_SLUG:-unknown} |"
  echo "| CNB branch | ${CNB_BRANCH:-unknown} |"
  echo "| CNB commit | ${CNB_COMMIT:-unknown} |"
  echo "| CNB build id | ${CNB_BUILD_ID:-unknown} |"
  echo "| CNB pipeline key | ${CNB_PIPELINE_KEY:-unknown} |"
  echo "| Runner tag | cnb:arch:amd64 |"
  echo "| Requested runner CPUs | 64 |"
  echo "| Observed logical CPUs | $(nproc --all 2>/dev/null || echo unknown) |"
  echo "| Observed CPU model | $(awk -F': ' '/model name/ { print $2; exit }' /proc/cpuinfo 2>/dev/null | sed 's/|/-/g' || echo unknown) |"
  echo "| Cgroup CPU max | $(cat /sys/fs/cgroup/cpu.max 2>/dev/null || echo unknown) |"
  echo "| Memory total | $(awk '/MemTotal/ { printf \"%.2f GiB\", $2 / 1024 / 1024 }' /proc/meminfo 2>/dev/null || echo unknown) |"
  echo "| Cgroup memory max | $(cat /sys/fs/cgroup/memory.max 2>/dev/null || echo unknown) |"
  echo "| Kernel | $(uname -a | sed 's/|/-/g') |"
  echo "| Docker server | $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unknown) |"
  echo "| Docker compose | $(docker compose version --short 2>/dev/null || echo unknown) |"
  echo "| Compose project | ${COMPOSE_PROJECT_NAME} |"
  echo "| CPU set | ${PERF_CPUSET:-unrestricted} |"
  echo "| Capacity scenarios | ${SCENARIOS} |"
  echo "| Duration per point | ${DURATION} |"
  echo "| App instances | ${INSTANCES} |"
  echo
} >"${ENV_REPORT}"

set +e
python3 perf/capacity.py \
  --duration "${DURATION}" \
  --instances "${INSTANCES}" \
  --scenarios "${SCENARIOS}" \
  --report-path "${REPORT}" \
  --results-path "perf/results/capacity-${REPORT_SUFFIX}.json"
status=$?
set -e

python3 - "${ENV_REPORT}" "${REPORT}" "${status}" <<'PY'
import sys
from pathlib import Path

env_path = Path(sys.argv[1])
target_path = Path(sys.argv[2])
status = int(sys.argv[3])

env = env_path.read_text(encoding="utf-8").rstrip() + "\n\n"
if target_path.exists():
    source = target_path.read_text(encoding="utf-8")
else:
    source = "\n".join([
        "# NazoAuth Capacity Curve Benchmarks",
        "",
        "No successful capacity point completed before the run failed.",
        "",
    ])
marker = "\n## Run Configuration\n"
if marker in source:
    source = source.replace(marker, "\n" + env + "## Run Configuration\n", 1)
else:
    source = source + "\n\n" + env
if status != 0:
    source = source.rstrip() + "\n\n## Run Status\n\n"
    source += f"- CNB capacity run failed with exit code `{status}` before completing the full matrix.\n"
    source += "- This report may contain only successful points completed before the failure.\n"
target_path.write_text(source, encoding="utf-8", newline="\n")
PY

if [ "${CNB_CAPACITY_COMMIT:-1}" = "0" ]; then
  exit "${status}"
fi

git config user.name "${CNB_GIT_USER_NAME:-NazoAuth Capacity Bot}"
git config user.email "${CNB_GIT_USER_EMAIL:-nazoauth-capacity-bot@noreply.cnb.cool}"
git add "${REPORT}"
if git diff --cached --quiet; then
  echo "No capacity report changes to commit."
  exit "${status}"
fi

git commit -m "Record CNB capacity curve ${REPORT_SUFFIX}"

BRANCH="${CNB_BRANCH:-main}"
for attempt in 1 2 3; do
  if git pull --rebase origin "${BRANCH}" && git push origin "HEAD:${BRANCH}"; then
    exit "${status}"
  fi
  sleep $((attempt * 10))
done

git push origin "HEAD:${BRANCH}"
exit "${status}"
