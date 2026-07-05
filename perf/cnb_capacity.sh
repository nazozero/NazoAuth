#!/usr/bin/env sh
set -eu

if [ "${CNB_CAPACITY_SKIP_BOOTSTRAP:-0}" != "1" ]; then
  . ./perf/cnb_bootstrap.sh
  install_capacity_dependencies
  docker compose version >/dev/null
fi

SCENARIOS="${CAPACITY_SCENARIOS:-token_only_client_credentials,oidc_cold_login_refresh,oidc_logged_in_authorization_code,oidc_refresh_only,fapi2_full_security}"
REPORT_SUFFIX="${CAPACITY_REPORT_SUFFIX:-full}"
DURATION="${CAPACITY_DURATION:-30m}"
INSTANCES="${CAPACITY_INSTANCES:-1,2,4}"
RATES="${CAPACITY_RATES:-}"
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

CPUSET_VALUE="${PERF_CPUSET:-unrestricted}"
CPUSET_CORES="$(python3 - "${CPUSET_VALUE}" <<'PY'
import sys

value = sys.argv[1]
if value == "unrestricted":
    print("unrestricted")
    raise SystemExit

count = 0
for part in value.split(","):
    part = part.strip()
    if not part:
        continue
    if "-" in part:
        start, end = [int(item) for item in part.split("-", 1)]
        count += end - start + 1
    else:
        count += 1
print(count)
PY
)"

{
  echo "## Test Environment and Topology"
  echo
  echo "| Field | Value |"
  echo "| --- | --- |"
  echo "| Source commit | ${CNB_COMMIT:-$(git rev-parse HEAD 2>/dev/null || echo unknown)} |"
  echo "| Runner tag | cnb:arch:amd64 |"
  echo "| Requested runner CPUs | 64 |"
  echo "| Observed logical CPUs | $(nproc --all 2>/dev/null || echo unknown) |"
  echo "| Process allowed CPUs | $(awk -F':\t' '/Cpus_allowed_list/ { print $2; exit }' /proc/self/status 2>/dev/null || echo unknown) |"
  echo "| Observed CPU model | $(awk -F': ' '/model name/ { print $2; exit }' /proc/cpuinfo 2>/dev/null | sed 's/|/-/g' || echo unknown) |"
  echo "| Cgroup CPU max | $(cat /sys/fs/cgroup/cpu.max 2>/dev/null || echo unknown) |"
  echo "| Memory total | $(awk '/MemTotal/ { printf \"%.2f GiB\", $2 / 1024 / 1024 }' /proc/meminfo 2>/dev/null || echo unknown) |"
  echo "| Cgroup memory max | $(cat /sys/fs/cgroup/memory.max 2>/dev/null || echo unknown) |"
  echo "| Workspace disk available | $(df -h . 2>/dev/null | awk 'NR==2 { print $4 \" on \" $6 }' || echo unknown) |"
  echo "| Kernel | $(uname -a | sed 's/|/-/g') |"
  echo "| Docker server | $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unknown) |"
  echo "| Docker compose | $(docker compose version --short 2>/dev/null || echo unknown) |"
  echo "| Compose project | ${COMPOSE_PROJECT_NAME} |"
  echo "| Compose files | docker-compose.perf.yml${PERF_COMPOSE_OVERRIDE:+ + ${PERF_COMPOSE_OVERRIDE}} |"
  echo "| CPU set | ${CPUSET_VALUE} |"
  echo "| CPU set size | ${CPUSET_CORES} |"
  echo "| Services pinned to CPU set | postgres, valkey, keyset, migrate, nazoauth, perf |"
  echo "| Per-container CPU model | Docker cpuset isolation; no CPU quota. Each service container may run on the listed CPU set. NazoAuth is additionally scaled by the stage instance count. |"
  echo "| Capacity scenarios | ${SCENARIOS} |"
  echo "| Duration per point | ${DURATION} |"
  echo "| App instance stages | ${INSTANCES} NazoAuth replica(s) |"
  echo "| Explicit rates | ${RATES:-scenario defaults} |"
  echo "| Load executor | k6 constant-arrival-rate, time unit 1s |"
  echo "| Token-only target rates | 1000, 2500, 5000, 7500, 10000 flow/s |"
  echo "| OIDC cold/login and logged-in target rates | 16, 32, 64, 128, 256 flow/s |"
  echo "| OIDC refresh-only target rates | 250, 500, 1000, 1500, 2000 flow/s |"
  echo "| FAPI2 full-security target rates | 16, 32, 64, 128, 256 flow/s |"
  echo "| Network topology | Single Docker bridge network; perf runner reaches NazoAuth at http://nazoauth:8000; NazoAuth reaches PostgreSQL and Valkey inside the same network. |"
  echo "| PostgreSQL container | docker.io/library/postgres:18-alpine; pg_stat_statements enabled; track_io_timing enabled; ephemeral Docker volume. |"
  echo "| Valkey container | docker.io/valkey/valkey:8-alpine; RDB save disabled; AOF disabled; warning log level; ephemeral state for benchmark isolation. |"
  echo "| NazoAuth container | Built from local Containerfile target runtime; PERF_METRICS_ENABLED=true; runtime key volume shared with keyset/migrate. |"
  echo "| Key material setup | keyset service generates runtime RS256 and PS256 keys before migration and benchmark traffic. |"
  echo "| Migration setup | migrate service runs nazo-oauth-migrate before the NazoAuth service is considered ready for benchmark traffic. |"
  echo "| Perf runner | Built from perf/runner/Containerfile; mounts Docker socket for container stats; writes Markdown reports to docs/ and runtime JSON/logs to ignored perf/results/. |"
  echo "| Metrics sources | k6 HTTP metrics; Docker stats CPU/memory samples; PostgreSQL pg_stat_statements; NazoAuth DB pool metrics; Valkey INFO counters. |"
  echo
} >"${ENV_REPORT}"

set +e
if [ -n "${RATES}" ]; then
  python3 perf/capacity.py \
    --duration "${DURATION}" \
    --instances "${INSTANCES}" \
    --scenarios "${SCENARIOS}" \
    --rates "${RATES}" \
    --report-path "${REPORT}" \
    --results-path "perf/results/capacity-${REPORT_SUFFIX}.json"
else
  python3 perf/capacity.py \
    --duration "${DURATION}" \
    --instances "${INSTANCES}" \
    --scenarios "${SCENARIOS}" \
    --report-path "${REPORT}" \
    --results-path "perf/results/capacity-${REPORT_SUFFIX}.json"
fi
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
