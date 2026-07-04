#!/usr/bin/env sh
set -eu

apk add --no-cache coreutils git jq python3 >/dev/null

docker compose version >/dev/null

SCENARIOS="${CAPACITY_SCENARIOS:-token_only_client_credentials,oidc_cold_login_refresh,oidc_logged_in_authorization_code,oidc_refresh_only,fapi2_full_security}"
REPORT_SUFFIX="${CAPACITY_REPORT_SUFFIX:-full}"
DURATION="${CAPACITY_DURATION:-30m}"
INSTANCES="${CAPACITY_INSTANCES:-1,2,4}"
REPORT="docs/performance-capacity-curve-${REPORT_SUFFIX}.md"
ENV_REPORT="perf/results/cnb-environment-${REPORT_SUFFIX}.md"

mkdir -p docs perf/results

{
  echo "## Test Environment"
  echo
  echo "| Field | Value |"
  echo "| --- | --- |"
  echo "| CNB repo | ${CNB_REPO_SLUG:-unknown} |"
  echo "| CNB branch | ${CNB_BRANCH:-unknown} |"
  echo "| CNB commit | ${CNB_COMMIT:-unknown} |"
  echo "| Runner tag | cnb:arch:amd64 |"
  echo "| Requested runner CPUs | 64 |"
  echo "| Observed logical CPUs | $(nproc --all 2>/dev/null || echo unknown) |"
  echo "| Memory total | $(awk '/MemTotal/ { printf \"%.2f GiB\", $2 / 1024 / 1024 }' /proc/meminfo 2>/dev/null || echo unknown) |"
  echo "| Kernel | $(uname -a | sed 's/|/-/g') |"
  echo "| Docker server | $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unknown) |"
  echo "| Docker compose | $(docker compose version --short 2>/dev/null || echo unknown) |"
  echo "| Capacity scenarios | ${SCENARIOS} |"
  echo "| Duration per point | ${DURATION} |"
  echo "| App instances | ${INSTANCES} |"
  echo
} >"${ENV_REPORT}"

python3 perf/capacity.py \
  --duration "${DURATION}" \
  --instances "${INSTANCES}" \
  --scenarios "${SCENARIOS}"

python3 - "${ENV_REPORT}" docs/performance-capacity-curve.md "${REPORT}" <<'PY'
import sys
from pathlib import Path

env_path = Path(sys.argv[1])
source_path = Path(sys.argv[2])
target_path = Path(sys.argv[3])

env = env_path.read_text(encoding="utf-8").rstrip() + "\n\n"
source = source_path.read_text(encoding="utf-8")
marker = "\n## Run Configuration\n"
if marker in source:
    source = source.replace(marker, "\n" + env + "## Run Configuration\n", 1)
else:
    source = source + "\n\n" + env
target_path.write_text(source, encoding="utf-8", newline="\n")
PY

git config user.name "${CNB_GIT_USER_NAME:-NazoAuth Capacity Bot}"
git config user.email "${CNB_GIT_USER_EMAIL:-nazoauth-capacity-bot@noreply.cnb.cool}"
git add "${REPORT}"
if git diff --cached --quiet; then
  echo "No capacity report changes to commit."
  exit 0
fi

git commit -m "Record CNB capacity curve ${REPORT_SUFFIX}"

BRANCH="${CNB_BRANCH:-main}"
for attempt in 1 2 3; do
  if git pull --rebase origin "${BRANCH}" && git push origin "HEAD:${BRANCH}"; then
    exit 0
  fi
  sleep $((attempt * 10))
done

git push origin "HEAD:${BRANCH}"
