#!/usr/bin/env bash
# Run after setup in a dedicated NazoAuth benchmark deployment.
set -euo pipefail
PERF=$(cd "$(dirname "$0")" && pwd)
WORK=${WORK:-"$PERF/.work"}
cd "$WORK"
source masks
source "$PERF/deploy.sh"
dest=${1:-"$WORK/login-$(date -u +%Y%m%dT%H%M%SZ)"}
mkdir "$dest"
app=oidc-bench-nazo
docker cp "$PERF/fixture/login_batch.py" "$prep:/tmp/login_batch.py"
memory() {
  docker exec --privileged -u 0 "$app" sh -ec 'test "$(cat /proc/1/comm)" = nazoauth
    awk "/^Pss:/ {print \$2}" /proc/1/smaps_rollup
    awk "/^VmHWM:/ {print \$2}" /proc/1/status' | xargs
}
for round in 1 2 3; do
  docker restart -t 8 "$app" >/dev/null
  ready "$app" /health
  sleep 2
  memory >"$dest/$round-cold.kib"
  for batch in 1 2 3; do
    docker exec "$prep" /affinity "$BENCH_GEN_CPUS" python3 /tmp/login_batch.py >"$dest/$round-$batch.json"
    sleep 3
    memory >"$dest/$round-$batch.kib"
  done
done
