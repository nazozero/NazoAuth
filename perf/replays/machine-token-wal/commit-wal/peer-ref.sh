#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/support.sh"
peer=$1
scenario=${BENCH_MACHINE_SCENARIO:-machine}
case "$scenario" in machine|introspect) ;; *) exit 2 ;; esac
shift
case "$peer" in
  keycloak) app=$kc; discovery=/realms/api-audit/.well-known/openid-configuration ;;
  hydra) app=$hy; discovery=/.well-known/openid-configuration ;;
  *) exit 2 ;;
esac
trap 'docker stop -t 20 "$app" >/dev/null; docker exec "$prep" rm -f /tmp/commit-kc-bootstrap.json >/dev/null' EXIT
start_deps
if [[ $peer == keycloak ]]; then
  docker cp ../private/keycloak.json "$prep:/tmp/commit-kc-bootstrap.json"
  docker cp keycloak-event-config.py "$prep:/tmp/commit-kc-events.py"
fi
docker stop -t 5 "$vk" >/dev/null
for trial in "$@"; do
  IFS=- read -r label rate round <<<"$trial"
  docker stop -t 20 "$app" >/dev/null
  docker start "$app" >/dev/null
  ready "$app" "$discovery"
  if [[ $peer == keycloak && ! -s results/keycloak-events.json ]]; then
    docker exec "$prep" python3 /tmp/commit-kc-events.py >results/keycloak-events.json
  fi
  vus=960; seconds=36
  if [[ $rate == 400 ]]; then vus=64; seconds=30; fi
  (cd ../peer-comparison/bench && BENCH_VUS=$vus bash peer-point.sh "$peer" "$scenario" "$rate" 10 "$seconds" "$ROOT/results/$trial.json")
  jq -c '{whole_success,whole_failed,success_per_second,p95_ms,p99_ms,dropped_whole_trial,outcome}' "$ROOT/results/$trial.json"
done
