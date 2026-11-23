#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/support.sh"
arm=${1:?A, N, K or H}
scenario=${2:?machine or introspect}
seed=${3:?initial offered rate}
case "$scenario" in machine|introspect) ;; *) exit 2 ;; esac
docker start "$pg" >/dev/null
ready_pg "$pg"
start_deps
docker start "$wrk" >/dev/null
case "$arm" in
  N|A)
    app=nazo-machine-policy-$arm; peer=nazo; discovery=/health
    prepare_machine_app "$arm" "$app"
    ;;
  K) app=$kc; peer=keycloak; discovery=/realms/api-audit/.well-known/openid-configuration ;;
  H) app=$hy; peer=hydra; discovery=/.well-known/openid-configuration ;;
  *) exit 2 ;;
esac
if [[ $peer != nazo ]]; then docker stop -t 5 "$vk" >/dev/null; fi
trap 'docker stop -t 15 "$app" "$wrk" >/dev/null' EXIT
docker start "$app" >/dev/null
ready "$app" "$discovery"
dest="$ROOT/results/wrk2/$arm/$scenario"
(cd bench && BENCH_NAZO_CONTAINER="$app" BENCH_WRK2_SEED="$seed" \
  taskset -c "$BENCH_CONTROL_CPU" python3 capacity/screen.py "$peer" "$scenario" "$dest")
jq -c '{status,confirmed_rate,first_rejected_rate,bounding_observation}' "$dest/summary.json"
