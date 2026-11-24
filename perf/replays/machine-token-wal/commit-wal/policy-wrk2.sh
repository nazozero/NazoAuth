#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/support.sh"
arm=${1:?A, D, N, K or H}
scenario=${2:?machine or introspect}
seed=${3:?initial offered rate}
case "$scenario" in machine|introspect) ;; *) exit 2 ;; esac
docker start "$pg" >/dev/null
ready_pg "$pg"
start_deps
docker start "$wrk" >/dev/null
case "$arm" in
  D|N|A)
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
if [[ $arm == A && $scenario == machine ]]; then
  read -r dbid audit_rel _ < <(relation_numbers "$pg")
  python3 prepare-wrk2-audit.py
  export BENCH_WRK2_AUDIT_REL="1663/$dbid/$audit_rel"
  export BENCH_WRK2_WAL_COUNT="$ROOT/count-wal.py"
  export BENCH_CAPACITY_POINT_SCRIPT=capacity/audited-point.sh
fi
connections=${BENCH_WRK2_CONNECTIONS:-960}
[[ $connections =~ ^[0-9]+$ && $connections -ge 15 ]]
suite=wrk2
if [[ $connections != 960 ]]; then suite="wrk2-c$connections"; fi
dest="${4:-$ROOT/results}/$suite/$arm/$scenario"
(cd bench && BENCH_NAZO_CONTAINER="$app" BENCH_WRK2_SEED="$seed" \
  taskset -c "$BENCH_CONTROL_CPU" python3 capacity/screen.py "$peer" "$scenario" "$dest")
jq -c '{status,confirmed_rate,first_rejected_rate,bounding_observation}' "$dest/summary.json"
