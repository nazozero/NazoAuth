#!/usr/bin/env bash
# B is the control. A enables audit, N disables it explicitly, and D uses the new default.
set -euo pipefail
source "$(dirname "$0")/support.sh"
mkdir -p results
apps=()
cleanup() {
  for app in "${apps[@]}"; do docker stop -t 10 "$app" >/dev/null; done
}
trap cleanup EXIT
docker start "$pg" >/dev/null
ready_pg "$pg"
start_deps
variants=()
for trial in "$@"; do
  variant=${trial%%-*}
  case "$variant" in B|A|D|N|P) ;; *) exit 2 ;; esac
  if [[ " ${variants[*]} " != *" $variant "* ]]; then variants+=("$variant"); fi
done
scenario=${BENCH_MACHINE_SCENARIO:-machine}
case "$scenario" in machine|introspect) ;; *) exit 2 ;; esac
for variant in "${variants[@]}"; do
  app="nazo-machine-policy-$variant"
  prepare_machine_app "$variant" "$app"
  apps+=("$app")
done
for trial in "$@"; do
  IFS=- read -r variant rate round <<<"$trial"
  case "$variant" in B|A) export BENCH_ISSUANCE_AUDIT=required ;; D|N|P) export BENCH_ISSUANCE_AUDIT=off ;; *) exit 2 ;; esac
  if [[ $scenario == introspect ]]; then export BENCH_ISSUANCE_AUDIT=off; fi
  app="nazo-machine-policy-$variant"
  docker start "$app" >/dev/null
  ready "$app" /health
  vus=960; seconds=36
  if [[ $rate == 400 ]]; then vus=64; seconds=30; fi
  point "$trial" "$app" "$pg" "$rate" "$seconds" "$vus" "$scenario"
  docker stop -t 10 "$app" >/dev/null
done
