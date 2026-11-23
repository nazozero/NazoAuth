#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/support.sh"
for variant in control candidate; do
  app=nazo-wal-app-$variant
  if ! docker inspect "$app" >/dev/null 2>&1; then
    docker create --name "$app" --network "$net" --network-alias oauthbench-api-audit \
      -v hotpath-nazo-data-revised:/var/lib/nazo_oauth --env-file ../private/revised.env \
      --log-opt max-size=16m --log-opt max-file=2 -e RUST_LOG=warn \
      --entrypoint /affinity "$app_image" "$BENCH_APP_CPUS" /usr/local/bin/nazoauth server >/dev/null
    install_tools "$app"
    docker cp "out/$variant" "$app:/usr/local/bin/nazoauth"
  fi
done
stop_apps_ab(){
  docker stop -t 15 nazo-wal-app-control nazo-wal-app-candidate >/dev/null
}
trap stop_apps_ab EXIT
docker start "$pg" >/dev/null
ready_pg "$pg"
start_deps
for trial in "$@"; do
  IFS=- read -r label rate round <<<"$trial"
  app=nazo-wal-app-control
  if [[ $label == E ]]; then app=nazo-wal-app-candidate; fi
  stop_apps_ab
  docker start "$app" >/dev/null
  ready "$app" /health
  vus=960; seconds=36
  if [[ $rate == 400 ]]; then vus=64; seconds=30; fi
  point "$trial" "$app" "$pg" "$rate" "$seconds" "$vus"
done
