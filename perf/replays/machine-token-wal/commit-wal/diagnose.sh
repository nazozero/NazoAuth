#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/support.sh"
if ! docker inspect "$dia_pg" >/dev/null 2>&1; then
  mapfile -t original_args < <(docker inspect -f '{{json .Config.Cmd}}' "$pg" | jq -r '.[]')
  docker create --name "$dia_pg" --network "$net" --network-alias "$pg" --shm-size 2g \
    --volumes-from "$pg" -e LD_PRELOAD=/tmp/pg-probe.so --entrypoint /affinity \
    "$bench_pg_image" "${original_args[@]}" >/dev/null
  install_tools "$dia_pg"
  docker cp pg-probe.so "$dia_pg:/tmp/pg-probe.so"
fi
if ! docker inspect "$dia_app" >/dev/null 2>&1; then
  docker create --name "$dia_app" --network "$net" --network-alias oauthbench-api-audit \
    --env-file ../private/revised.env -e RUST_LOG=warn -e LD_PRELOAD=/tmp/app-probe.so \
    -v hotpath-nazo-data-revised:/var/lib/nazo_oauth --entrypoint /affinity "$app_image" \
    "$BENCH_APP_CPUS" /usr/local/bin/nazoauth server >/dev/null
  install_tools "$dia_app"
  docker cp out/control "$dia_app:/usr/local/bin/nazoauth"
  docker cp app-probe.so "$dia_app:/tmp/app-probe.so"
fi
docker stop -t 60 "$pg" >/dev/null
cleanup() {
  rm -f app.tsv pg.tsv
  for container in "$dia_app" "$dia_pg"; do
    docker exec -u 0 "$container" rm -f /tmp/commit-probe.tsv >/dev/null 2>&1 || :
  done
  docker stop -t 20 "$dia_app" >/dev/null
  docker stop -t 90 "$dia_pg" >/dev/null
}
trap cleanup EXIT
docker start "$dia_pg" >/dev/null
ready_pg "$dia_pg"
start_deps
docker start "$dia_app" >/dev/null
ready "$dia_app" /health
for rate in "$@"; do
  vus=960; seconds=36
  if [[ $rate == 400 ]]; then vus=64; seconds=30; fi
  point "diag-$rate" "$dia_app" "$dia_pg" "$rate" "$seconds" "$vus"
  docker exec "$dia_app" cat /tmp/commit-probe.tsv >app.tsv
  docker exec "$dia_pg" cat /tmp/commit-probe.tsv >pg.tsv
  python3 phases.py "results/diag-$rate.json" app.tsv pg.tsv
  rm -f app.tsv pg.tsv
done
