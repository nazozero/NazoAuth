#!/usr/bin/env bash
# Measure the response on the original PostgreSQL process, outside the A/B.
set -euo pipefail
source "$(dirname "$0")/support.sh"
app=nazo-wal-app-http-timing
if ! docker inspect "$app" >/dev/null 2>&1; then
  docker create --name "$app" --network "$net" --network-alias oauthbench-api-audit \
    -v hotpath-nazo-data-revised:/var/lib/nazo_oauth --env-file ../private/revised.env \
    --log-opt max-size=16m --log-opt max-file=2 -e RUST_LOG=warn \
    --entrypoint /affinity "$app_image" "$BENCH_APP_CPUS" /usr/local/bin/nazoauth server >/dev/null
  install_tools "$app"
fi
docker stop -t 15 "$app" >/dev/null
docker cp out/http-timing "$app:/usr/local/bin/nazoauth"
start_deps
tmp=$(mktemp)
cleanup() {
  docker stop -t 15 "$app" >/dev/null
  docker cp bench/durable-k6.js oauthbench-k6:/tmp/durable.js
  docker exec oauthbench-k6 rm -f /tmp/k6-http-timing.json
  rm -f "$tmp"
}
trap cleanup EXIT
python3 prepare-response.py bench/durable-k6.js "$tmp"
docker cp "$tmp" oauthbench-k6:/tmp/durable.js
for rate in "$@"; do
  docker start "$app" >/dev/null
  ready "$app" /health
  seconds=36; vus=960
  if [[ $rate == 400 ]]; then seconds=30; vus=64; fi
  docker exec oauthbench-k6 rm -f /tmp/k6-http-timing.json
  point "http-$rate" "$app" "$pg" "$rate" "$seconds" "$vus"
  docker cp oauthbench-k6:/tmp/k6-http-timing.json "results/http-$rate.timing.json"
  jq -e '(.postcommit_samples.count >= 100) and (.postcommit_samples.count >= 0.05 * .measured_success.count)' "results/http-$rate.timing.json" >/dev/null
  docker stop -t 15 "$app" >/dev/null
done
