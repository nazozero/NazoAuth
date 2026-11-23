#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
source <(awk '/^case /{exit} {print}' ../retest.sh)
dia_app=nazo-commit-observer
dia_pg=nazo-pg-observer
bench_pg_image=$(docker inspect -f '{{.Image}}' "$pg")
ready_pg() {
  for _ in {1..80}; do
    if docker exec "$1" pg_isready -q -h 127.0.0.1 -U postgres; then return; fi
    sleep .4
  done
  return 1
}
start_deps() {
  docker start "$vk" "$prep" oauthbench-k6 >/dev/null
  docker cp bench/durable-k6.js oauthbench-k6:/tmp/durable.js
  docker exec "$prep" cp /tmp/revised.json /tmp/nazo.json
}
prepare_machine_app() {
  local variant=$1 app=$2 binary
  local -a extra
  binary=out/control; extra=()
  if [[ $variant != B ]]; then binary=${BENCH_REVISED_BINARY:-out/revised}; fi
  if [[ $variant == P ]]; then binary=$BENCH_NO_AUDIT_REFERENCE; fi
  if [[ $variant == N || $variant == P ]]; then extra=(-e AUDIT_CLIENT_CREDENTIALS_ISSUANCE=false); fi
  if ! docker inspect "$app" >/dev/null 2>&1; then
    docker create --name "$app" --network "$net" --network-alias oauthbench-api-audit \
      -v hotpath-nazo-data-revised:/var/lib/nazo_oauth --env-file ../private/revised.env \
      --log-opt max-size=16m --log-opt max-file=2 -e RUST_LOG=warn "${extra[@]}" \
      --entrypoint /affinity "$app_image" "$BENCH_APP_CPUS" /usr/local/bin/nazoauth server >/dev/null
    install_tools "$app"
  fi
  docker cp "$binary" "$app:/usr/local/bin/nazoauth"
}
relation_numbers() {
  local database=$1 dbid rel client_rel
  rel=$(docker exec -u postgres "$database" oid2name -d nazo_revised_ready -t security_audit_events | awk '$2=="security_audit_events"{print $1}')
  client_rel=$(docker exec -u postgres "$database" oid2name -d nazo_revised_ready -t oauth_clients | awk '$2=="oauth_clients"{print $1}')
  dbid=$(docker exec -u postgres "$database" oid2name | awk '$2=="nazo_revised_ready"{print $1}')
  [[ $rel =~ ^[0-9]+$ && $client_rel =~ ^[0-9]+$ && $dbid =~ ^[0-9]+$ ]]
  printf '%s %s %s\n' "$dbid" "$rel" "$client_rel"
}
point() {
  local label=$1 service=$2 database=$3 rate=$4 seconds=$5 vus=$6 scenario=${7:-machine}
  local output="$ROOT/results/$label.json"
  local lo hi dbid rel client_rel
  read -r dbid rel client_rel < <(relation_numbers "$database")

  (cd bench && BENCH_WINDOW_PG="$database" BENCH_NAZO_CONTAINER="$service" BENCH_VUS="$vus" \
    bash comparison-point.sh nazo "$scenario" "$rate" 10 "$seconds" "$output")
  lo=$(cat "$output.start-lsn"); hi=$(cat "$output.end-lsn")
  if [[ "$lo" == "$hi" ]]; then
    python3 count-wal.py "1663/$dbid/$rel" "$output" "1663/$dbid/$client_rel" </dev/null
  else
    docker exec -u postgres "$database" pg_waldump -s "$lo" -e "$hi" \
      | python3 count-wal.py "1663/$dbid/$rel" "$output" "1663/$dbid/$client_rel"
  fi
  jq -c '{whole_success,durable_token_issued,wal_committed_audit_rows,dropped_whole_trial,p95_ms,p99_ms,outcome}' "$output"
}
