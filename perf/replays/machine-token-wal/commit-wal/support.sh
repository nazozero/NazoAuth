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
point() {
  local label=$1 service=$2 database=$3 rate=$4 seconds=$5 vus=$6
  local output="$ROOT/results/$label.json"
  local lo hi rel
  rel=$(docker exec -u postgres "$database" oid2name -d nazo_revised_ready -t security_audit_events | awk '$2=="security_audit_events"{print $1}')
  local dbid
  dbid=$(docker exec -u postgres "$database" oid2name | awk '$2=="nazo_revised_ready"{print $1}')
  [[ $rel =~ ^[0-9]+$ && $dbid =~ ^[0-9]+$ ]]

  (cd bench && BENCH_WINDOW_PG="$database" BENCH_NAZO_CONTAINER="$service" BENCH_VUS="$vus" \
    bash comparison-point.sh nazo machine "$rate" 10 "$seconds" "$output")
  lo=$(cat "$output.start-lsn"); hi=$(cat "$output.end-lsn")
  docker exec -u postgres "$database" pg_waldump -s "$lo" -e "$hi" \
    | python3 count-wal.py "1663/$dbid/$rel" "$output"
  jq -c '{whole_success,durable_token_issued,wal_committed_audit_rows,dropped_whole_trial,p95_ms,p99_ms,outcome}' "$output"
}
