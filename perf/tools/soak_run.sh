#!/bin/bash
# Sustained endurance run. Main load is a CONSTANT-ARRIVAL-RATE cap_mixed at an
# explicit ops/s target derived from the verified clean ladder capacity
# (SOAK_RATE, default 2700 = ~75% of clean c32 ~3600 ops/s measured 2026-09-18).
# Sidecars run their own bounded arrival rates; every workload keeps its
# compact summary/errors artifacts under $OUT/<name>/.
cd /workspace
OUT=/workspace/perf-results/soak
mkdir -p "$OUT/main" "$OUT/argon2" "$OUT/meta" "$OUT/fapi"
LOG=$OUT/soak.log
DUR_MAIN=${SOAK_DURATION:-7200s}
DUR_SIDE=${SOAK_SIDE_DURATION:-7000s}
RATE=${SOAK_RATE:-2700}
DEPID=$(docker exec nazoauth-perf-valkey-1 valkey-cli keys 'nazo:state:v1:*' | head -1 | cut -d: -f4)
echo "soak start $(date -u +%FT%TZ) DEPID=$DEPID RATE=$RATE DUR=$DUR_MAIN" >> "$LOG"

# dependency counters at start (deadlocks delta evidence)
docker exec nazoauth-perf-postgres-1 psql -U postgres -d oauth -tc \
  "SELECT now() AT TIME ZONE 'utc', deadlocks, xact_commit, xact_rollback FROM pg_stat_database WHERE datname='oauth'" \
  > "$OUT/pg_counters_start.txt" 2>/dev/null
docker exec nazoauth-perf-valkey-1 valkey-cli info stats | grep -E "total_commands|keyspace_hits|keyspace_misses|expired" > "$OUT/valkey_counters_start.txt" 2>/dev/null

# in-network sampler: pg backends/stats + valkey INFO + app pool metrics (10s)
docker compose -f docker-compose.perf.yml run -d --name soak-sampler --no-deps \
  -v /workspace/perf/tools/soak_sampler.py:/tmp/sampler.py \
  perf python3 /tmp/sampler.py >> "$LOG" 2>&1
echo "sampler started $(date -u +%H:%M:%S)" >> "$LOG"

# host-side runner RSS/CPU sampler (docker stats is broken in nested cgroup v1)
(
  while :; do
    ts=$(date -u +%s)
    for c in $(docker ps --format '{{.Names}}' | grep -E 'perf-run-|soak-'); do
      read rss utime <<<"$(docker exec "$c" sh -c 'r=0;u=0;for f in /proc/[0-9]*/stat; do set -- $(cat $f 2>/dev/null); [ -n "$3" ] && { u=$((u+${14}+${15})); }; done; for f in /proc/[0-9]*/status; do v=$(grep VmRSS $f 2>/dev/null | awk "{print \$2}"); r=$((r+v)); done; echo "$r $u"' 2>/dev/null)"
      [ -n "${rss:-}" ] && echo "{\"ts\":$ts,\"container\":\"$c\",\"rss_kb\":$rss,\"utime\":$utime}" >> "$OUT/runner-rss.jsonl"
    done
    sleep 15
  done
) &
RSSPID=$!
echo "runner rss sampler started pid=$RSSPID $(date -u +%H:%M:%S)" >> "$LOG"

# main sustained load: cap_mixed at explicit arrival rate
docker compose -f docker-compose.perf.yml run --rm --no-deps \
  -v "$OUT/main":/out \
  -e PERF_RESULTS_DIR=/out -e PERF_REPORT_PATH=/out/report.md \
  -e PERF_TENANT_HOST=127.0.0.1:8000 -e PERF_DEPLOYMENT_ID="$DEPID" \
  -e PERF_PROFILE=capacity -e PERF_SCENARIO=cap_mixed \
  -e PERF_EXECUTOR=constant-arrival-rate -e PERF_RATE="$RATE" \
  -e PERF_PRE_ALLOCATED_VUS=96 -e PERF_MAX_VUS=256 \
  -e PERF_DURATION="$DUR_MAIN" -e CAP_WARMUP_MS=15000 \
  -e PERF_USER_COUNT=256 \
  perf > "$OUT/main/run.log" 2>&1 &
MAINPID=$!
echo "main cap_mixed arrival=${RATE}ops/s started pid=$MAINPID $(date -u +%H:%M:%S)" >> "$LOG"

sleep 120

# sidecar: Argon2 cold-login, low explicit arrival rate (~8 login/s attempted)
docker compose -f docker-compose.perf.yml run -d --name soak-argon2 --no-deps \
  -v "$OUT/argon2":/out \
  -e PERF_RESULTS_DIR=/out -e PERF_REPORT_PATH=/out/report.md \
  -e PERF_TENANT_HOST=127.0.0.1:8000 -e PERF_DEPLOYMENT_ID="$DEPID" \
  -e PERF_PROFILE=capacity -e PERF_SCENARIO=oidc_cold_login_refresh \
  -e PERF_SKIP_SEED=1 \
  -e PERF_EXECUTOR=constant-arrival-rate -e PERF_RATE=8 \
  -e PERF_PRE_ALLOCATED_VUS=8 -e PERF_MAX_VUS=16 \
  -e PERF_DURATION="$DUR_SIDE" -e CAP_WARMUP_MS=15000 \
  -e PERF_USER_COUNT=64 \
  perf >> "$LOG" 2>&1
echo "argon2 sidecar arrival=8/s started $(date -u +%H:%M:%S)" >> "$LOG"

# sidecar: metadata/jwks reads, explicit arrival rate
docker compose -f docker-compose.perf.yml run -d --name soak-meta --no-deps \
  -v "$OUT/meta":/out \
  -e PERF_RESULTS_DIR=/out -e PERF_REPORT_PATH=/out/report.md \
  -e PERF_TENANT_HOST=127.0.0.1:8000 -e PERF_DEPLOYMENT_ID="$DEPID" \
  -e PERF_PROFILE=capacity -e PERF_SCENARIO=metadata_jwks \
  -e PERF_SKIP_SEED=1 \
  -e PERF_EXECUTOR=constant-arrival-rate -e PERF_RATE=200 \
  -e PERF_PRE_ALLOCATED_VUS=16 -e PERF_MAX_VUS=32 \
  -e PERF_DURATION="$DUR_SIDE" -e CAP_WARMUP_MS=15000 \
  -e PERF_USER_COUNT=64 \
  perf >> "$LOG" 2>&1
echo "meta sidecar arrival=200/s started $(date -u +%H:%M:%S)" >> "$LOG"

# sidecar: FAPI2 logged-in high-security, modest explicit arrival rate
docker compose -f docker-compose.perf.yml run -d --name soak-fapi --no-deps \
  -v "$OUT/fapi":/out \
  -e PERF_RESULTS_DIR=/out -e PERF_REPORT_PATH=/out/report.md \
  -e PERF_TENANT_HOST=127.0.0.1:8000 -e PERF_DEPLOYMENT_ID="$DEPID" \
  -e PERF_PROFILE=capacity -e PERF_SCENARIO=fapi2_logged_in_high_security \
  -e PERF_SKIP_SEED=1 \
  -e PERF_EXECUTOR=constant-arrival-rate -e PERF_RATE=30 \
  -e PERF_PRE_ALLOCATED_VUS=32 -e PERF_MAX_VUS=64 \
  -e PERF_DURATION="$DUR_SIDE" -e CAP_WARMUP_MS=15000 \
  -e PERF_USER_COUNT=128 \
  perf >> "$LOG" 2>&1
echo "fapi sidecar arrival=30/s started $(date -u +%H:%M:%S)" >> "$LOG"

wait $MAINPID
echo "main finished $(date -u +%H:%M:%S)" >> "$LOG"
docker stop soak-argon2 soak-meta soak-fapi soak-sampler >/dev/null 2>&1
kill $RSSPID 2>/dev/null
docker rm soak-argon2 soak-meta soak-fapi soak-sampler >/dev/null 2>&1

# dependency counters at end
docker exec nazoauth-perf-postgres-1 psql -U postgres -d oauth -tc \
  "SELECT now() AT TIME ZONE 'utc', deadlocks, xact_commit, xact_rollback FROM pg_stat_database WHERE datname='oauth'" \
  > "$OUT/pg_counters_end.txt" 2>/dev/null
docker exec nazoauth-perf-valkey-1 valkey-cli info stats | grep -E "total_commands|keyspace_hits|keyspace_misses|expired" > "$OUT/valkey_counters_end.txt" 2>/dev/null

# copy sampler jsonl out of the shared volume
docker run --rm -v nazoauth-perf_perf_state:/s alpine cat /s/soak-metrics.jsonl > "$OUT/soak-metrics.jsonl" 2>/dev/null
echo "SOAK_DONE $(date -u +%FT%TZ)" >> "$LOG"
