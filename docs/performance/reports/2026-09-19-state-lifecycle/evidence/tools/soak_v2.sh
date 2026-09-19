#!/bin/bash
# Round-2 soak: patched image, RUN_ID isolated output, fixed harness.
# Usage: soak_v2.sh <rate> <dur_s> <run_id>
set -u
cd /workspace
RATE=${1:-2000}; DUR=${2:-7200}; RUNID=${3:-soak-v2}
OUT=/workspace/perf-results/$RUNID
mkdir -p "$OUT/main" "$OUT/argon2" "$OUT/meta" "$OUT/fapi"
LOG=$OUT/soak.log
DEPID=$(docker exec nazoauth-perf-valkey-1 valkey-cli keys "nazo:state:v1:*" | head -1 | cut -d: -f4)
IMG=$(docker inspect nazoauth-perf-nazoauth-1 --format "{{.Image}}")
GIT=$(git rev-parse HEAD)
{
  echo "soak start $(date -u +%FT%TZ) RUN_ID=$RUNID RATE=$RATE DUR=${DUR}s"
  echo "DEPID=$DEPID IMAGE=$IMG GIT=$GIT"
  docker exec nazoauth-perf-postgres-1 psql -U postgres -d oauth -c "SELECT count(*) AS tokens FROM oauth_tokens" -t
} >> "$LOG"

# state ledger pre-soak
docker exec nazoauth-perf-postgres-1 psql -U postgres -d oauth -f /dev/stdin < /tmp/ledger.sql > "$OUT/ledger-pre.txt" 2>&1 || true
docker exec nazoauth-perf-valkey-1 valkey-cli info stats > "$OUT/valkey-stats-pre.txt" 2>&1
docker exec nazoauth-perf-valkey-1 valkey-cli dbsize > "$OUT/valkey-dbsize-pre.txt" 2>&1

# proc sampler (runner RSS / app RSS / pg / vk, 2s)
rm -f /workspace/perf-results/STOP_SAMPLER
nohup /workspace/perf-results/proc_sampler.sh "$OUT/proc-stats.csv" > "$OUT/proc_sampler.log" 2>&1 &
echo "proc sampler pid=$! $(date -u +%H:%M:%S)" >> "$LOG"

# in-network sampler v2 (pg+valkey+pool+state backlog, 10s)
docker compose -f docker-compose.perf.yml run -d --name ${RUNID}-sampler --no-deps \
  -v /workspace/perf-results/soak_sampler_v2.py:/tmp/sampler.py \
  perf python3 /tmp/sampler.py >> "$LOG" 2>&1
echo "sampler started $(date -u +%H:%M:%S)" >> "$LOG"

# main sustained load: cap_mixed constant-arrival-rate
docker compose -f docker-compose.perf.yml run --rm --no-deps \
  -v "$OUT/main":/out \
  -e PERF_RESULTS_DIR=/out -e PERF_REPORT_PATH=/out/report.md \
  -e PERF_TENANT_HOST=127.0.0.1:8000 -e PERF_DEPLOYMENT_ID="$DEPID" \
  -e PERF_PROFILE=capacity -e PERF_SCENARIO=cap_mixed \
  -e PERF_EXECUTOR=constant-arrival-rate -e PERF_RATE=$RATE \
  -e PERF_PRE_ALLOCATED_VUS=256 -e PERF_MAX_VUS=512 \
  -e PERF_DURATION=${DUR}s -e CAP_WARMUP_MS=15000 \
  -e PERF_USER_COUNT=256 -e PERF_SKIP_SEED=1 \
  perf > "$OUT/main/run.log" 2>&1 &
MAINPID=$!
echo "main cap_mixed arrival=${RATE}ops/s started pid=$MAINPID $(date -u +%H:%M:%S)" >> "$LOG"

sleep 120

# sidecar: Argon2 cold-login (1 VU)
docker compose -f docker-compose.perf.yml run -d --name ${RUNID}-argon2 --no-deps \
  -v "$OUT/argon2":/out \
  -e PERF_RESULTS_DIR=/out -e PERF_REPORT_PATH=/out/report.md \
  -e PERF_TENANT_HOST=127.0.0.1:8000 -e PERF_DEPLOYMENT_ID="$DEPID" \
  -e PERF_PROFILE=capacity -e PERF_SCENARIO=oidc_cold_login_refresh \
  -e PERF_SKIP_SEED=1 \
  -e PERF_EXECUTOR=constant-vus -e PERF_VUS=1 \
  -e PERF_FLOW_VUS=1 -e PERF_PRE_ALLOCATED_VUS=1 -e PERF_MAX_VUS=1 \
  -e PERF_DURATION=$((DUR-400))s -e CAP_WARMUP_MS=15000 \
  -e PERF_USER_COUNT=64 \
  perf >> "$LOG" 2>&1
echo "argon2 sidecar started $(date -u +%H:%M:%S)" >> "$LOG"

# sidecar: metadata/jwks (4 VU)
docker compose -f docker-compose.perf.yml run -d --name ${RUNID}-meta --no-deps \
  -v "$OUT/meta":/out \
  -e PERF_RESULTS_DIR=/out -e PERF_REPORT_PATH=/out/report.md \
  -e PERF_TENANT_HOST=127.0.0.1:8000 -e PERF_DEPLOYMENT_ID="$DEPID" \
  -e PERF_PROFILE=capacity -e PERF_SCENARIO=metadata_jwks \
  -e PERF_SKIP_SEED=1 \
  -e PERF_EXECUTOR=constant-vus -e PERF_VUS=4 \
  -e PERF_FLOW_VUS=4 -e PERF_PRE_ALLOCATED_VUS=4 -e PERF_MAX_VUS=4 \
  -e PERF_DURATION=$((DUR-400))s -e CAP_WARMUP_MS=15000 \
  -e PERF_USER_COUNT=64 \
  perf >> "$LOG" 2>&1
echo "meta sidecar started $(date -u +%H:%M:%S)" >> "$LOG"

# sidecar: FAPI2 logged-in high-security 30/s (vectors offset 1200 < 3000 seeded)
docker compose -f docker-compose.perf.yml run -d --name ${RUNID}-fapi --no-deps \
  -v "$OUT/fapi":/out \
  -e PERF_RESULTS_DIR=/out -e PERF_REPORT_PATH=/out/report.md \
  -e PERF_TENANT_HOST=127.0.0.1:8000 -e PERF_DEPLOYMENT_ID="$DEPID" \
  -e PERF_PROFILE=capacity -e PERF_SCENARIO=fapi2_logged_in_high_security \
  -e PERF_SKIP_SEED=1 \
  -e PERF_EXECUTOR=constant-arrival-rate -e PERF_RATE=30 \
  -e PERF_PRE_ALLOCATED_VUS=64 -e PERF_MAX_VUS=64 \
  -e PERF_DURATION=$((DUR-400))s -e CAP_WARMUP_MS=15000 \
  -e PERF_USER_COUNT=128 \
  perf >> "$LOG" 2>&1
echo "fapi sidecar started $(date -u +%H:%M:%S)" >> "$LOG"

wait $MAINPID
echo "main finished $(date -u +%H:%M:%S)" >> "$LOG"
touch /workspace/perf-results/STOP_SAMPLER
docker stop ${RUNID}-argon2 ${RUNID}-meta ${RUNID}-fapi ${RUNID}-sampler >/dev/null 2>&1
docker rm ${RUNID}-argon2 ${RUNID}-meta ${RUNID}-fapi ${RUNID}-sampler >/dev/null 2>&1
docker run --rm -v nazoauth-perf_perf_state:/s alpine cat /s/soak-metrics-v2.jsonl > "$OUT/soak-metrics.jsonl" 2>/dev/null
docker exec nazoauth-perf-postgres-1 psql -U postgres -d oauth -f /dev/stdin < /tmp/ledger.sql > "$OUT/ledger-post.txt" 2>&1 || true
docker exec nazoauth-perf-valkey-1 valkey-cli info stats > "$OUT/valkey-stats-post.txt" 2>&1
docker exec nazoauth-perf-valkey-1 valkey-cli dbsize > "$OUT/valkey-dbsize-post.txt" 2>&1
echo "SOAK_DONE $(date -u +%FT%TZ)" >> "$LOG"
