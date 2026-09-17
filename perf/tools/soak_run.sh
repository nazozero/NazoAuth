#!/bin/bash
cd /workspace
OUT=/workspace/perf-results/soak
mkdir -p "$OUT/main" "$OUT/argon2" "$OUT/meta" "$OUT/fapi"
LOG=$OUT/soak.log
DEPID=$(docker exec nazoauth-perf-valkey-1 valkey-cli keys 'nazo:state:v1:*' | head -1 | cut -d: -f4)
echo "soak start $(date -u +%FT%TZ) DEPID=$DEPID" >> "$LOG"

# in-network sampler: pg backends/stats + valkey INFO + app pool metrics (10s)
docker compose -f docker-compose.perf.yml run -d --name soak-sampler --no-deps \
  -v /workspace/perf-results/soak_sampler.py:/tmp/sampler.py \
  perf python3 /tmp/sampler.py >> "$LOG" 2>&1
echo "sampler started $(date -u +%H:%M:%S)" >> "$LOG"

# main sustained load: cap_mixed c=24 (~75% of max sustainable c=32)
docker compose -f docker-compose.perf.yml run --rm --no-deps \
  -v "$OUT/main":/out \
  -e PERF_RESULTS_DIR=/out -e PERF_REPORT_PATH=/out/report.md \
  -e PERF_TENANT_HOST=127.0.0.1:8000 -e PERF_DEPLOYMENT_ID="$DEPID" \
  -e PERF_PROFILE=capacity -e PERF_SCENARIO=cap_mixed \
  -e PERF_EXECUTOR=constant-vus -e PERF_VUS=24 \
  -e PERF_FLOW_VUS=24 -e PERF_PRE_ALLOCATED_VUS=24 -e PERF_MAX_VUS=24 \
  -e PERF_DURATION=9600s -e CAP_WARMUP_MS=15000 \
  -e PERF_USER_COUNT=256 \
  perf > "$OUT/main/run.log" 2>&1 &
MAINPID=$!
echo "main cap_mixed c=24 started pid=$MAINPID $(date -u +%H:%M:%S)" >> "$LOG"

sleep 120

# sidecar: Argon2 cold-login low background (1 VU ~ 9 login/s)
docker compose -f docker-compose.perf.yml run -d --name soak-argon2 --no-deps \
  -v "$OUT/argon2":/out \
  -e PERF_RESULTS_DIR=/out -e PERF_REPORT_PATH=/out/report.md \
  -e PERF_TENANT_HOST=127.0.0.1:8000 -e PERF_DEPLOYMENT_ID="$DEPID" \
  -e PERF_PROFILE=capacity -e PERF_SCENARIO=oidc_cold_login_refresh \
  -e PERF_SKIP_SEED=1 \
  -e PERF_EXECUTOR=constant-vus -e PERF_VUS=1 \
  -e PERF_FLOW_VUS=1 -e PERF_PRE_ALLOCATED_VUS=1 -e PERF_MAX_VUS=1 \
  -e PERF_DURATION=9200s -e CAP_WARMUP_MS=15000 \
  -e PERF_USER_COUNT=64 \
  perf >> "$LOG" 2>&1
echo "argon2 sidecar started $(date -u +%H:%M:%S)" >> "$LOG"

# sidecar: metadata/jwks
docker compose -f docker-compose.perf.yml run -d --name soak-meta --no-deps \
  -v "$OUT/meta":/out \
  -e PERF_RESULTS_DIR=/out -e PERF_REPORT_PATH=/out/report.md \
  -e PERF_TENANT_HOST=127.0.0.1:8000 -e PERF_DEPLOYMENT_ID="$DEPID" \
  -e PERF_PROFILE=capacity -e PERF_SCENARIO=metadata_jwks \
  -e PERF_SKIP_SEED=1 \
  -e PERF_EXECUTOR=constant-vus -e PERF_VUS=4 \
  -e PERF_FLOW_VUS=4 -e PERF_PRE_ALLOCATED_VUS=4 -e PERF_MAX_VUS=4 \
  -e PERF_DURATION=9200s -e CAP_WARMUP_MS=15000 \
  -e PERF_USER_COUNT=64 \
  perf >> "$LOG" 2>&1
echo "meta sidecar started $(date -u +%H:%M:%S)" >> "$LOG"

# sidecar: FAPI2 logged-in high-security at modest fixed rate
docker compose -f docker-compose.perf.yml run -d --name soak-fapi --no-deps \
  -v "$OUT/fapi":/out \
  -e PERF_RESULTS_DIR=/out -e PERF_REPORT_PATH=/out/report.md \
  -e PERF_TENANT_HOST=127.0.0.1:8000 -e PERF_DEPLOYMENT_ID="$DEPID" \
  -e PERF_PROFILE=capacity -e PERF_SCENARIO=fapi2_logged_in_high_security \
  -e PERF_SKIP_SEED=1 \
  -e PERF_EXECUTOR=constant-arrival-rate -e PERF_RATE=60 \
  -e PERF_PRE_ALLOCATED_VUS=64 -e PERF_MAX_VUS=64 \
  -e PERF_DURATION=9200s -e CAP_WARMUP_MS=15000 \
  -e PERF_USER_COUNT=128 \
  perf >> "$LOG" 2>&1
echo "fapi sidecar started $(date -u +%H:%M:%S)" >> "$LOG"

wait $MAINPID
echo "main finished $(date -u +%H:%M:%S)" >> "$LOG"
docker stop soak-argon2 soak-meta soak-fapi soak-sampler >/dev/null 2>&1
docker rm soak-argon2 soak-meta soak-fapi soak-sampler >/dev/null 2>&1
# copy sampler jsonl out of the shared volume
docker run --rm -v nazoauth-perf_perf_state:/s alpine cat /s/soak-metrics.jsonl > "$OUT/soak-metrics.jsonl" 2>/dev/null
echo "SOAK_DONE $(date -u +%FT%TZ)" >> "$LOG"
