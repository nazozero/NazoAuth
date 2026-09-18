#!/bin/bash
cd /workspace
DEP=$(docker exec nazoauth-perf-valkey-1 valkey-cli keys "nazo:state:v1:*" | head -1 | cut -d: -f4)
OUT=/workspace/perf-results/composites
mkdir -p "$OUT"
run() {
  local scen=$1 rate=$2 dur=$3 vus=$4 users=$5
  d="$OUT/${scen}-r${rate}"; rm -rf "$d"; mkdir -p "$d"
  echo "=== $scen rate=$rate 02:45:57 ==="
  docker compose -f docker-compose.perf.yml run --rm --no-deps     -v "$d":/out -e PERF_RESULTS_DIR=/out -e PERF_REPORT_PATH=/out/report.md     -e PERF_TENANT_HOST=127.0.0.1:8000 -e PERF_DEPLOYMENT_ID="$DEP"     -e PERF_PROFILE=capacity -e PERF_SCENARIO="$scen"     -e PERF_EXECUTOR=constant-arrival-rate -e PERF_RATE="$rate"     -e PERF_PRE_ALLOCATED_VUS="$vus" -e PERF_MAX_VUS="$vus"     -e PERF_DURATION="$dur" -e CAP_WARMUP_MS=12000     -e PERF_USER_COUNT="$users"     perf > "$d/run.log" 2>&1
  tail -2 "$d/run.log" | head -1
}
run fapi2_logged_in_high_security 30 45s 48 128
run fapi2_logged_in_high_security 60 45s 64 128
run fapi2_logged_in_high_security 120 45s 96 128
run fapi2_logged_in_high_security 240 45s 160 192
run oidc_logged_in_authorization_code 200 45s 48 128
run oidc_logged_in_authorization_code 400 45s 64 128
run oidc_refresh_only 500 45s 64 128
run oidc_refresh_only 1000 45s 96 128
PERF_PROFILE=capacity run ciba_private_key_jwt_dpop_poll 60 45s 32 64
PERF_PROFILE=capacity run ciba_private_key_jwt_dpop_poll 120 45s 48 64
run authorize_par_session 200 45s 64 128
run same_user_refresh_token_rotation 200 45s 32 64
echo COMPOSITES_DONE
