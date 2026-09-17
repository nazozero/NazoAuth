#!/bin/bash
cd /workspace
OUT=/workspace/perf-results/ladder
mkdir -p "$OUT"
LOG=/workspace/perf-results/tier4.log
KEY=$(docker exec nazoauth-perf-valkey-1 valkey-cli keys 'nazo:state:v1:*' | head -1)
DEPID=$(echo "$KEY" | cut -d: -f4)
echo "DEPID=$DEPID" >> "$LOG"

point() {
  local SCEN=$1 C=$2
  local d="$OUT/${SCEN}-c${C}"
  rm -rf "$d"; mkdir -p "$d"
  local users=$(( C > 64 ? C : 64 ))
  echo "=== $SCEN c=$C start $(date -u +%H:%M:%S) ===" >> "$LOG"
  docker compose -f docker-compose.perf.yml run --rm --no-deps \
    -v "$d":/out \
    -e PERF_RESULTS_DIR=/out -e PERF_REPORT_PATH=/out/report.md \
    -e PERF_TENANT_HOST=127.0.0.1:8000 -e PERF_DEPLOYMENT_ID="$DEPID" \
    -e PERF_PROFILE=capacity -e PERF_SCENARIO="$SCEN" \
    -e PERF_EXECUTOR=constant-vus -e PERF_VUS="$C" \
    -e PERF_FLOW_VUS="$C" -e PERF_PRE_ALLOCATED_VUS="$C" -e PERF_MAX_VUS="$C" \
    -e PERF_DURATION=75s -e CAP_WARMUP_MS=15000 \
    -e PERF_USER_COUNT="$users" \
    perf > "$d/run.log" 2>&1
  python3 - "$d" "$SCEN" >> "$LOG" 2>/dev/null <<'PY'
import json,sys,glob
d,scen=sys.argv[1],sys.argv[2]
files=glob.glob(d+"/*.summary.json")
if not files: print("  -> NO SUMMARY"); sys.exit()
s=json.load(open(files[0]))
m=s["metrics"]
rps=m.get("http_reqs",{}).get("rate",0)
err=m.get("checks",{}).get("fails",0)
p99=m.get("http_req_duration",{}).get("p(99)",0)
iters=m.get("iterations",{}).get("count",0)
print(f"  -> {rps:.3f} ops/s errs={err} p99={p99:.2f}ms iters={iters}")
PY
}

arrival() {
  local SCEN=$1 R=$2 MV=$3
  local d="$OUT/${SCEN}-r${R}"
  rm -rf "$d"; mkdir -p "$d"
  echo "=== $SCEN rate=$R/s start $(date -u +%H:%M:%S) ===" >> "$LOG"
  docker compose -f docker-compose.perf.yml run --rm --no-deps \
    -v "$d":/out \
    -e PERF_RESULTS_DIR=/out -e PERF_REPORT_PATH=/out/report.md \
    -e PERF_TENANT_HOST=127.0.0.1:8000 -e PERF_DEPLOYMENT_ID="$DEPID" \
    -e PERF_PROFILE=capacity -e PERF_SCENARIO="$SCEN" \
    -e PERF_EXECUTOR=constant-arrival-rate -e PERF_RATE="$R" \
    -e PERF_PRE_ALLOCATED_VUS="$MV" -e PERF_MAX_VUS="$MV" \
    -e PERF_DURATION=75s -e CAP_WARMUP_MS=15000 \
    -e PERF_USER_COUNT=128 \
    perf > "$d/run.log" 2>&1
  python3 - "$d" "$SCEN" >> "$LOG" 2>/dev/null <<'PY'
import json,sys,glob
d,scen=sys.argv[1],sys.argv[2]
files=glob.glob(d+"/*.summary.json")
if not files: print("  -> NO SUMMARY"); sys.exit()
s=json.load(open(files[0]))
m=s["metrics"]
rps=m.get("http_reqs",{}).get("rate",0)
err=m.get("checks",{}).get("fails",0)
p99=m.get("http_req_duration",{}).get("p(99)",0)
iters=m.get("iterations",{}).get("count",0)
drop=m.get("dropped_iterations",{}).get("count",0)
print(f"  -> {rps:.3f} ops/s errs={err} p99={p99:.2f}ms iters={iters} dropped={drop}")
PY
}

for c in 8 32 64 128; do point mtls_client_credentials $c; done
for c in 16 64 128 256; do point metadata_jwks $c; done
for c in 8 32 64 128; do point cap_introspect $c; done
for c in 8 32; do point cap_revoke $c; done
for c in 8 32 64; do point cap_token_exchange $c; done
for c in 8 32 64; do point cap_authorization_code $c; done
for c in 16; do point same_user_refresh_token_rotation $c; done
for c in 16; do point same_user_introspect_opaque_refresh_token $c; done
arrival fapi2_logged_in_high_security 300 512
arrival fapi2_logged_in_high_security 600 512
echo "TIER4_DONE $(date -u +%H:%M:%S)" >> "$LOG"
