#!/bin/bash
# Argon2 login controlled-concurrency test: oidc_cold_login_refresh at fixed VU levels.
set -u
cd /workspace
OUT=/workspace/perf-results/argon2
mkdir -p "$OUT"
DEP=$(docker compose -f docker-compose.perf.yml exec -T valkey redis-cli --scan --pattern "nazo:state:v1:*" | head -1 | cut -d: -f4)
for c in "$@"; do
  d="$OUT/cold-c${c}"; rm -rf "$d"; mkdir -p "$d"
  users=$(( c > 64 ? c : 64 ))
  echo "=== argon2 oidc_cold_login_refresh c=$c start $(date -u +%H:%M:%S)"
  docker compose -f docker-compose.perf.yml run --rm --no-deps \
    -v "$d":/out -e PERF_RESULTS_DIR=/out -e PERF_REPORT_PATH=/out/report.md \
    -e PERF_TENANT_HOST=127.0.0.1:8000 -e PERF_DEPLOYMENT_ID=$DEP \
    -e PERF_PROFILE=capacity -e PERF_SCENARIO=oidc_cold_login_refresh \
    -e PERF_EXECUTOR=constant-vus -e PERF_VUS="$c" -e PERF_FLOW_VUS="$c" \
    -e PERF_PRE_ALLOCATED_VUS="$c" -e PERF_MAX_VUS="$c" \
    -e PERF_DURATION=60s -e PERF_USER_COUNT="$users" \
    perf > "$d/run.log" 2>&1
  python3 - "$d/capacity-oidc-cold-login-refresh.summary.json" <<PY
import json,sys
try:
    d=json.load(open(sys.argv[1])); k=d["k6"]
    steps={s["step"]:s for s in d.get("steps",[])}
    lg=steps.get("login",{})
    print("  flows/s=%.2f reqs=%d err=%.4f login_p50=%s login_p95=%s login_p99=%s login_err=%s"%(
      k["rps"]/6, k["http_reqs"], k["error_rate"],
      lg.get("latency_ms",{}).get("p50"), lg.get("latency_ms",{}).get("p95"),
      lg.get("latency_ms",{}).get("p99"), lg.get("error_rate")))
except Exception as e:
    print("  ERR",e); print(open(sys.argv[1].replace(".summary.json","")+"/../run.log").read()[-300:] if False else "")
PY
  tail -3 "$d/run.log" | head -2
  [ -f /workspace/perf-results/STOP ] && break
done
echo ARGON2_DONE
