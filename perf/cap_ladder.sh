#!/bin/bash
# Capacity ladder orchestrator for perf/capacity-stress-20260915.
# Usage: cap_ladder.sh <scenario> [concurrency list] [duration] [warmup_ms]
set -u
cd /workspace
SCEN="$1"; LEVELS="${2:-8 16 32 64 128 256 512 1024}"
DUR="${3:-60s}"; WARM="${4:-15000}"
OUT=/workspace/perf-results/ladder
mkdir -p "$OUT"

sat() { docker run --rm python:3.12-alpine python -c "import sys;sys.exit(0 if ($1) else 1)"; }

prev_tps=0; low_growth=0; baseline_p99=0; saturated=0
for c in $LEVELS; do
  d="$OUT/${SCEN}-c${c}"
  rm -rf "$d"; mkdir -p "$d"
  echo "=== $SCEN c=$c $(date -u +%H:%M:%S) ==="
  users=$(( c > 64 ? c : 64 ))
  docker compose -f docker-compose.perf.yml run --rm --no-deps \
    -v "$d":/out \
    -e PERF_RESULTS_DIR=/out \
    -e PERF_REPORT_PATH=/out/report.md \
    -e PERF_TENANT_HOST=127.0.0.1:8000 -e PERF_DEPLOYMENT_ID=01a0a547-ec73-7383-ab7f-f2e49b373a08 \
    -e PERF_PROFILE=capacity -e PERF_SCENARIO="$SCEN" \
    -e PERF_EXECUTOR=constant-vus -e PERF_VUS="$c" \
    -e PERF_FLOW_VUS="$c" -e PERF_PRE_ALLOCATED_VUS="$c" -e PERF_MAX_VUS="$c" \
    -e PERF_DURATION="$DUR" -e CAP_WARMUP_MS="$WARM" \
    -e PERF_USER_COUNT="$users" \
    perf > "$d/run.log" 2>&1
  read tps errs p99 appcpu <<<"$(docker run --rm -v "$d":/r -v /workspace/cap_point.py:/cap_point.py python:3.12-alpine python /cap_point.py /r "$SCEN" 2>/dev/null)"
  if [ -z "${tps:-}" ]; then
    echo "  FAILED: no measured stats; see $d/run.log"; tail -5 "$d/run.log"
    [ -f /workspace/perf-results/STOP ] && break
    continue
  fi
  echo "  measured: ${tps} ops/s errors=${errs} p99=${p99}ms appcpu=${appcpu}%"
  [ "$baseline_p99" = "0" ] && baseline_p99="$p99"
  if sat "$errs>0 or $p99>2000 or ($baseline_p99>0 and $p99>5*$baseline_p99) or $appcpu>95"; then
    echo "  SATURATED: errors/latency/cpu threshold"; saturated=1; break
  fi
  if [ "$prev_tps" != "0" ]; then
    growth=$(docker run --rm python:3.12-alpine python -c "print(($tps-$prev_tps)/$prev_tps*100)")
    echo "  growth vs prev: ${growth}%"
    if sat "$growth<10"; then
      low_growth=$((low_growth+1))
    else
      low_growth=0
    fi
    if [ "$low_growth" -ge 2 ]; then echo "  SATURATED: two low-growth doublings"; saturated=1; break; fi
  fi
  prev_tps=$tps
  [ -f /workspace/perf-results/STOP ] && { echo "STOP file detected"; break; }
done
[ "$saturated" = "0" ] && echo "  $SCEN NOT SATURATED within tested envelope"
