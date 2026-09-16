#!/bin/bash
# A/B wait-event matrix: {cc,refresh} x {c8,c32} for one pool-recycling mode.
# Usage: AB_OUT=<dir under /workspace/perf-results> AB_TAG=<verified|fast> ./wait_ab.sh
set -euo pipefail
cd /workspace
OUT=/workspace/perf-results/${AB_OUT:?need AB_OUT}
rm -rf "$OUT"; mkdir -p "$OUT/sampler" "$OUT/runs"
rm -f "$OUT/sampler/STOP"

docker rm -f wsab >/dev/null 2>&1 || true
docker run -d --name wsab --network nazoauth-perf_perf_net \
  -v "$OUT/sampler:/shared" \
  -v /workspace/perf/wait_sampler.py:/w.py \
  --entrypoint python nazoauth-perf-perf /w.py >"$OUT/sampler.cid"

DEP=$(docker compose -f docker-compose.perf.yml exec -T valkey \
  redis-cli --scan --pattern 'nazo:state:v1:*' | head -1 | cut -d: -f4)
echo "deployment=$DEP mode=${AB_TAG:-?}" | tee "$OUT/meta.txt"

run_point() {
  local scenario=$1 vus=$2 tag=$3
  mkdir -p "$OUT/runs/$tag"
  echo "=== point $tag ($scenario vus=$vus) start $(date -u +%T)"
  docker compose -f docker-compose.perf.yml run --rm --no-deps \
    -v "$OUT/runs/$tag:/out" \
    -e PERF_RESULTS_DIR=/out \
    -e PERF_REPORT_PATH=/out/report.md \
    -e PERF_TENANT_HOST=127.0.0.1:8000 \
    -e PERF_DEPLOYMENT_ID=$DEP \
    -e PERF_PROFILE=capacity \
    -e PERF_SCENARIO=$scenario \
    -e PERF_EXECUTOR=constant-vus \
    -e PERF_VUS=$vus -e PERF_FLOW_VUS=$vus \
    -e PERF_PRE_ALLOCATED_VUS=$vus -e PERF_MAX_VUS=$vus \
    -e PERF_DURATION=90s \
    -e CAP_WARMUP_MS=15000 \
    -e CAP_MEASURE_START_MS=30000 \
    -e PERF_USER_COUNT=64 \
    perf > "$OUT/runs/$tag.log" 2>&1
  echo "=== point $tag done $(date -u +%T)"
  sleep 8
}

for c in 8 32; do run_point cap_client_credentials $c cc-c$c; done
for c in 8 32; do run_point cap_refresh_token    $c refresh-c$c; done

touch "$OUT/sampler/STOP"
sleep 2
docker logs wsab > "$OUT/sampler.log" 2>&1 || true
docker rm -f wsab >/dev/null 2>&1 || true
echo MATRIX_DONE
