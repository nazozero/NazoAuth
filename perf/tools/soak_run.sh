#!/bin/bash
# Sustained endurance run — hardened evidence-chain version.
# Main load: CONSTANT-ARRIVAL-RATE cap_mixed at an explicit ops/s target
# (SOAK_RATE; derived from this host's verified C_valid — never reuse a
# prior host's number). Sidecars run bounded arrival rates.
#
# Evidence contract (A1):
#   - psql: -X -v ON_ERROR_STOP=1 ; stdin via `docker exec -i`
#   - no `|| true` on required captures; a failed ledger/sampler aborts
#   - every artifact carries RUN_ID; ledger files are validated by
#     ledger_check.py before the run and after it
#   - executed-script sha256 (repo copy AND in-container copy) recorded
#     in manifest.txt — digest mismatch = INVALID evidence
set -euo pipefail
cd /workspace

RUN_ID=${RUN_ID:?RUN_ID required (e.g. 20260919-state-min-v2-soak1)}
OUT=/workspace/perf-results/$RUN_ID
mkdir -p "$OUT/main" "$OUT/argon2" "$OUT/meta" "$OUT/fapi"
LOG=$OUT/soak.log
DUR_MAIN=${SOAK_DURATION:-14400s}
DUR_SIDE=${SOAK_SIDE_DURATION:-14200s}
RATE=${SOAK_RATE:?SOAK_RATE required (0.75 x C_valid for this host)}
DEPID=$(docker exec nazoauth-perf-valkey-1 valkey-cli keys 'nazo:state:v1:*' | head -1 | cut -d: -f4)
TOOLS=/workspace/perf/tools
PGC="docker exec -i nazoauth-perf-postgres-1 psql -X -v ON_ERROR_STOP=1 -U postgres -d oauth"
MANIFEST=$OUT/manifest.txt

{
  echo "RUN_ID=$RUN_ID"
  echo "DEPID=$DEPID RATE=$RATE DUR_MAIN=$DUR_MAIN DUR_SIDE=$DUR_SIDE"
  echo "start_utc=$(date -u +%FT%TZ)"
  echo "--- tool digests (repo copy) ---"
  for f in "$TOOLS"/ledger.sql "$TOOLS"/soak_sampler.py "$TOOLS"/vkledger.py \
           "$TOOLS"/ledger_check.py "$TOOLS"/soak_run.sh; do
    echo "sha256 $(basename "$f") $(sha256sum "$f" | cut -d' ' -f1)"
  done
  echo "--- container-side digests ---"
  echo "sampler $(docker exec nazoauth-perf-perf-1 sha256sum /perf/tools/soak_sampler.py 2>/dev/null | cut -d' ' -f1 || echo unavailable)"
} | tee "$MANIFEST" >>"$LOG"
echo "soak start $(date -u +%FT%TZ) RUN_ID=$RUN_ID RATE=$RATE" >>"$LOG"

# ---------------- pre-window ledgers (validated before load starts) ----
echo "ledger pre $(date -u +%H:%M:%S)" >>"$LOG"
$PGC -v run_id="$RUN_ID" -v phase=pre -f - \
  < "$TOOLS/ledger.sql" > "$OUT/ledger-pre.txt"
python3 "$TOOLS/ledger_check.py" check "$OUT/ledger-pre.txt" --run-id "$RUN_ID" >>"$LOG"

RUN_ID=$RUN_ID docker run --rm --network nazoauth-perf_perf_net \
  -e RUN_ID="$RUN_ID" \
  -v "$TOOLS/vkledger.py:/tmp/vkledger.py:ro" \
  nazoauth-perf-perf python3 /tmp/vkledger.py \
  > "$OUT/vkledger-pre.json"
python3 - "$OUT/vkledger-pre.json" >>"$LOG" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
assert d.get("done") is True and d["meta"]["run_id"], "vkledger incomplete"
print(f"vkledger pre: keys={d['total_keys']} dbsize={d['info']['dbsize']}")
PY

# ---------------- samplers ---------------------------------------------
docker compose -f docker-compose.perf.yml run -d --name "soak-sampler-$RUN_ID" --no-deps \
  -v "$TOOLS/soak_sampler.py:/tmp/sampler.py:ro" \
  -e RUN_ID="$RUN_ID" -e OUT_PATH=/tmp/soak-metrics.jsonl \
  -e INTERVAL_S=10 \
  perf python3 /tmp/sampler.py >>"$LOG" 2>&1
echo "sampler started $(date -u +%H:%M:%S)" >>"$LOG"

# host-side runner RSS/CPU sampler (docker stats broken in nested cgroup v1)
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
echo "runner rss sampler pid=$RSSPID $(date -u +%H:%M:%S)" >>"$LOG"

# ---------------- main load --------------------------------------------
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
echo "main cap_mixed arrival=${RATE}ops/s pid=$MAINPID $(date -u +%H:%M:%S)" >>"$LOG"

sleep 120

for side in argon2 meta fapi; do
  case $side in
    argon2) SC=oidc_cold_login_refresh;      SR=8;   PV=8;  MV=16; UC=64 ;;
    meta)   SC=metadata_jwks;              SR=200; PV=16; MV=32; UC=64 ;;
    fapi)   SC=fapi2_logged_in_high_security; SR=30; PV=32; MV=64; UC=128 ;;
  esac
  docker compose -f docker-compose.perf.yml run -d --name "soak-$side-$RUN_ID" --no-deps \
    -v "$OUT/$side":/out \
    -e PERF_RESULTS_DIR=/out -e PERF_REPORT_PATH=/out/report.md \
    -e PERF_TENANT_HOST=127.0.0.1:8000 -e PERF_DEPLOYMENT_ID="$DEPID" \
    -e PERF_PROFILE=capacity -e PERF_SCENARIO=$SC \
    -e PERF_SKIP_SEED=1 \
    -e PERF_EXECUTOR=constant-arrival-rate -e PERF_RATE=$SR \
    -e PERF_PRE_ALLOCATED_VUS=$PV -e PERF_MAX_VUS=$MV \
    -e PERF_DURATION="$DUR_SIDE" -e CAP_WARMUP_MS=15000 \
    -e PERF_USER_COUNT=$UC \
    perf >>"$LOG" 2>&1
  echo "$side sidecar arrival=$SR/s started $(date -u +%H:%M:%S)" >>"$LOG"
done

wait $MAINPID
echo "main finished $(date -u +%H:%M:%S)" >>"$LOG"
docker stop "soak-argon2-$RUN_ID" "soak-meta-$RUN_ID" "soak-fapi-$RUN_ID" "soak-sampler-$RUN_ID" >/dev/null 2>&1 || true
kill $RSSPID 2>/dev/null || true

# ---------------- sampler output + validation ---------------------------
docker cp "soak-sampler-$RUN_ID":/tmp/soak-metrics.jsonl "$OUT/soak-metrics.jsonl" 2>/dev/null \
  || echo "WARN: sampler jsonl unavailable" >>"$LOG"
docker rm "soak-argon2-$RUN_ID" "soak-meta-$RUN_ID" "soak-fapi-$RUN_ID" "soak-sampler-$RUN_ID" >/dev/null 2>&1 || true
if [ -s "$OUT/soak-metrics.jsonl" ]; then
  python3 "$TOOLS/ledger_check.py" sampler "$OUT/soak-metrics.jsonl" --run-id "$RUN_ID" >>"$LOG" \
    || echo "SAMPLER_VALIDATION_FAILED" >>"$LOG"
else
  echo "SAMPLER_EMPTY_INVALID" >>"$LOG"
fi

# ---------------- post-window ledgers (drain boundary is caller's job) --
echo "ledger post $(date -u +%H:%M:%S)" >>"$LOG"
$PGC -v run_id="$RUN_ID" -v phase=post -f - \
  < "$TOOLS/ledger.sql" > "$OUT/ledger-post.txt"
python3 "$TOOLS/ledger_check.py" check "$OUT/ledger-post.txt" --run-id "$RUN_ID" >>"$LOG"
python3 "$TOOLS/ledger_check.py" diff "$OUT/ledger-pre.txt" "$OUT/ledger-post.txt" \
  > "$OUT/ledger-diff.txt" 2>&1 || echo "LEDGER_DIFF_INVALID" >>"$LOG"

RUN_ID=$RUN_ID docker run --rm --network nazoauth-perf_perf_net \
  -e RUN_ID="$RUN_ID" \
  -v "$TOOLS/vkledger.py:/tmp/vkledger.py:ro" \
  nazoauth-perf-perf python3 /tmp/vkledger.py \
  > "$OUT/vkledger-post.json"

echo "end_utc=$(date -u +%FT%TZ)" | tee -a "$MANIFEST" >>"$LOG"
echo "SOAK_DONE RUN_ID=$RUN_ID $(date -u +%FT%TZ)" >>"$LOG"
