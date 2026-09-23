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
DEPID=$(docker exec nazoauth-perf-valkey-1 valkey-cli keys 'nazo:state:v1:*' | awk -F: 'NR==1{print $4}')
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

# ---------------- provenance (git -> image -> binary -> schema) ---------
# BENCHMARK_PROVENANCE gate: a formal run is only admissible when the
# source commit, the image built from it, the running binary hash and the
# applied schema are all captured here. No secrets are recorded.
{
  echo "--- source ---"
  echo "TEST_SOURCE_SHA=$(git -C /workspace rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "git_status_clean=$([ -z "$(git -C /workspace status --porcelain 2>/dev/null)" ] && echo yes || echo no)"
  echo "--- image ---"
  APP_IMAGE=$(docker inspect nazoauth-perf-nazoauth-1 --format '{{.Image}}' 2>/dev/null || echo unknown)
  echo "app_image_id=$APP_IMAGE"
  docker image inspect "$APP_IMAGE" --format 'repo_digest={{json .RepoDigests}}' 2>/dev/null || true
  docker inspect nazoauth-perf-nazoauth-1 --format 'base_image={{.Config.Image}}' 2>/dev/null || true
  echo "--- running binary ---"
  BIN=$(docker exec nazoauth-perf-nazoauth-1 sh -c 'readlink /proc/1/exe' 2>/dev/null || echo unknown)
  echo "binary_path=$BIN"
  echo "RUNNING_BINARY_SHA256=$(docker exec nazoauth-perf-nazoauth-1 sha256sum "$BIN" 2>/dev/null | cut -d' ' -f1 || echo unavailable)"
  echo "--- postgres ---"
  docker exec nazoauth-perf-postgres-1 psql -X -A -t -U postgres -d oauth -c "SELECT version()" 2>/dev/null | head -1 | sed 's/^/pg_version=/'
  for s in max_wal_size checkpoint_timeout checkpoint_completion_target fsync synchronous_commit full_page_writes shared_buffers max_connections; do
    v=$(docker exec nazoauth-perf-postgres-1 psql -X -A -t -U postgres -d oauth -c "SHOW $s" 2>/dev/null)
    echo "pg_$s=$v"
  done
  echo "--- migrations ---"
  echo "MIGRATION_SET_SHA256=$(find /workspace/migrations -type f -name '*.sql' | sort | xargs sha256sum 2>/dev/null | sha256sum | cut -d' ' -f1)"
  docker exec -i nazoauth-perf-postgres-1 psql -X -A -t -U postgres -d oauth -c "SELECT version FROM __diesel_schema_migrations ORDER BY version" 2>/dev/null > "$OUT/applied-migrations.txt" || true
  echo "applied_migrations=$(wc -l < "$OUT/applied-migrations.txt" 2>/dev/null || echo 0)"
  echo "APPLIED_MIGRATIONS_SHA256=$(sha256sum "$OUT/applied-migrations.txt" 2>/dev/null | cut -d' ' -f1 || echo unavailable)"
  # Canonical schema identity: deterministic catalog dump (sorted logical
  # schema, no OIDs/owners/ACLs). Raw pg_dump -s remains diagnostic only.
  docker exec -i nazoauth-perf-postgres-1 psql -X -v ON_ERROR_STOP=1 \
    -U postgres -d oauth -f - < "$TOOLS/canonical_schema.sql" \
    > "$OUT/canonical-schema.txt" 2>/dev/null || true
  echo "CANONICAL_PG_SCHEMA_SHA256=$(sha256sum "$OUT/canonical-schema.txt" 2>/dev/null | cut -d' ' -f1 || echo unavailable)"
  echo "PG_DUMP_SCHEMA_SHA256_DIAG=$(docker exec nazoauth-perf-postgres-1 sh -c 'pg_dump -U postgres -d oauth -s --no-owner --no-privileges 2>/dev/null | grep -v "^--" | grep -v "^$" | sha256sum | cut -d" " -f1' || echo unavailable)"
  echo "--- valkey ---"
  docker exec nazoauth-perf-valkey-1 sh -c 'valkey-cli INFO server 2>/dev/null | grep -E "redis_version|valkey_version" | head -1' 2>/dev/null | tr -d '\r' | sed 's/^/valkey_/'
  docker exec nazoauth-perf-valkey-1 sh -c 'valkey-cli CONFIG GET maxmemory 2>/dev/null | tail -1' 2>/dev/null | tr -d '\r' | sed 's/^/valkey_maxmemory=/'
  docker exec nazoauth-perf-valkey-1 sh -c 'valkey-cli CONFIG GET maxmemory-policy 2>/dev/null | tail -1' 2>/dev/null | tr -d '\r' | sed 's/^/valkey_maxmemory_policy=/'
  echo "--- harness ---"
  echo "k6=$(docker exec nazoauth-perf-perf-1 k6 version 2>/dev/null | head -1 || echo unavailable)"
  echo "python=$(python3 --version 2>&1)"
  echo "docker=$(docker --version 2>/dev/null)"
  echo "compose=$(docker compose version --short 2>/dev/null)"
  echo "--- host ---"
  echo "cpu_model=$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs)"
  echo "logical_cpus=$(nproc)"
  echo "mem_kb=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}')"
  echo "kernel=$(uname -r)"
  echo "rootfs=$(df -T /workspace 2>/dev/null | tail -1 | awk '{print $2" "$1}')"
} | tee -a "$MANIFEST" >>"$LOG" 2>/dev/null || echo "WARN: provenance capture partial" >>"$LOG"
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
    for c in $(docker ps --format '{{.Names}}' | grep -E 'perf-run-|soak-|nazoauth-perf-nazoauth'); do
      read rss utime <<<"$(docker exec "$c" sh -c 'r=0;u=0;for f in /proc/[0-9]*/stat; do set -- $(cat $f 2>/dev/null); [ -n "$3" ] && { u=$((u+${14}+${15})); }; done; for f in /proc/[0-9]*/status; do v=$(grep VmRSS $f 2>/dev/null | awk "{print \$2}"); r=$((r+v)); done; echo "$r $u"' 2>/dev/null)"
      [ -n "${rss:-}" ] && echo "{\"ts\":$ts,\"container\":\"$c\",\"rss_kb\":$rss,\"utime\":$utime}" >> "$OUT/runner-rss.jsonl"
    done
    sleep 15
  done
) &
RSSPID=$!
echo "runner rss sampler pid=$RSSPID $(date -u +%H:%M:%S)" >>"$LOG"

# ---------------- audit anchor export (optional mode, live evidence) ---
AUDIT_ENABLED=${SOAK_AUDIT:-1}
AUDITPID=""
if [ "$AUDIT_ENABLED" = "1" ]; then
  # `compose run` registers the *container* name as the network alias, not
  # the service name, so the receiver certificate is issued per run.
  RCV_NAME="soak-anchor-rcv-$RUN_ID"
  TLS_DIR=/workspace/perf-results/anchor-tls/$RUN_ID
  mkdir -p "$TLS_DIR"
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -keyout "$TLS_DIR/receiver.key" -out "$TLS_DIR/receiver.crt" \
    -subj "/CN=$RCV_NAME" \
    -addext "basicConstraints=CA:FALSE" \
    -addext "extendedKeyUsage=serverAuth" \
    -addext "subjectAltName=DNS:$RCV_NAME" >/dev/null 2>&1
  ANCHOR_TOKEN=$(openssl rand -hex 32)
  ANCHOR_SEED=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')
  # Dedicated least-privilege exporter role for the worker connection.
  docker exec -i nazoauth-perf-postgres-1 psql -X -v ON_ERROR_STOP=1 \
    -U postgres -d oauth </dev/null <<'SQL'
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nazoauth_perf_exporter') THEN
    CREATE ROLE nazoauth_perf_exporter LOGIN PASSWORD 'exporter' NOSUPERUSER NOBYPASSRLS NOINHERIT;
  END IF;
END $$;
GRANT CONNECT ON DATABASE oauth TO nazoauth_perf_exporter;
GRANT USAGE ON SCHEMA public TO nazoauth_perf_exporter;
GRANT EXECUTE ON FUNCTION
  public.nazo_security_audit_shared_privilege_preflight(BOOLEAN,BOOLEAN,BOOLEAN),
  public.nazo_persist_security_audit_event(UUID,TEXT,TEXT,JSONB,TIMESTAMPTZ),
  public.nazo_security_audit_chain_head_for_update(),
  public.nazo_security_audit_batch_members(),
  public.nazo_claim_security_audit_pending(BIGINT),
  public.nazo_open_security_audit_batch(BIGINT,BIGINT,INTEGER,BYTEA,INTEGER),
  public.nazo_reclaim_security_audit_batch(BYTEA,INTEGER),
  public.nazo_append_security_audit_chain(BIGINT,BYTEA,UUID[],BYTEA[]),
  public.nazo_ack_security_audit_batch(BIGINT,BIGINT,BIGINT,INTEGER,BYTEA,BYTEA,TEXT),
  public.nazo_fail_security_audit_batch(BIGINT,TIMESTAMPTZ,TEXT,BOOLEAN),
  public.nazo_observe_security_audit_anchor(TEXT),
  public.nazo_record_security_audit_genesis(TEXT,BYTEA),
  public.nazo_security_audit_shared_anchor_health()
TO nazoauth_perf_exporter;
SQL
  docker compose -f docker-compose.perf.yml run -d --name "$RCV_NAME" --no-deps \
    -e ANCHOR_RECEIVER_LISTEN=0.0.0.0:9443 \
    -e ANCHOR_RECEIVER_TLS_CERT="/run/anchor-tls/$RUN_ID/receiver.crt" \
    -e ANCHOR_RECEIVER_TLS_KEY="/run/anchor-tls/$RUN_ID/receiver.key" \
    -e ANCHOR_RECEIVER_DEPLOYMENT="$DEPID" \
    -e ANCHOR_RECEIVER_TOKEN="$ANCHOR_TOKEN" \
    -e ANCHOR_RECEIVER_SIGNING_KEY="$ANCHOR_SEED" \
    -e ANCHOR_RECEIVER_DATA_DIR=/data \
    audit-receiver >>"$LOG" 2>&1
  sleep 3
  VERIFY_KEY=$(docker logs "soak-anchor-rcv-$RUN_ID" 2>&1 | awk -F'pubkey=' 'NF>1{split($2,a,/[ \t]/); print a[1]; exit}')
  [ -n "$VERIFY_KEY" ] || { echo "FATAL: audit receiver pubkey unavailable" >>"$LOG"; exit 1; }
  docker compose -f docker-compose.perf.yml run -d --name "soak-anchor-worker-$RUN_ID" --no-deps \
    -e AUDIT_ANCHOR_MODE=optional \
    -e DEPLOYMENT_ID="$DEPID" \
    -e AUDIT_ANCHOR_URL="https://$RCV_NAME:9443/checkpoint" \
    -e AUDIT_ANCHOR_TOKEN="$ANCHOR_TOKEN" \
    -e AUDIT_ANCHOR_RECEIPT_VERIFY_KEY="$VERIFY_KEY" \
    -e AUDIT_ANCHOR_CA_BUNDLE="/run/anchor-tls/$RUN_ID/receiver.crt" \
    -e AUDIT_ANCHOR_DATABASE_URL=postgresql://nazoauth_perf_exporter:exporter@postgres:5432/oauth \
    -e AUDIT_ANCHOR_POLL_INTERVAL_SECONDS=2 \
    -e AUDIT_ANCHOR_BATCH_SIZE=256 \
    audit-worker >>"$LOG" 2>&1
  echo "audit anchor worker+receiver started depid=$DEPID $(date -u +%H:%M:%S)" >>"$LOG"
  (
    while :; do
      ts=$(date -u +%FT%TZ)
      row=$(docker exec -i nazoauth-perf-postgres-1 psql -X -A -t \
        -U postgres -d oauth </dev/null \
        -c "SELECT pending_estimate, anchor_sequence, (batch_blocked_reason IS NOT NULL) FROM public.nazo_security_audit_shared_anchor_health()" 2>/dev/null || echo ERR)
      horizon=$(docker exec -i nazoauth-perf-postgres-1 psql -X -A -t \
        -U postgres -d oauth </dev/null \
        -c "SELECT COALESCE(max(extract(epoch FROM now()-xact_start))::bigint,-1), COALESCE(max(age(backend_xmin)),-1) FROM pg_stat_activity WHERE xact_start IS NOT NULL" 2>/dev/null || echo ERR)
      echo "{\"ts\":\"$ts\",\"health\":\"$row\",\"horizon\":\"$horizon\"}" >> "$OUT/audit-health.jsonl"
      sleep 60
    done
  ) &
  AUDITPID=$!
  echo "audit health sampler pid=$AUDITPID $(date -u +%H:%M:%S)" >>"$LOG"
fi

# ---------------- main load --------------------------------------------
docker compose -f docker-compose.perf.yml run --rm --no-deps \
  -v "$OUT/main":/out \
  -e PERF_RESULTS_DIR=/out -e PERF_REPORT_PATH=/out/report.md \
  -e PERF_TENANT_HOST=127.0.0.1:8000 -e PERF_DEPLOYMENT_ID="$DEPID" \
  -e PERF_PROFILE=capacity -e PERF_SCENARIO=cap_mixed \
  -e PERF_EXECUTOR=constant-arrival-rate -e PERF_RATE="$RATE" \
  -e PERF_PRE_ALLOCATED_VUS=${SOAK_MAIN_PRE_VUS:-256} -e PERF_MAX_VUS=${SOAK_MAIN_MAX_VUS:-1024} \
  -e PERF_DURATION="$DUR_MAIN" -e CAP_WARMUP_MS=15000 \
  -e PERF_USER_COUNT=256 \
  perf > "$OUT/main/run.log" 2>&1 &
MAINPID=$!
echo "main cap_mixed arrival=${RATE}ops/s pid=$MAINPID $(date -u +%H:%M:%S)" >>"$LOG"

sleep 120

for side in argon2 meta fapi refresh; do
  case $side in
    argon2)  SC=oidc_cold_login_refresh;      SR=8;   PV=8;   MV=16;  UC=64 ;;
    meta)    SC=metadata_jwks;              SR=200; PV=16;  MV=32;  UC=64 ;;
    fapi)    SC=fapi2_logged_in_high_security; SR=30; PV=32;  MV=64;  UC=128 ;;
    refresh) SC=cap_refresh_token;          SR=${SOAK_REFRESH_RATE:-600}; PV=64; MV=256; UC=256 ;;
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
    -e PERF_VECTOR_COUNT=${PERF_VECTOR_COUNT:-2000} \
    perf >>"$LOG" 2>&1
  echo "$side sidecar arrival=$SR/s started $(date -u +%H:%M:%S)" >>"$LOG"
done

wait $MAINPID
echo "main finished $(date -u +%H:%M:%S)" >>"$LOG"
docker stop "soak-argon2-$RUN_ID" "soak-meta-$RUN_ID" "soak-fapi-$RUN_ID" "soak-refresh-$RUN_ID" "soak-sampler-$RUN_ID" >/dev/null 2>&1 || true
kill $RSSPID 2>/dev/null || true
[ -n "${AUDITPID:-}" ] && kill "$AUDITPID" 2>/dev/null || true

# ---------------- audit receiver evidence ------------------------------
# Keep worker running briefly so the outbox drains, then snapshot receiver
# counters and the final chain head for the report's integrity section.
if [ "${AUDIT_ENABLED:-0}" = "1" ]; then
  sleep 30
  docker compose -f docker-compose.perf.yml run --rm --no-deps \
    -v "/workspace/perf-results/anchor-tls:/run/anchor-tls:ro" \
    -e TOKEN="$ANCHOR_TOKEN" -e RCV_NAME="$RCV_NAME" -e RUN_ID="$RUN_ID" \
    --entrypoint python3 \
    perf -c '
import json, os, ssl, urllib.request
ctx = ssl.create_default_context(cafile="/run/anchor-tls/" + os.environ["RUN_ID"] + "/receiver.crt")
req = urllib.request.Request("https://" + os.environ["RCV_NAME"] + ":9443/__state")
req.add_header("Authorization", "Bearer " + os.environ["TOKEN"])
print(urllib.request.urlopen(req, context=ctx, timeout=10).read().decode())
' > "$OUT/audit-receiver-state.json" 2>>"$LOG" \
    || echo "WARN: receiver state capture failed" >>"$LOG"
  docker logs "soak-anchor-rcv-$RUN_ID" > "$OUT/audit-receiver.log" 2>&1 || true
  docker logs "soak-anchor-worker-$RUN_ID" > "$OUT/audit-worker.log" 2>&1 || true
  docker stop "soak-anchor-worker-$RUN_ID" "soak-anchor-rcv-$RUN_ID" >/dev/null 2>&1 || true
  docker rm "soak-anchor-worker-$RUN_ID" "soak-anchor-rcv-$RUN_ID" >/dev/null 2>&1 || true
fi

# ---------------- sampler output + validation ---------------------------
docker cp "soak-sampler-$RUN_ID":/tmp/soak-metrics.jsonl "$OUT/soak-metrics.jsonl" 2>/dev/null \
  || echo "WARN: sampler jsonl unavailable" >>"$LOG"
docker rm "soak-argon2-$RUN_ID" "soak-meta-$RUN_ID" "soak-fapi-$RUN_ID" "soak-refresh-$RUN_ID" "soak-sampler-$RUN_ID" >/dev/null 2>&1 || true
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

# Post-run canonical schema re-capture: must equal the pre-run fingerprint
# (schema is fixed at migration/startup; a drift here invalidates identity).
docker exec -i nazoauth-perf-postgres-1 psql -X -v ON_ERROR_STOP=1 \
  -U postgres -d oauth -f - < "$TOOLS/canonical_schema.sql" \
  > "$OUT/canonical-schema-post.txt" 2>/dev/null || true
{
  echo "CANONICAL_PG_SCHEMA_SHA256_POST=$(sha256sum "$OUT/canonical-schema-post.txt" 2>/dev/null | cut -d' ' -f1 || echo unavailable)"
  echo "end_utc=$(date -u +%FT%TZ)"
} | tee -a "$MANIFEST" >>"$LOG"
echo "SOAK_DONE RUN_ID=$RUN_ID $(date -u +%FT%TZ)" >>"$LOG"
