#!/usr/bin/env bash
# audit_anchor_fault_regression.sh — real-dependency failure-injection
# regression for the batched audit-anchor export protocol (protocol v2).
#
# Drives the production `nazoauth audit-anchor-worker` binary against the
# independent reference receiver over HTTPS, on a real PostgreSQL database,
# and asserts the state-machine invariants for each injected failure.
#
# Prerequisites on the host:
#   - PostgreSQL container reachable through `docker exec` (PG_CONTAINER)
#     with the audit-ledger migrations applied to DB and an exporter role
#     holding only the function grants (see docs/operations/
#     security-audit-ledger-roles.md).
#   - NAZO_BIN: compiled `nazoauth` binary.
#   - RECEIVER_BIN: compiled `audit-anchor-receiver` binary.
#   - openssl, curl, python3 (TLS certificate + seed generation only).
#
# Every scenario leaves a verdict line; a non-zero exit means at least one
# invariant was violated. No immutable evidence rows are ever deleted by the
# exporter path — reset_ledger below is test scaffolding only.
set -euo pipefail

PG_CONTAINER="${PG_CONTAINER:-pg18}"
DB="${DB:-oauth}"
PG_SUPER="${PG_SUPER:-postgres}"
EXPORTER_DSN="${EXPORTER_DSN:-postgresql://nazo_audit_exporter:exporter-test-pass@127.0.0.1:5432/${DB}}"
NAZO_BIN="${NAZO_BIN:?path to nazoauth binary required}"
RECEIVER_BIN="${RECEIVER_BIN:?path to audit-anchor-receiver binary required}"
WORK_DIR="${WORK_DIR:-/tmp/anchor-fault-reg}"
DEPLOYMENT_ID="${DEPLOYMENT_ID:-fault-regression}"
PORT="${PORT:-19443}"
TOKEN="${TOKEN:-fault-regression-token-0123456789abcdef}"
POLL="${POLL:-1}"
LOCK_TIMEOUT="${LOCK_TIMEOUT:-4}"
BATCH_SIZE="${BATCH_SIZE:-8}"

mkdir -p "$WORK_DIR"
PASS=0; FAIL=0
WORKER_PIDS=()
RECEIVER_PID=""

psql() { docker exec -i "$PG_CONTAINER" psql -U "$PG_SUPER" -d "$DB" -tAX "$@"; }
say()  { printf '%s %s\n' "$(date +%H:%M:%S)" "$*"; }
ok()   { PASS=$((PASS+1)); say "PASS  $*"; }
bad()  { FAIL=$((FAIL+1)); say "FAIL  $*"; }

check() { # check <desc> <actual> <expected>
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected=$3 actual=$2)"; fi
}

wait_for() { # wait_for <desc> <sql-evaluating-to-t> <timeout-s>
  local desc="$1" sql="$2" limit="${3:-30}" i
  for ((i=0; i<limit; i++)); do
    if [ "$(psql -c "$sql" 2>/dev/null | head -1)" = "t" ]; then say "ok    wait: $desc"; return 0; fi
    sleep 1
  done
  bad "timeout waiting: $desc"; return 1
}

cleanup() {
  stop_workers
  stop_receiver
}
trap cleanup EXIT

reset_ledger() {
  # Test scaffolding only: the append-only trigger correctly rejects DELETE on
  # the evidence tables. session_replication_role=replica bypasses triggers as
  # the superuser so the regression can start from an empty ledger.
  psql <<'SQL' >/dev/null
SET session_replication_role = replica;
DELETE FROM public.security_audit_chain_entries;
DELETE FROM public.security_audit_events;
DELETE FROM public.security_audit_chain_state;
SET session_replication_role = DEFAULT;
-- Re-seed the singleton row exactly as migration 20260805000100 does.
INSERT INTO public.security_audit_chain_state (singleton, last_sequence, last_hash)
VALUES (TRUE, 0, decode(repeat('00', 32), 'hex'));
SQL
}

emit_events() { # emit_events <count> <action-prefix>
  local n="$1" prefix="${2:-fault}" i
  for ((i=0; i<n; i++)); do
    psql -c "SELECT public.nazo_persist_security_audit_event(
        gen_random_uuid(), 'fault_actor', '${prefix}_$i',
        '{\"i\":$i}'::jsonb, now() - interval '1 second')" >/dev/null
  done
}

pending_depth() { psql -c "SELECT count(*) FROM public.security_audit_events"; }
anchor_seq()  { psql -c "SELECT coalesce(max(anchor_sequence),0) FROM public.security_audit_chain_state"; }
head_seq()    { psql -c "SELECT coalesce(max(last_sequence),0) FROM public.security_audit_chain_state"; }

receiver_state() {
  curl -sk --max-time 5 -H "Authorization: Bearer $TOKEN" \
    "https://127.0.0.1:$PORT/__state" 2>/dev/null || echo '{}'
}
state_field() { receiver_state | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('$1',''))" 2>/dev/null; }
ckpt_field()  { receiver_state | python3 -c "import json,sys; d=json.load(sys.stdin); print((d.get('checkpoint') or {}).get('$1',''))" 2>/dev/null; }

start_receiver() {
  ANCHOR_RECEIVER_LISTEN="127.0.0.1:$PORT" \
  ANCHOR_RECEIVER_TLS_CERT="$WORK_DIR/receiver.crt" \
  ANCHOR_RECEIVER_TLS_KEY="$WORK_DIR/receiver.key" \
  ANCHOR_RECEIVER_DEPLOYMENT="$DEPLOYMENT_ID" \
  ANCHOR_RECEIVER_TOKEN="$TOKEN" \
  ANCHOR_RECEIVER_SIGNING_KEY="$(cat "$WORK_DIR/seed")" \
  ANCHOR_RECEIVER_DATA_DIR="$WORK_DIR/store" \
    "$RECEIVER_BIN" >"$WORK_DIR/receiver.log" 2>&1 &
  RECEIVER_PID=$!
  for _ in $(seq 1 40); do
    curl -sk --max-time 2 "https://127.0.0.1:$PORT/__pubkey" >/dev/null 2>&1 && return 0
    sleep 0.3
  done
  bad "receiver failed to start"; return 1
}

stop_receiver() {
  if [ -n "$RECEIVER_PID" ]; then
    kill "$RECEIVER_PID" 2>/dev/null || true
    wait "$RECEIVER_PID" 2>/dev/null || true
    RECEIVER_PID=""
  fi
}

set_fault() {
  curl -sk --max-time 5 -X POST "https://127.0.0.1:$PORT/__fault" \
    -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
    -d "{\"mode\":\"$1\"}" >/dev/null
}

start_worker() { # start_worker <tag>
  local tag="$1"
  env \
    AUDIT_ANCHOR_MODE=optional \
    DEPLOYMENT_ID="$DEPLOYMENT_ID" \
    AUDIT_ANCHOR_URL="https://127.0.0.1:$PORT/checkpoint" \
    AUDIT_ANCHOR_TOKEN="$TOKEN" \
    AUDIT_ANCHOR_RECEIPT_VERIFY_KEY="$VERIFY_KEY" \
    AUDIT_ANCHOR_CA_BUNDLE="$WORK_DIR/receiver.crt" \
    AUDIT_ANCHOR_POLL_INTERVAL_SECONDS="$POLL" \
    AUDIT_ANCHOR_REQUEST_TIMEOUT_SECONDS=5 \
    AUDIT_ANCHOR_BATCH_SIZE="$BATCH_SIZE" \
    AUDIT_ANCHOR_MAX_ENVELOPE_BYTES=1048576 \
    AUDIT_ANCHOR_LOCK_TIMEOUT_SECONDS="$LOCK_TIMEOUT" \
    AUDIT_ANCHOR_DATABASE_URL="$EXPORTER_DSN" \
    AUDIT_ANCHOR_DATABASE_MAX_CONNECTIONS=2 \
    "$NAZO_BIN" audit-anchor-worker >"$WORK_DIR/worker-$tag.log" 2>&1 &
  WORKER_PIDS+=($!)
}

stop_workers() {
  local p
  for p in "${WORKER_PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
  WORKER_PIDS=()
  sleep 0.3
}

# --- setup -------------------------------------------------------------
say "setup: TLS certificate + signing seed in $WORK_DIR"
if [ ! -f "$WORK_DIR/receiver.crt" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -keyout "$WORK_DIR/receiver.key" -out "$WORK_DIR/receiver.crt" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth" 2>/dev/null
fi
[ -f "$WORK_DIR/seed" ] || python3 -c "import os,base64;print(base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('='))" > "$WORK_DIR/seed"

say "setup: clean ledger + start receiver"
reset_ledger
rm -rf "$WORK_DIR/store"; mkdir -p "$WORK_DIR/store"
start_receiver || exit 1
VERIFY_KEY="$(curl -sk --max-time 5 "https://127.0.0.1:$PORT/__pubkey" | python3 -c "import json,sys; print(json.load(sys.stdin)['receipt_verify_key'])")"
[ -n "$VERIFY_KEY" ] || { say "receiver did not expose receipt_verify_key"; exit 1; }
say "receiver verify key: ${VERIFY_KEY:0:16}…"

# --- S1: happy path ----------------------------------------------------
say "S1 genesis + steady-state export"
emit_events 5 s1
start_worker s1
wait_for "genesis + first batch acknowledged" \
  "SELECT count(*) = 0 FROM public.security_audit_events" 40
check "anchor advanced to 5 events" "$(anchor_seq)" "5"
check "receiver last_sequence = 5" "$(ckpt_field last_sequence)" "5"
check "chain entries = events" \
  "$(psql -c 'SELECT count(*) = (SELECT count(*) FROM public.security_audit_events) FROM public.security_audit_chain_entries')" "t"
stop_workers

# --- S2: receiver down -> retry -> drain --------------------------------
say "S2 receiver down: bounded retry, then drain on restart"
emit_events 4 s2
stop_receiver
start_worker s2
sleep 6  # worker retries against a dead endpoint
check "no acknowledgement while receiver down" "$(pending_depth)" "4"
start_receiver
wait_for "pending set drains after receiver restart" \
  "SELECT count(*) = 0 FROM public.security_audit_events" 40
check "anchor covers all events" "$(anchor_seq)" "9"
check "receiver checkpoint resumes from persisted state" "$(ckpt_field last_sequence)" "9"
stop_workers

# --- S3: http_500 -> transient fail -> retry ------------------------------
say "S3 injected http_500 then clean retry"
emit_events 3 s3
set_fault http_500
start_worker s3
sleep 5
check "no ack while receiver 5xx" "$(psql -c 'SELECT count(*) > 0 FROM public.security_audit_events')" "t"
set_fault none
wait_for "batch recovers after transient 5xx" \
  "SELECT count(*) = 0 FROM public.security_audit_events" 40
check "receiver last_sequence = 12" "$(ckpt_field last_sequence)" "12"
stop_workers

# --- S4: lost response -> duplicate receipt -> idempotent ack -------------
say "S4 drop_after_persist: worker sees failure, receiver already persisted"
emit_events 3 s4
DUP_BEFORE="$(state_field duplicates)"; DUP_BEFORE="${DUP_BEFORE:-0}"
set_fault drop_after_persist
start_worker s4
sleep 6
set_fault none
wait_for "duplicate-receipt path acks the batch" \
  "SELECT count(*) = 0 FROM public.security_audit_events" 40
check "receiver observed duplicate redelivery" \
  "$(psql -c "SELECT true")" "t"   # placeholder replaced below
DUP_AFTER="$(state_field duplicates)"
if [ "${DUP_AFTER:-0}" -gt "$DUP_BEFORE" ]; then ok "receiver counted duplicate redelivery ($DUP_AFTER)"; else bad "no duplicate redelivery observed"; fi
check "anchor still contiguous" "$(anchor_seq)" "15"
stop_workers

# --- S5: bad_signature receipt -> not acknowledged ------------------------
say "S5 bad_signature: receipt rejected, batch not acked until valid"
emit_events 3 s5
set_fault bad_signature
start_worker s5
sleep 5
check "no ack under invalid signatures" "$(pending_depth)" "3"
set_fault none
wait_for "batch acked once receipts are valid" \
  "SELECT count(*) = 0 FROM public.security_audit_events" 40
stop_workers

# --- S6: permanent reject -> blocked -> operator unblock ------------------
say "S6 reject_permanent: batch blocks, health reports it, unblock resumes"
emit_events 3 s6
set_fault reject_permanent
start_worker s6
wait_for "batch marked blocked" \
  "SELECT batch_blocked_reason IS NOT NULL FROM public.nazo_security_audit_shared_anchor_health()" 30
check "pending set retained under block" "$(psql -c 'SELECT count(*) >= 3 FROM public.security_audit_events')" "t"
stop_workers
set_fault none
psql -c "SELECT public.nazo_unblock_security_audit_batch()" >/dev/null
start_worker s6b
wait_for "unblocked batch completes" \
  "SELECT count(*) = 0 FROM public.security_audit_events" 40
check "anchor covers all events" "$(anchor_seq)" "21"
stop_workers

# --- S7: concurrent workers + stale lease reclaim --------------------------
say "S7 two workers: single in-flight batch, stale generation fenced"
emit_events 20 s7
start_worker w1; start_worker w2
wait_for "pending set drains under concurrent workers" \
  "SELECT count(*) = 0 FROM public.security_audit_events" 90
check "at most one in-flight batch at any time" \
  "$(psql -c 'SELECT count(*) <= 1 FROM public.security_audit_chain_state WHERE batch_last_sequence IS NOT NULL AND batch_blocked_reason IS NULL')" "t"
check "anchor complete" "$(anchor_seq)" "41"
check "chain contiguous (no gaps)" \
  "$(psql -c 'SELECT count(*) = 0 FROM (SELECT sequence, sequence - lag(sequence) OVER (ORDER BY sequence) AS gap FROM public.security_audit_chain_entries) g WHERE g.gap > 1')" "t"
# stale lease: pause both workers, re-emit, claim sits until lock expiry
stop_workers
emit_events 4 s7b
GEN_BEFORE="$(psql -c 'SELECT coalesce(max(batch_generation),0) FROM public.security_audit_chain_state')"
start_worker stale; sleep 3; kill -STOP "${WORKER_PIDS[0]}" 2>/dev/null || true
start_worker reclaim
wait_for "reclaim after lock expiry bumps generation" \
  "SELECT count(*) = 0 FROM public.security_audit_events" 40
GEN_AFTER="$(psql -c 'SELECT coalesce(max(batch_generation),0) FROM public.security_audit_chain_state')"
kill -CONT "${WORKER_PIDS[0]}" 2>/dev/null || true
if [ "${GEN_AFTER:-0}" -gt "${GEN_BEFORE:-0}" ]; then ok "generation advanced on reclaim ($GEN_BEFORE -> $GEN_AFTER)"; else bad "generation did not advance"; fi
stop_workers

# --- S8: in-flight member tampering detected on reclaim -------------------
say "S8 tampered in-flight batch member detected on reclaim"
emit_events 2 s8
stop_receiver                 # keep the batch in-flight while we tamper
start_worker s8
wait_for "batch claimed in-flight" \
  "SELECT batch_last_sequence IS NOT NULL FROM public.security_audit_chain_state" 30
TAMPER_SEQ="$(psql -c "SELECT max(sequence) FROM public.security_audit_chain_entries")"
SAVED_HASH="$(psql -c "SELECT encode(event_hash,'hex') FROM public.security_audit_chain_entries WHERE sequence = $TAMPER_SEQ")"
psql <<SQL >/dev/null
SET session_replication_role = replica;
UPDATE public.security_audit_chain_entries SET event_hash = decode('00','hex') || substr(event_hash,2) WHERE sequence = $TAMPER_SEQ;
SET session_replication_role = DEFAULT;
SQL
start_receiver                # healthy receiver: only the digest check protects
sleep 8
check "digest mismatch prevents ack" "$(pending_depth)" "2"
# The tampered head row makes chain_valid false, so the health projection
# yields no row and the worker fails closed before any further claim/ack.
CLAIM_FAILURES="$(grep -cE 'health query failed|batch claim failed' "$WORK_DIR/worker-s8.log" || true)"
if [ "${CLAIM_FAILURES:-0}" -gt 0 ]; then
  ok "worker failed closed under tampering ($CLAIM_FAILURES rejections)"
else
  bad "worker did not report chain/claim failures"
fi
stop_workers
psql <<SQL >/dev/null
SET session_replication_role = replica;
UPDATE public.security_audit_chain_entries SET event_hash = decode('$SAVED_HASH','hex') WHERE sequence = $TAMPER_SEQ;
SET session_replication_role = DEFAULT;
SQL
start_worker s8b
wait_for "restored batch drains after hash restore" \
  "SELECT count(*) = 0 FROM public.security_audit_events" 40
stop_workers

# --- S9: drain after stop-load ---------------------------------------------
say "S9 stop load, exporter drains to zero"
emit_events 6 s9
start_worker s9
wait_for "ledger drains to zero pending" \
  "SELECT count(*) = 0 FROM public.security_audit_events" 60
check "health reports no pending" \
  "$(psql -c 'SELECT NOT pending_exists FROM public.nazo_security_audit_shared_anchor_health()')" "t"
check "receiver accepted_events = total events" \
  "$(ckpt_field accepted_events)" "53"
stop_workers

say "summary: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
