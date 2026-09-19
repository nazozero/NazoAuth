# NazoAuth State-Minimization Correction & Revalidation

**Run ID:** `20260919-df536d79-state-min`
**Baseline source SHA:** `df536d791f92f634b9d44a1ed0037f74a1c069e7` (GitHub/CNB `main`, prior state-lifecycle commit)
**Patched source:** this commit (see §3); second code-level correction pass over the state-lifecycle findings
**Deployment ID (perf DB anchor):** `maint-dep`
**Date:** 2026-09-19 (all times UTC)
**Prior references:** `docs/performance/reports/2026-09-19-state-lifecycle/report.md`, `docs/performance/reports/2026-09-18-capacity-endurance/`

## 0. Scope statement

This round is a **first-principles audit and minimization** of the durable and transient state produced per logical OAuth operation — not a capacity re-pursuit. The goal: how much PostgreSQL state, how many writes/index writes/WAL bytes/cleanup writes, and how much long-term retained state one logical operation creates, and whether every retained byte is either necessary business/security state, immutable audit evidence, or explicitly bounded temporary state. All numbers are topology-specific (single app container, co-located PostgreSQL 18.6 + Valkey 8 + k6 2.2.0 + a stub audit anchor).

## 1. Correction items — status

| # | Item | Status | Evidence |
|---|---|---|---|
| A | Refresh-token family authority paths not consistently tenant-scoped (cleanup, active-successor check, unlink, delete) | **Confirmed & fixed** | §3.1, §6.1 |
| B | Whole-family reclaim falsely bounded: a single statement could affect an unbounded row count; ordering could starve progress under timestamp ties | **Confirmed & fixed** | §3.2, §6.2 |
| C | Exported audit-outbox rows kept 1-day grace with no reader — pure durable garbage | **Confirmed & fixed** | §3.3, §6.3 |
| D | Two durable audit ledger rows per refresh rotation (`token_issued` + `refresh_rotated`) — write amplification | **Confirmed & fixed** | §3.4 |
| E | Authorization-code consumed marker carried a redundant `consumed_at` timestamp | **Confirmed & fixed (payload-only)** | §3.5, §6.4 |
| F | `audit-anchor-worker` initialized no tracing subscriber — all operational logs lost (silent exporter) | **Confirmed & fixed** | §3.6, §7.1 |
| G | Exporter drain capacity vs event rate — per-event checkpoint on a singleton chain serializes far below soak event rate | **Measured; capacity finding, not a leak** | §7.2 |
| H | Measurement tooling referenced removed `exported_at` column / ledger snapshots silently empty (`docker exec` missing `-i`) | **Fixed** | §8 |

## 2. Environment

| Item | Value |
|---|---|
| Host | CNB dev container (nested container runtime), ~192 logical CPUs, ~128 GiB RAM |
| App | `nazoauth-perf-nazoauth-1`, single container, image `98ff0a2aba58` (this commit) |
| DB | PostgreSQL 18.6 (`nazoauth-perf-postgres-1`), pg_stat_statements on |
| Cache/state | Valkey 8.x (`nazoauth-perf-valkey-1`), maxmemory=0 |
| Load gen | k6 2.2.0 (`nazoauth-perf-perf`), constant-arrival-rate `cap_mixed` |
| Audit anchor | Local TLS stub (`python3 asyncio`, always 200) at `https://172.17.0.4:8902/anchor`; 6 exporter workers (`nzanchor1-6`), `AUDIT_ANCHOR_BATCH_SIZE=256`, `SSL_CERT_FILE` pointed at the stub CA |
| Exporter DB role | `nazoauth_exporter` (least-privilege: 8 function EXECUTEs, no table grants, non-superuser) |

## 3. Changes applied (this commit)

### 3.1 Tenant boundaries on all family-authority paths

`crates/persistence-postgres/src/repositories/security_state.rs`: every refresh-token family operation — expired-family scan, active-successor existence check, unlink of outside references, closed-set delete — now filters on **both** `tenant_id` and `token_family_id`. Family IDs are not globally unique; without the tenant conjunct, identically-named families in other tenants could block or be affected by reclaim. The advisory lock key remains the family ID alone (lock-domain compatible with writers: it only serializes same-named families across tenants; it grants no cross-tenant visibility). New regression test builds a real second tenant (tenant+realm+organization+user+client fixture rows) with the same `token_family_id` and asserts isolation in both directions.

### 3.2 Truly bounded whole-family reclaim

Previously the "bounded" whole-family delete could affect an unbounded number of rows in one statement, and with all-equal `issued_at` values the candidate order could pick a batch of permanently blocked ancestors → 0-progress batch → premature "converged".

Now, per batch, inside one transaction on one guarded connection:

1. **Bounded unlink** — `rotated_from_id` cleared on up to `remaining` outside references.
2. **Closed-set delete** on a fresh snapshot — a recursive `blocked` CTE marks every doomed row that is directly or transitively referenced by a surviving row; only unblocked rows are deleted, so the self-FK can never dangle (reproduced live: 300-node same-`issued_at` chain previously violated `fk_oauth_tokens_rotated_from`; now drains cleanly 256+44).

Candidate ordering for **both** statements: `issued_at DESC`, then a leaf-existence tiebreak (`NOT EXISTS` a referrer within the family), then `id` — the newest layer of any finite same-timestamp DAG contains a sink, so every batch makes progress even under pathological timestamp ties; production chains (issued_at increasing along the chain) still take the newest-256 closed set per batch.

Verified: a 10,000-member chain plus a 1,001-member star/anomaly family drains completely in bounded batches (`total_deleted=11001, residual=0`), each `cleanup_batch` ≤ 256 rows.

### 3.3 Audit outbox — acknowledgement *is* deletion

Migration `20260919000200_audit_outbox_ack_delete` replaces the 1-day exported grace with same-transaction removal. `nazo_ack_security_audit_event(event_id, expected_attempts, deployment_id)`:

- validates deployment identity against the singleton anchor state,
- requires the chain entry to exist,
- `DELETE`s the outbox row only when event_id **and** attempts **and** `locked_at IS NOT NULL` all match — stale or already-terminal claims delete nothing and return `FALSE`,
- advances the anchor checkpoint (`anchor_sequence/hash/occurred_at/accepted_at`) in the same statement,
- never touches immutable `security_audit_events` / `security_audit_chain_entries` evidence.

The `exported_at` column, its partial index, and the exported-retention cleanup function/category are removed (`down.sql` restores them). Once a checkpoint is accepted, the delivery row has **no reader** — keeping it was retained bookkeeping garbage with zero consumers. Regression test: successful ACK removes the row; wrong attempt fence preserves it; reschedule preserves it; stale claim rejected; events+chains intact.

### 3.4 Audit ledger write amplification

`refresh_rotated` is removed as a separate durable event. Rotation lineage is carried on the single `token_issued` event via `rotated_from_id` in the payload — one ledger row + one outbox row + (at claim time) one chain append per issuance instead of two of each. Unit tests assert: normal issuance → `token_issued` only; rotated issuance → `token_issued` with `rotated_from_id`; no second ledger row. This removes 2 durable writes + index writes + WAL per refresh-token rotation op.

### 3.5 Authorization-code consumed-marker payload

`ConsumedAuthorizationCode.consumed_at` is removed (`crates/authorization-server-core/src/transaction.rs`, `token_service.rs`). The timestamp duplicated information already implied by the marker's existence and TTL. **The marker record itself is retained by contract**: `{client_id, redemption_binding, access_token_jti, access_token_expires_at, refresh_token_family_id}` at `consumed_state_ttl_seconds` = initial refresh-token TTL when family-bound (≈30 d in this deployment), else access-token TTL — the replay→family-revocation evidence window (see prior report §4.2 threat model). This change shrinks the marker ~30 B/record; it does **not** change retention, which is a deliberate contract decision, not a leak. Tests updated (`replay.rs`, `authorization_code.rs`).

### 3.6 Exporter observability

`run_audit_anchor_worker` (cli.rs) never installed a tracing subscriber — every `tracing::warn!/info!` in the worker loop went to a black hole; the exporter was un-diagnosable in production. `bootstrap::observability::init(&config)` is now called on this path (module visibility widened to `pub(crate)`). Verified live: with `RUST_LOG=info` the worker emits health/claim/anchor lifecycle logs, including `audit ledger checkpoint accepted by independent sink` per delivery.

## 4. Exporter topology findings

### 4.1 What the exporter actually does

Serial loop per worker: `anchor_health` (gated on `chain_valid`) → `observe_anchor` → `claim_due(batch, lock_timeout)` (transaction: chain-head `FOR UPDATE` + `nazo_claim_security_audit_events` + `nazo_append_security_audit_chain` for rows lacking chain entries) → per delivery: `POST` checkpoint → `nazo_ack_security_audit_event` (ACK=delete, §3.3) → on failure reschedule with `2^(attempts-1)`s backoff (max 300 s). `SKIP LOCKED` makes claims safe across N workers.

### 4.2 Chain-validity gate

`anchor_health` filters `WHERE chain_valid`: head must equal `chain_state.last_sequence/last_hash`. On a DB whose chain entries were populated outside `nazo_append_security_audit_chain` (fixtures, writer-side history), `last_sequence=0` vs real head → `chain_valid=false` → health returns **zero rows** → worker retries forever, never claims. Not a functional defect under normal operation (append maintains the invariant atomically), but a recovery caveat: after out-of-band chain repair, `last_sequence/last_hash` must be reconciled before the exporter can start.

### 4.3 Deployment notes (measured)

- `rustls-platform-verifier` loads the **system** root set (observed: 151 roots). A self-signed stub CA must be presented via `SSL_CERT_FILE`/`SSL_CERT_DIR` or an openssl-hash-linked file inside the cert dir; a bare file bind-mounted over `ca-certificates.crt` is *not* enough by itself.
- The stub presents a proper chain: root CA (`CA:TRUE`) → server cert (`CA:FALSE`, `keyUsage=digitalSignature`, `EKU=serverAuth`, `SAN=IP:172.17.0.4`). A CA:TRUE self-signed cert used directly as the end-entity is not accepted by webpki.

## 5. Functional verification

| Suite | Result |
|---|---|
| `security_state_maintenance` (13 tests incl. cross-tenant same-family, 10k+1k chain/star bounded reclaim, ACK-delete semantics, OID4VP, pool-discard) | **13/13 pass** (remote PG; app maintenance worker `SIGSTOP`-isolated to keep shared-DB fixtures deterministic) |
| `audit_ledger` + related persistence tests | pass |
| `migrations` suite (isolated-schema + public-only exclusion list updated for the two new public-only audit migrations) | **22/22 pass** |
| `nazoauth` lib unit tests | change-adjacent suites pass (55); full `--lib` run: 1234 pass / 51 fail — **all 51 environment-gated** (`NAZO_TEST_DATABASE_URL NotPresent` / Valkey `Unavailable` panics in DB-backed tests; the container lacked those services). None touch the changed paths |
| `access_token_retention`, `token_issuance_atomicity`, query-count suites | pass (6+4+…) |
| Fresh migration | 77 migrations applied on scratch DB; `20260919000200` head; ACK function contains same-transaction `DELETE` (verified via `pg_get_functiondef`) |
| Upgrade migration | applied on the live perf DB (the upgrade path exercised before image rebuild) |

Non-determinism note for future runs: the app container's maintenance worker consumes shared-DB fixtures; freeze it (`docker kill --signal=SIGSTOP`) or isolate the DB for integration suites.

## 6. Runtime evidence

### 6.1 Tenant isolation

Regression test: same `token_family_id` in two fully-populated tenants — cleanup in tenant A does not observe, unlink, or delete tenant-B rows, and vice versa.

### 6.2 Bounded closed-set reclaim

- 3-node chain with identical `issued_at`: previously `fk_oauth_tokens_rotated_from` violation; now batch1 unlinks 37 + deletes 256, batch2 deletes 44 → family empty, no FK error.
- 10,000-member chain + 1,001-member star: `total_deleted=11001, residual=0`; every batch ≤256 rows.

### 6.3 ACK atomicity

`security_audit_event_outbox` after ACK: row physically gone in the same commit that advances `anchor_sequence`. Verified end-to-end through the real worker (§7).

### 6.4 Exporter end-to-end (measured)

| Metric | Value |
|---|---|
| Workers | 6 × `nzanchor*`, batch=256, poll=1 s |
| Single delivery latency (POST+ACK inside claimed batch) | ~1–3 ms/event observed in worker logs |
| Aggregate drain, idle DB, batch=64 | ~126 events/s |
| Aggregate drain, idle DB, batch=256 | ~290–470 events/s (accelerates as backlog shrinks) |
| Aggregate drain under 2500 ops/s load | ~230 events/s |
| Serialization ceiling | singleton chain-head `FOR UPDATE` per claim batch — adding workers yields diminishing returns; per-event checkpoint protocol is the bound |

Event rate under load: ~2,780 events/s at 2,500 ops/s (~1.11 durable events per logical op, post-§3.4 merge).

**Consequence:** at 2000 ops/s the ledger produces ~2,400–2,500 events/s while this exporter topology drains ≲500/s → the outbox is **export-flow-controlled**: it grows ~2,000 rows/s under sustained load and drains when the sink is faster or load drops. This is a capacity/cost property of the per-event checkpoint design (one chain append + one HTTP POST + one ACK delete per event, serialized on the singleton chain head), not a leak — rows are never retained past ACK; the immutable ledger itself is the permanent state. To make outbox near-zero in steady state at this event rate the protocol needs batched checkpoints (or a sharded chain head), which is a design decision beyond this pass.

## 7. Throughput verification (post-fix image)

| Run | Iterations | Rate | Errors | Drops | p50 | p95 | p99 |
|---|---|---|---|---|---|---|---|
| short @2000 (10 min) | 1,195,749 | 2000.00 iters/s | 0.000000 | 4,251 dropped; 0 interrupted | 4.17 ms | 11.35 ms | 93.58 ms |
| short @2500 (10 min) | 1,491,192 | 2500.00 iters/s | 0.000000 | 8,809 dropped; 0 interrupted | — | 11.95 ms | 81.66 ms |
| **2 h soak @2000** | **14,382,058** | **2000.00 iters/s** | **0.000000** | **17,943 dropped (2.49% of k6 arrival-rate schedule); 0 interrupted** | **4.45 ms** | **10.61 ms** | **22.90 ms** |

The 2 h soak sustained exactly the target rate for the full duration with **zero request errors and zero business errors**. k6 reported **17,943 dropped iterations** (arrival-rate scheduling backlog when no VU was free — a harness capacity signal, not an application error) and **0 interrupted**. Compare the previous soak: **432,644 dropped (≈3.0% of ~14.4 M — the earlier report's "0.31%" was a miscount and is corrected here)**, a ~9-minute contention window and p99 88 ms; this run has no degraded tail (p99 22.9 ms).

Auxiliary measurements: HTTP RPS 2,905 (1.45 req/iter); k6 `db_calls` = 279,140,501 → **19.4 DB statements/logical op**; Valkey 53.1M hits vs 104.7K misses (~99.8% hit).

## 8. Amplification accounting (2 h soak @2000 ops/s, 14.38 M logical ops)

### 8.1 Per-logical-op durable state

| Measure | Value | Evidence |
|---|---|---|
| Durable audit events/op | **~1.08** | `security_audit_events` +15.47 M over soak window; breakdown: `token_issued` 10.43 M (2.17 M carrying `rotated_from_id`), `authorization_decision_intent`+`authorization_approved` 2×2.39 M, `login_success` 45 K |
| OAuth token rows/op | ~0.36 | `oauth_tokens` 226 K → 5.46 M over the metrics window |
| Issuance-record rows | +95 K | `oauth_token_issuances` 402.8 K → 497.7 K |
| DB statements/op | ~19.4 | k6 `db_calls` |
| WAL bytes/op | **~8.0–8.2 KB** | `pg_stat_wal.wal_bytes`: 186.55 GB → 298.59 GB over 13.74 M iters |
| Chain appends | +125 K | `security_audit_chain_entries` 154 K → 280 K (exporter-side, one per delivered event) |
| Outbox ACK deletes | ~1.1 M/day-equivalent | outbox rows are DELETEd on ACK — every delivered event costs 1 insert + 1 delete + 1 anchor-state update on the singleton row |

### 8.2 Write amplification per event type

- `token_issued` (post-§3.4): **1 events row + 1 outbox row + 1 chain insert (at claim) + 1 outbox DELETE + ~6 index writes** per issuance — down from 2 of each for rotations.
- `authorization_decision_intent` + `authorization_approved` (2.39 M pairs): **remaining same-class amplification** — two durable rows+outbox+chains per authorize op (~31% of audit volume). Unlike `refresh_rotated`, the intent record may carry decision-time non-repudiation semantics; merging is a design decision beyond this pass — flagged for review.
- `security_audit_chain_state`: every claim batch and every ACK writes the singleton row (chain head + anchor checkpoint) — a per-batch and per-event hotspot row.

### 8.3 Temporary/flow-controlled state

- **Audit outbox ended at 15.35 M** (started 0 after TRUNCATE): net growth ≈ +2,000 rows/s = event rate (~2,400/s) − exporter drain (~17.6/s under soak load, vs ~290–470/s idle). The drain collapse under load+deep backlog is evidence for §6.4/§10: claim's `ORDER BY chain.sequence NULLS LAST` materializes the whole backlog before `LIMIT` — `pg_stat_database.temp_bytes` reached **8.57 TB cumulative** over the session (sort spill), and the singleton chain-head lock serializes claims.
- **Classification: export-flow-controlled, not a leak.** No row outlives its ACK; the bound is exporter throughput, which the current per-event checkpoint protocol cannot push to event rate.

### 8.4 Valkey census (post-soak)

- `dbsize` = **6,177,182 keys** (from 3.69 M); `expired_keys` = 6.31 M cumulative (expiration working); `evicted_keys` = 0.
- Prefix census (100 K sample): **auth_code ≈ 97.4%**, session 1.7 K, jar:jti 0.9 K, dpop:jti/nonce, client_assertion:jti — replay markers with short TTLs.
- auth_code TTLs ≈ 42,900–43,200 min ≈ **30 d** — the contract-retained replay→family-revocation evidence window (§3.5). Growth ≈ authorize rate (~330/s → ~1.2 M keys/h); at this workload the 30-day steady state is a capacity-planning number, not a defect.
- Valkey RSS: 2.3 → 4.1 GB.

### 8.5 Cleanup convergence

- `oauth_tokens` expired backlog held at **0** all soak (maintenance worker reclaiming in real time; bounded catch-up never saturated).
- `oauth_token_issuances` due-backlog **shrank 26.3 K → 5.9 K** during the soak (catch-up converging under load).
- tup_del vs tup_ins at DB level: +27.8 M deletes vs +102.5 M inserts over the metrics window — cleanup writes ≈ 27% of insert volume; deletes are dominated by outbox ACK + family reclaim + expired-state sweep.

### 8.6 Process RSS

| Process | min | p50 | max | Verdict |
|---|---|---|---|---|
| nazoauth app | 146.6 MB | 215.5 MB | 216.4 MB | **Flat** — independent of 36.8 M-event ledger, 15.3 M outbox, 6.2 M Valkey keys |
| postgres | 6.39 GB | 7.13 GB | 8.48 GB | shared_buffers + workload |
| valkey | 2.27 GB | 3.27 GB | 4.06 GB | tracks key count |
| k6 runner | — | 3.04 GB | 5.94 GB | harness |

### 8.7 Verdict

At 2000 ops/s the corrected system creates per logical op ≈ **1.08 durable audit events, ~0.36 token rows, ~19.4 statements and ~8 KB WAL**, with app RSS flat at ~215 MB and cleanup converging in real time. Remaining unbounded item is the audit outbox **solely under an exporter that cannot reach event rate** — its bound is a throughput/protocol property (per-event checkpoint on a singleton chain head), not lost-garbage accumulation.

## 9. Tooling corrections

- `evidence/tools/ledger.sql`: removed references to the dropped `exported_at` column; `outbox_pending` now counts the whole outbox (ACK deletes); AUDIT section reports `pending_export` + `anchor_sequence`.
- `evidence/tools/vkledger.py`: exact census pass (every key bucketed into the `oauth:<category>` taxonomy — never truncated) + bounded per-category sample for TTL/memory; `dbsize`/`used_memory` recorded for scaling. The soak-window census quoted in §8.4 used a 100 K-key scan; the committed tool performs the full census.
- `soak_v2.sh`: `docker exec -i` added to the two ledger snapshot calls — without `-i` the pre/post ledger files were silently empty in the previous run.

## 10. Follow-ups (not in this pass)

- Exporter batch-checkpoint protocol and/or sharded chain head to raise drain capacity above the event rate (§6.4).
- `chain_valid` reconciliation helper for recovered/cutover databases (§4.2).
- Outbox claim ordering: `ORDER BY chain.sequence NULLS LAST, created_at` materializes the whole backlog before `LIMIT` — consider an index-aligned claim predicate for deep backlogs.
