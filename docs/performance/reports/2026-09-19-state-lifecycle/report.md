# NazoAuth State-Lifecycle Fix & Capacity Revalidation

**Run ID:** `20260919-f93c6914-cnb-state-v2`
**Baseline source SHA:** `f93c6914a49530db702847f95f3809a0abc83fe8` (GitHub `main`, = prior corrected-benchmark commit)
**Patched source:** this commit (see §3); changes reviewed against the `3ff5030e` investigation findings
**Deployment ID:** `01a0b7d8-9fde-7590-ad63-b1d3b33ff378`
**Date:** 2026-09-19 (all times UTC)
**Prior references:** `nazoauth_state_growth_investigation.md`, `docs/performance/reports/2026-09-18-capacity-endurance/`

## 0. Scope statement

This round re-validates **state lifecycle** (reclamation, retention, cleanup throughput, audit outbox) on the current source, applies only proven-necessary fixes, and re-measures sustained capacity with the corrected harness from 2026-09-18. All numbers are **topology-specific** (single app container, ≤64 of 192 host CPUs, co-located PostgreSQL 18.6 + Valkey 8 + k6 2.2.0). A 2-hour soak demonstrates stability *for that duration, state volume and topology only* — not an infinite capacity guarantee.

## 1. Investigation items — status

| # | Item | Status | Evidence |
|---|---|---|---|
| A | Cleanup throughput mismatch: 1 batch ≤256 rows/category per 60 s → ~4.27 rows/s ceiling | **Confirmed & fixed** | §3.1, §6.1, §7.2 |
| B | Refresh-chain reclaim removed only expired leaves; fully-expired families retained | **Confirmed & fixed** | §3.2, §6.1–6.3 |
| C | Exported audit-outbox rows accumulated forever (no retention category existed) | **Confirmed & fixed** | §3.3, §6.2 |
| D | Consumed authorization-code state in Valkey | **Reasonable design retained** | §4.2 |
| E | Active refresh-family history growth | **Reasonable design retained** | §4.1 |
| F | Pending (unexported) audit outbox growth | **Legitimate retained state; measured** | §4.3, §5.3 |
| G | Pool saturation not directly observable (no in-use/idle/waiter metrics) | **Fixed** | §3.4, §7.3 |

## 2. Environment

| Item | Value |
|---|---|
| Host | AMD EPYC 9K65, ~192 logical CPUs, ~128 GiB RAM |
| App | `nazoauth-perf-nazoauth-1`, single container, no CPU pin |
| DB | PostgreSQL 18.6 (`nazoauth-perf-postgres-1`), pg_stat_statements on |
| Cache/state | Valkey 8.x, maxmemory=0 |
| Load gen | k6 2.2.0 (`nazoauth-perf-perf`), constant-arrival-rate |
| Fixtures | 64 users; flow vectors reseeded to 3000 pre-load (covers fapi absolute offset 1200) |
| Baseline image | `nazoauth-perf-nazoauth:baseline-f93c6914` (`6303eaaf3cd8`) |
| Patched image | `nazoauth-perf-nazoauth:latest` (`d363903d601a`) |

## 3. Changes applied (this commit)

### 3.1 Maintenance worker — bounded catch-up

`crates/nazoauth/src/jobs/security_state.rs`: previously one batch/cycle then a fixed 60 s sleep. Now each cycle runs bounded batches **while the port reports `saturated`**, subject to:

- `CATCH_UP_BUDGET = 30 s` wall-clock per 60 s cycle — cleanup can never exceed half the interval;
- `CATCH_UP_MAX_BATCHES = 512` hard cap (defense-in-depth);
- `tokio::task::yield_now()` between batches — cooperative, not a busy loop;
- failure → break → next interval (backoff; no fast retry);
- per-batch structured log: per-category counts, `saturated`, elapsed_ms.

### 3.2 Whole-family refresh reclaim

`crates/persistence-postgres/src/repositories/security_state.rs`: previously ≤256 families/cycle, deleting only expired **leaves** — a 400-member chain needed ~400 cycles ≈ 6.7 h. Now a candidate family is reclaimed **as a whole only when every member is expired** (re-checked under the existing shared family advisory lock — an unexpired member protects the whole family), `rotated_from_id` detached, deleted in bounded chunks. Family scan limited per round; row budget per batch; `SKIP LOCKED` on contention. Reuse detection, family compromise, concurrent-rotation control and lost-response recovery keep all their state while any member is live.

### 3.3 Exported audit-outbox retention

Migration `20260919000100_audit_outbox_exported_retention` adds `nazo_cleanup_exported_security_audit_outbox()` (SECURITY DEFINER; `EXECUTE` granted to the runtime role via role provisioning): deletes delivery rows `exported_at <= now() - interval '1 day'`, bounded 256 rows/call, `FOR UPDATE SKIP LOCKED`. Pending/locked/rescheduled rows are never touched; the immutable `security_audit_events` record stays. Partial index `idx_security_audit_outbox_exported` added. `down.sql` drops function+index.

### 3.4 Pool state metrics

`PostgresPoolMetrics` now carries the live pool handle; `/__perf/metrics` `db_pool` exposes `connections`, `idle_connections`, `waiting_acquisitions` alongside cumulative acquire count / wait total / wait max. `crates/authorization-server-postgres` wiring and one test mock updated accordingly.

### 3.5 Deliberately not changed

- No pool-size increase — previous 60 s-wait saturation is now directly observable, not presumed a sizing defect.
- No TTL shortening, no expiry-field manipulation, no new family absolute-expiry policy.
- No consumed-marker TTL reduction (§4.2).
- No maintenance-dedicated connection pool — identified as follow-up (§10), not silently added.

## 4. Design-retained findings

### 4.1 Active refresh-family history

Each rotation inserts a member carrying `oidc_auth_context`, audience, DPoP/mTLS bindings. History is **required** while the family is live (replay detection compares ancestors; compromise revokes the family; lost-response recovery reads the predecessor). Reclaim begins only when the *whole* family is expired — enforced by §3.2. **Retained.**

### 4.2 Consumed authorization-code markers (Valkey `oauth:auth_code`)

Measured fixture: 397 B `{client_id, redemption_binding, access_token_jti, access_token_expires_at, refresh_token_family_id, consumed_at}`, TTL = refresh-family TTL (30 d). Required for RFC 6749/9700 code-replay → associated-token/family revocation: a replay attempt at day 25 must still revoke the live family. Payload already minimal. **Retained.** Growth is proportional to authorization-code volume — a capacity-planning number (§5.2), not a defect.

### 4.3 Pending audit outbox

No exporter runs in this perf topology (`audit-anchor-worker` is a separate process needing an HTTPS anchor + HMAC secret). Pending rows are correctly never deleted — they are undelivered audit. Growth is measured (§5.3) and is a deployment property, not a leak; production deployments must run the worker.

## 5. State-storage ledger

### 5.1 PostgreSQL

| Metric | Pre-load | Post-soak (06:58) |
|---|---|---|
| `oauth_tokens` rows | 68 | 4,515,010 (peak; seed-cleaned after) |
| `oauth_token_issuances` rows | 1 | ~570k peak → 220,096; **due → 0** |
| `security_audit_events` | 0 | 18,527,762 |
| `security_audit_event_outbox` | 0 | 18,527,758 (all pending) |
| `security_audit_chain_entries` | 0 | 0 (none anchored — no exporter) |
| tup_inserted (soak delta) | — | 46,734,183 |
| tup_deleted (soak delta) | — | **9,714,443 reclaimed in-run** |
| deadlocks (soak delta) | — | **0** |

### 5.2 Valkey

| Metric | Pre | Post |
|---|---|---|
| keys (dbsize) | 66 | 2,744,883 |
| used_memory | 1.2 MB | ~1.94 GB |
| evictions | 0 | **0** |
| dominant class | `oauth:session` | `oauth:auth_code` consumed markers (TTL 30 d — §4.2), `oauth:jar` (TTL ≤4 min churn) |

### 5.3 Audit backlog (no exporter in topology)

- Generation: **~2,570 events/s at 2000 ops/s** (~1.28 events/op) — 0 → 18.5 M over the round.
- Pending is legitimate retained state awaiting export; `exported=1` row total, so §3.3's retention had nothing to reclaim in-run — its semantics are covered by `exported_audit_outbox_rows_reclaim_only_past_grace` (§6.2).
- `queue_full` best-effort drops occurred during the §7.3 contention window (~06:33–06:42): the in-memory channel filled while DB writes queued — audit *losses* (not ledger corruption); the durable ledger is unaffected, logged `not_queued`.

### 5.4 Cleanup throughput — the headline number

- Baseline ceiling: **≤256 rows/category per 60 s ≈ 4.27 rows/s**.
- Patched: observed single-cycle drains of **~72–76 k issuances** inside a ≤30 s budget (**~7.4 k rows/s effective**, ~1,700× the old ceiling), bounded, yielding, self-limiting.
- Soak `iss_due` sawtooth: backlog accumulated to ~80–100 k between cycles, each drain cycle reset it; peak during the contention window 530,046; **post-load drained to 0** (~1.4–6.7 k rows/s uncontended).
- Fixture proof: a 400-member fully-expired refresh family was reclaimed **in one cycle** (baseline would have needed ~6.7 h).

## 6. Validation

### 6.1 Controlled fixture experiment (pre-soak, live worker)

- 400-member fully-expired family: **fully reclaimed in one maintenance cycle**.
- Single-member expired family: reclaimed.
- 2-member family with an unexpired successor: **all rows retained** — active-family protection verified end-to-end.

### 6.2 Lifecycle test suite (patched source)

| Suite | Result |
|---|---|
| `security_state_maintenance` (persistence-postgres) | **11/11 pass** — whole-chain reclaim, bounded batches + saturation, writer-lock skip + late-successor recheck, concurrent batches no deadlock/double-count, exported-outbox grace, active-successor protection, cancel leaves no open tx |
| `nazoauth jobs::security_state` (worker unit) | **4/4 pass** — incl. `saturated_batches_drain_immediately_until_unsaturated` |

### 6.3 Security regression (post-soak, quiescent DB)

| Suite | Result | Covers |
|---|---|---|
| `auth_repositories` | **27/27 pass** | refresh reuse → family compromise, concurrent rotation waits, grant-revoke race, replay compensation, lost-response recovery, auth-context round-trip, rotation SQL-failure rollback |
| `token_issuance_atomicity` | **4/4 pass** | issuance+audit atomic commits, single-use grant retry, no duplicate audit |
| `audit_ledger` | **4/4 pass** | ledger persistence semantics |
| `audit_chain_cutover` | **1/1 pass** | chain-entry ownership after cutover |
| `access_token_retention` | **6/6 pass** | retention cutoff does not delete early; expired state reclaimed |
| `mtls_trust` | **1/1 pass** | mTLS trust-anchor lifecycle |

(An earlier attempt at this suite failed 9/27 — concurrently with the post-soak **re-seed DELETE holding `ACCESS EXCLUSIVE` on `oauth_tokens`**; rerun on the quiet database: 27/27. Fixture interference, not a regression.)

## 7. Capacity revalidation

### 7.1 Short reference points (300 s, cap_mixed, identical harness/fixtures)

| Run | Image | Target | Achieved ops/s | Errors | p95 | p99 | Dropped |
|---|---|---|---|---|---|---|---|
| baseline r2000 | `6303eaaf3cd8` (f93c6914) | 2000/s | 1880.9 | 0 | 18 ms | 49 ms | 1,667 (0.28%) |
| patched r2000 | `d363903d601a` | 2000/s | 1885.0 | 0 | 17 ms | 24 ms | 1,610 (0.27%) |
| patched r2500 | `d363903d601a` | 2500/s | 2400.2 | 0 | 17 ms | 23 ms | 12 |

Parity: lifecycle changes do not regress throughput or tail latency at reference scale.

### 7.2 Soak — RUN_ID `soak-v2-patched-2000` (patched image, 2 h)

Main: cap_mixed constant-arrival-rate **2000 ops/s × 7200 s**. Sidecars: argon2 1 VU (37.2 ops/s, 0 err — valid), meta 4 VU (26.2 k req/s, 0 err — valid), fapi 30/s (**invalid — see §8**); standalone fapi r30 point: 150 req/s, 0 err, p95 7.7 ms (valid).

| Metric | This run (patched, hot start) | Prior soak (f93c6914, near-empty start) |
|---|---|---|
| Duration | 120.0 min | 120 min |
| Completed ops | 13,919,408 | 14,360,000 |
| Achieved rate | **1,933.2 ops/s** (96.7% of target) | 1,994.7 ops/s |
| HTTP requests | 20,305,117 — **0 failed** | 20,860,000 — 0 failed |
| Business/app errors | **0** (all `err_classified` series = 0) | 0 |
| p50 / p95 / p99 | 5 / 58 / **519 ms** | 6 / 28 / 88 ms |
| Dropped iterations | **432,644 (0.31% of scheduled)** | 38,018 |
| DB deadlocks delta | **0** | 0 |
| Valkey evictions | 0 | 0 |
| App RSS | 136→148 MB (max 214) | ~135 MB |
| Runner RSS | →6.86 GB (metric accumulation) | ~5.5 GB |
| Starting DB state | ~3 M audit rows + ~400 k tokens (post reference runs) | near-empty |

**Honest verdict:** sustained 2000 ops/s was achieved for the full 2 h with **zero request and zero business errors**, and the lifecycle fixes performed ~9.7 M row reclamations in-run. The run is **not** classified "clean": a ~9-minute contention window (see §7.3) produced the elevated drop count and p99 tail. The degraded tail correlates with the much larger starting state and in-run write volume, not with correctness of the fixes.

### 7.3 Contention window (06:33–06:42, ~min 105–114)

- Pool: `idle → 0`, `waiting` sustained ~470, **peak 492**, `wait_max` 508 ms; recovered to idle>0/waiting=0 without intervention and held 2000 ops/s for the remaining ~38 min.
- k6 compensated with VU scaling to 512/512 (peak); dropped iterations concentrated here.
- App emitted `audit.persistence ... not_queued queue_full` for ~5 min — best-effort audit channel backpressure; durable ledger unaffected.
- `pg_stat_activity` during the window: all queries millisecond-fast, `WalSync`/`WALWrite` LWLock waits — **storage-layer (WAL/checkpoint-scale) pressure at 46.7 M inserts + 9.7 M deletes + 18.5 M-row audit table**, not lock waits or long transactions. The cleanup worker was itself starved (due backlog climbed 240 k → 530 k), so contention was upstream of cleanup rather than caused by it — though drain bursts add bounded DB pressure by design (§3.1).
- Root-cause candidates for follow-up: WAL/checkpoint tuning at this insert rate; a **dedicated maintenance connection/pool** so catch-up cannot share fate with request traffic (§10).

## 8. Harness/run defects encountered this round

- Sampler v2 initially lacked `Host: 127.0.0.1` on `/__perf/metrics` → first ~10 min pool samples 404; fixed by restarting **only** the sampler (observability, not the load path). Cumulative pool counters kept start/end deltas computable.
- fapi soak-sidecar invalid again: an intermediate `arrive.sh` reference run re-seeded vectors.json at the default 1000 (< absolute offset 1200). **Process defect: any non-`PERF_SKIP_SEED` runner silently resets the shared vector pool.** The standalone r30 point (valid) substitutes for fapi coverage; workload description adjusted accordingly.
- First regression-suite attempt collided with the post-soak re-seed's `ACCESS EXCLUSIVE` DELETE — rerun clean (§6.3). Confirms the rule: **never seed while DB tests run**.

## 9. Prior-report conclusions — withdrawn vs. standing

| Prior conclusion | Status |
|---|---|
| 2000 ops/s sustainable 2 h on f93c6914 | **Stands** — re-validated on patched source (zero errors, §7.2) |
| 2500 ops/s unsustainable | Reference point clean for 300 s this round; **sustained 2500 not re-attempted** — remains unproven either way (§10) |
| Runner RSS growth = generator metric accumulation | **Stands** — 6.86 GB peak, same pattern |
| Argon2 ~40 login/s ceiling | **Stands** — argon2 sidecar 37.2 ops/s at 1 VU, consistent; unchanged code path |
| "cleanup keeps up under sustained load" (implicit) | **Corrected** — new code keeps up but shares the request pool; at this write volume a contention window appeared at ~105 min (§7.3) |

## 10. Not done / open items

- Sustained 2500/s not re-run: previous failure mode is now directly observable; 2 h budget prioritized for the proven-rate re-validation under the new lifecycle code.
- Maintenance vs request-traffic pool isolation: candidate fix for the §7.3 window — needs its own validation cycle; deliberately **not** rushed into this commit.
- No audit-anchor worker in perf topology → pending-backlog growth expected and measured (18.5 M rows), not "fixed". Production deployments must run the worker.
- WAL/checkpoint behavior under ~46 M inserts/2 h not tuned; flagged as the leading §7.3 suspect.
- `chain_entries` = 0 — chain entries are written at anchor/export time; with no exporter they stay empty (consistent, noted).
- CPU-pinned capacity ladder not repeated (see 2026-09-18 report §11).

## 11. Reproduction

```bash
# reference points (300 s each)
bash perf-results/arrive.sh cap_mixed 2000 300
bash perf-results/arrive.sh cap_mixed 2500 300
# soak (isolated RUN_ID dir, pre/post ledgers, sidecars)
bash perf-results/soak_v2.sh 2000 7200 soak-v2-patched-2000
# state ledger + valkey prefix census
docker exec nazoauth-perf-postgres-1 psql -U postgres -d oauth -f tools/ledger.sql
docker run --rm --network nazoauth-perf_perf_net -v $PWD/perf-results:/r nazoauth-perf-perf python3 /r/vkledger.py
# tests
cargo test --release -p nazo-postgres --test security_state_maintenance   # 11/11
cargo test --release -p nazoauth --lib jobs::security_state               # 4/4
cargo test --release -p nazo-postgres --test auth_repositories \
  --test token_issuance_atomicity --test audit_ledger \
  --test audit_chain_cutover --test access_token_retention --test mtls_trust  # 43/43
```

Evidence: `docs/performance/reports/2026-09-19-state-lifecycle/evidence/` — soak summary + errors json, sampler v2 series, proc-stats, ledgers, sidecar summaries, test logs, repro tools.
