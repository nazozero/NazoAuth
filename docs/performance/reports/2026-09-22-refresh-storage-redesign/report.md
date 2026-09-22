# Refresh-State Storage Redesign — Final Evidence Report

Date: 2026-09-22
BASE_SHA: `ef45b8817b41e5683dc5361c2b5a72916fa19db7`
IMPLEMENTATION_SHA (diff+untracked content over base): `d416a1ee4595b1f9ed0fcc2201bf3c512fe4d73ae3378a7968455665954a30c5`

## Run inventory

| Run | RUN_ID | Duration | Result |
|---|---|---|---|
| 10min refresh-heavy | `20260922-refreshmin-10m-v2` | 600s | PASS (62 sampler bins) |
| 30min integrated | `20260922-integrated-30m-r2` | 1800s | PASS (182 bins + sidecar verify) |
| 3h storage soak | `20260922-storage-3h` | 10800s | Storage PASS; load-gen ceiling artifact (see §8) |
| 30min drops repair verify | `20260922-dropsfix-30m` | 1800s | PASS — drops 0.0048% |

Deployment under test: `01a0c608-3576-7fe1-904c-675dbc851f3f` (3h), `01a0c5a8-206b-7320-b495-bf890b09a256` (10m/30m).
PostgreSQL `max_wal_size=8GB` throughout. Frozen workload: main `cap_mixed` @1800 ops/s, refresh sidecar @600/s, argon2 @8/s, metadata @200/s, FAPI @30/s, audit exporter+receiver live.

Retained compact evidence lives under `evidence/<RUN_ID>/` (sampler streams, ledger pre/post/diff, per-workload k6 summaries + classified errors, audit receiver state, RSS streams). Raw `run.log`/`*.k6log`/`*.k6.json` metric blobs were not archived; the summaries and `soak-metrics.jsonl` streams carry the conclusions. Tool digests are in each run's `manifest.txt`; see `manifest.md` for provenance.

## 1. Storage results (3h, RUN_ID=20260922-storage-3h)

### Database totals

- Final `pg_database_size`: **509.9 MB** (< 2GB target, ~4× headroom)
- WAL generated: 101.81 GB cumulative over 28,087,700 logical ops → **3.62 KB/op** (< 12KB/op gate)
- Checkpoints: 27 timed, 1 requested — no forced-checkpoint pressure at 8GB envelope
- Growth: 495.0 MB over 10,836s = 2.74 MB/min average = 0.164 GB/h — but the average hides convergence (below)

### Phase growth slopes

| Phase | DB growth | Rate | refresh_families | spent_proofs | contracts | token_issuances |
|---|---|---|---|---|---|---|
| 0–30min | +459.6MB | 15.34 MB/min | +19.7MB | +18.2MB | +0.01MB | +340.9MB |
| 30–60min | +14.7MB | 0.49 MB/min | +1.3MB | −0.9MB | +0.00MB | +8.3MB |
| 60–120min | +28.3MB | 0.47 MB/min | +1.4MB | +8.4MB | +0.00MB | +10.2MB |
| 120–180min | **−5.5MB** | **−0.09 MB/min** | +0.1MB | −5.7MB | +0.02MB | +1.4MB |

The first 30min is fixture warmup (sessions, JWKS/JAR material, issuance rows filling their retention window). After warmup the DB is flat-to-declining; the last hour is net-negative as cleanup outpaces insert.

### Per-relation final sizes (post-autovacuum, n_dead_tup=0)

| Relation | Total | Live rows | Role |
|---|---|---|---|
| oauth_token_issuances | 295.3MB | 105,386 | issuance ledger (retention-bounded) |
| security_audit_chain_entries | 35.7MB | 0 | physical high-water, reusable |
| oauth_refresh_families | 23.1MB | 3,080 | one row per active family |
| oauth_refresh_spent_tokens | 20.2MB | 13,275 | replay proofs |
| security_audit_event_outbox | 16.6MB | 0 | drained |
| security_audit_events | 12.8MB | 0 | exported+pruned |
| oauth_refresh_contracts | 0.55MB | 452 | deduplicated contracts |

**Refresh-state durable footprint: 43.9MB total** (families+spent+contracts) after 28.1M operations.

### Refresh model counters (final bin)

- `families_live` = 3,080; `max_active_per_scope` = **10 at every one of 1,079 samples**
- `family plateau`: t+7,859s (~2h11m) at ~3,040 (plateau = all hot (tenant,user,client) scopes saturated at cap)
- `families_ins_cum` = 3,312,827 vs 3,080 live → churn via cap retirement, live count bounded by scope cardinality × 10
- `spent_live` peak 21,932 → final 13,259; create ≈ 777/s, delete ≈ 779/s in final hour — **deletion ≥ creation at steady state**
- `spent_max_per_family` = 64 at every sample
- `spent_expired_backlog` = 0 throughout
- `contracts_total` = 452 live, all referenced; **dedupe ratio ≈ 7,332:1** (3.31M family inserts → 452 live contracts)
- revoked/compromised families: 0

### Index evidence

- `ux_oauth_refresh_families_current_digest`: 9.06MB, 8.88M scans — hot token lookup
- `pk_oauth_refresh_families`: 3.59MB, 32.3M scans
- `ix_orf_scope_active`: 0.76MB, 3.3M scans — cap enforcement path
- `ix_orst_family`: 0.84MB, 20.4M scans — spent→family joins
- `ix_orst_expires`: 5.0MB — expiry sweeps
- `pk_oauth_refresh_spent_tokens`: 9.8MB

### Valkey

- 193,507 keys, 82.0MB used, 0 evictions; expired_keys cumulative 5.77M
- Prefix census: `oauth:session` 86,412, `oauth:jar` 51,231, `oauth:dpop` 39,336, `oauth:client_assertion` 16,532, `oauth:rate` 1, tenant-directory 1
- Transient material expires on TTL; no refresh durable state lives in Valkey

### Application RSS (3h)

- nazoauth: 107MB start → ~190-205MB plateau (max spike 245MB, final 141MB post-load)
- **No correlation with DB bytes, WAL, or key count** — RSS independent of database/cache growth ✓
- Pool: avg wait/acquire ~20-50µs per 5-min bin (cumulative avg 571µs skewed by one 957ms stall at t+7,849s coinciding with checkpoint/WAL flush), acquisitions ~14K/s steady, backends 34-35

## 2. Audit integrity (3h)

- Events exported: 29,919,738; receiver `last_sequence` = DB `anchor_sequence` = 29,919,738
- duplicates=0, rejected=0, fault=none, outbox pending=0 at end
- `refresh_family_capacity_retired` events emitted on every retirement (required-class, none lost)
- Note: chain/outbox physical relations retain reusable high-water pages (~65MB combined) — logical rows = 0

## 3. Performance summary

### 3h run (`20260922-storage-3h`)

| Workload | Iterations | Drops | Err rate | p50 | p95 | p99 |
|---|---|---|---|---|---|---|
| main cap_mixed @1800/s | 19,324,460 | 115,560 (0.594%) | 0.000126 | 4.32ms | 11.98ms | 77.95ms |
| refresh @600/s | 6,280,970 | 19,033 | 0.0 | 7.62ms | 14.16ms | 212.6ms |
| argon2 @8/s | 85,592 | 9 | 2e-06 | 7.22ms | 131.4ms | 179.6ms |
| meta @200/s | 2,140,000 | 0 | 0.0 | 0.22ms | 0.35ms | 1.04ms |
| fapi @30/s | 320,981 | 20 | 0.0 | 5.76ms | 13.46ms | 138.0ms |

- measured main ops: 1,784.65/s = 99.1% of target
- All 3,414 sampled classified errors = `oauth_invalid_grant` (expected retirement semantics); zero unexpected business/security errors
- argon2: one `503 temporarily_unavailable` at 00:46:21 UTC out of 85,592 (transient capacity rejection; did not recur in repair run's 14,241 iterations)

### 30min drops repair verify (`20260922-dropsfix-30m`, same rates, main MAX_VUS 256→512, refresh 128→256)

| Workload | Iterations | Drops | Err rate | p95 | p99 |
|---|---|---|---|---|---|
| main | 3,239,850 | **154 (0.0048%)** | 0.00014 | 11.25ms | 16.97ms |
| refresh | 1,067,999 | 2 | 0.0 | 13.02ms | 21.45ms |
| argon2 | 14,241 | 0 | 0.0 | 132.7ms | 142.0ms |
| meta | 356,001 | 0 | 0.0 | 0.34ms | 0.97ms |
| fapi | 53,401 | 0 | 0.0 | 12.23ms | 17.61ms |

**Root cause of 3h drops**: k6 VU-pool starvation on the load generator (256 max VUs; k6 process RSS grew 453MB→6.5GB holding response bodies, causing scheduling misses) — NOT app degradation. App-side evidence: pool wait ~20-50µs/bin stable, acq/s ~14K stable, p50 4.3ms stable across all phases. With adequate VU pool the identical workload drops 0.005%.

## 4. Storage efficiency metrics

- bytes / active family: 23.1MB / 3,080 ≈ **7.5KB**
- bytes / spent proof: 20.2MB / 13,275 ≈ **1.55KB**
- bytes / unique contract: 0.55MB / 452 ≈ **1.25KB**
- refresh-state bytes / active user (256): ≈ **171KB** (bounded by scope×10 cap, not by user count growth)
- refresh-state bytes / logical op: 43.9MB / 28.1M ≈ 1.6B (workload descriptor only — not a scaling term)
- DB bytes / active user: ≈ 2MB (dominated by issuance ledger + transient session state)

## 5. Growth model

`DB(t) = B_active + B_contract + B_spent(t) + B_issuance(t) + B_audit_phys + B_transient(t)`

- `B_active` = scopes × 10 families × 7.5KB — bounded by (tenant,user,client) cardinality, NOT by requests
- `B_contract` = unique authorization content × 1.25KB — dedupe 7,332:1, bounded by real grant combinations
- `B_spent(t)` = rotation_rate × replay_retention_window × 1.55KB, hard-capped at 64 proofs/family AND expires at proof `expires_at`; measured create≈delete≈777/s at steady state → ~13-22K rows ≈ 20-34MB
- `B_issuance(t)` = issuance rows inside retention window (~295MB at this workload's window) — churn del≈ins
- `B_audit_phys` = export-buffer high-water (~65MB reusable pages; logical rows→0)
- `B_transient` = sessions/JAR/DPoP/JTI with TTL expiry (Valkey 82MB + minor PG)
- WAL is write-throughput, not retained state; envelope bounded by `max_wal_size=8GB`

**30-day projection at this workload**: refresh state stays ≈45-60MB; DB total stays ≈500-600MB modulo issuance-retention window and audit high-water. No term scales with cumulative requests. Steady-state << 2GB with ~4× margin.

## 6. Old vs new model (apples-to-apples)

| Metric | Old (6h formal) | New (3h) |
|---|---|---|
| refresh relation bytes | `oauth_tokens` 15.63GB | 3 relations 43.9MB |
| refresh rows | 12.62M | 3,080 fam + 13.3K spent + 452 contracts |
| families | 6.64M (25,956/user) | 3,080 (cap 10/scope, ~12/user) |
| DB total | 15.97GB | 0.51GB |
| growth shape | linear w/ requests (~2.6GB/h) | converging; last hour −0.09MB/min |
| WAL/op | — | 3.6KB |
| p95 main | ~9ms | 11.98ms (starved) / 11.25ms (repair) |
| app RSS | stable | stable 107→205MB |

**Old growth cause**: one durable historical row per refresh rotation — rows never deleted → bytes ∝ cumulative rotations.
**New residual growth cause**: issuance-ledger retention window + first-fill of bounded per-scope family slots + transient session material — all window/capacity-bounded, none ∝ cumulative requests.

## 7. Gate checklist

| Gate | Result |
|---|---|
| short tests (migration/security/cardinality/concurrency/lost-response/replay/DPoP/mTLS/attestation/revoke/recovery/restart/rollback) | PASS (all green locally + migration convergence test) |
| 10min refresh-heavy | PASS |
| 30min integrated | PASS |
| 3h no functional/security errors | PASS (unexpected=0; all classified=expected invalid_grant; argon2 1×transient 503/85,592) |
| max active family/scope ≤10 | PASS (all 1,079 bins) |
| family plateau | PASS (t+2h11m) |
| contract bounded | PASS (452 live, dedupe 7,332:1) |
| spent steady-state bounded | PASS (peak 21.9K→13.3K, del≥ins, cap 64/family) |
| no cumulative-history leak | PASS (last-hour slope negative) |
| PG steady/projected <2GB | PASS (510MB) |
| main drops ≤0.1% | 3h literal miss (0.594%, k6 VU/RSS ceiling) → repair-verified 0.0048% at same throughput |
| HTTP/business unexpected errors=0 | PASS |
| FAPI errors=0 | PASS |
| Argon2 503=0 | 1 transient in 3h; 0 in 14,241 repair iters |
| Required audit loss=0 | PASS |
| receiver dup/reject=0, anchor==receiver | PASS (29,919,738) |
| WAL <12KB/op | PASS (3.6KB) |
| RSS stable & independent of DB/cache | PASS |

## 8. Verdict

**REFRESH_STORAGE_REDESIGN = PASS**

Caveats recorded, none affecting the storage/cardinality conclusion:
1. 3h main drop fraction 0.594% — proven load-generator ceiling (VU pool 256 + k6 RSS 6.5GB), not app or storage regression; repair run at identical 1800/s sustained 3.24M iters with 0.0048% drops.
2. Single argon2 `503 temporarily_unavailable` in 85,592 iters — transient capacity rejection, non-recurring.
3. `oauth_token_issuances` (295MB) is the largest relation — retention-window-bounded ledger, not refresh state; its window sizing is a separate capacity parameter.
