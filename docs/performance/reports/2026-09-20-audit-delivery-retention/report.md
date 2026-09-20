# Audit Delivery-Scoped Retention — Post-Soak Correction Report

- **BASE_SHA**: `b5ee3139` (remote-verified on `origin` GitHub + `cnb` before work began)
- **IMPLEMENTATION_SHA**: `72572eba` (last code change); report+evidence commit `63efa404`; local `main`, push pending authorization
- **TEST_SOURCE_SHA of the prior soak**: `6e3a352c` — the 8h run's binary; distinct from report/bookkeeping commits
- **Fixture**: prior soak's live database — 11.88M undelivered audit events, anchor `41,586,901`, receiver checkpoint seeded to match
- **Scope**: correct the exporter cliff and write amplification found by `statemin-v2-soak-8h-r2`; 10-minute isolated diagnostics + one 30-minute integrated short test. No capacity re-test.

## 1. Facts carried forward (not re-measured)

From `statemin-v2-soak-8h-r2` (TEST_SOURCE_SHA `6e3a352c`): 51.8M iterations @1796.8 ops/s, 0 errors, p50/95/99 = 5/21/35 ms, app RSS ≈126 MB, 1.12B SQL statements, 53.03M audit events generated (1.024/op), 35.2M anchored, receiver duplicates/rejections = 0, archive ≈25.9 GB, WAL ≈16.8 KB/op, post-stop export 73–105 ev/s on deep backlog.

## 2. Isolated 10-minute diagnostics

Three runs on the real fixture (same schema, indexes, 128 MB shared_buffers, batch size, receiver contract).

| Run | Result | Key evidence |
|---|---|---|
| **A — claim/export only** (archive stopped, 18M backlog) | **100.7 ev/s** (236 batches / 60,416 events / 600 s); receiver 0 dup / 0 rej | claim inner SQL 13–22 ms bounded, 0 temp spill; but `nazo_security_audit_shared_anchor_health` = 237 calls × **2,449.9 ms** ≈ 96.8 % of wall time |
| **B — archive only** (no arrivals) | **6,960 rows/s**, 2.93M rows reclaimed in ~7 min | per reclaimed event: archive INSERT ≈6,494 B WAL + events DELETE ≈745 B + chain DELETE ≈233 B ≈ **7.5 KB WAL/event** |
| **C — claim + archive** | export **160 ev/s**; archive ~11.7k rows/s | claim probe 22→**146 ms** (6.6×); `Lock:transactionid` — exporter's `chain_head_for_update` blocked on archive's `chain_state` row lock |

### Root cause (evidence-backed)

1. **Primary — per-iteration orphan scan.** The worker calls `anchor_health()` every loop. Its `pending_orphan_exists` predicate ran `EXISTS(outbox ⋈ chain WHERE chain.sequence ≤ anchor)`. Under the old model every anchored row stayed in `chain_entries` until the archive sweeper reclaimed it, so the probe had to *falsify* millions of delivered rows each iteration — measured standalone: **5.18 s**, 2.885 M chain rows scanned, 11.5 M buffer hits. This is the cliff: throughput ≈ 256 events / health-call latency, degrading as anchored history grew.
2. **Secondary — archive lock serialization.** `nazo_archive_security_audit_prefix` held `chain_state FOR UPDATE` across archive INSERT + two DELETEs + watermark update; observed blocking claim/ack (`Lock:transactionid` waits).
3. **Amplifier — archive copy WAL.** ~6.5 KB WAL/event written to a 31 GB OLTP table with **zero readers** (verified: no production query touches `security_audit_archive`, `security_audit_events`, or `security_audit_chain_entries` outside the delivery path). Under contention it also evicted claim's working set, producing the 6.6× latency regression.
4. **Latent — queue-head tombstones.** Ack deletes at the head of `idx_security_audit_outbox_order`; an unrelated 17-minute seed `UPDATE oauth_tokens …` held `backend_xmin` and pinned the vacuum horizon → 357k heap fetches / 115 ms for a `LIMIT 1` probe. Once the pinning transaction was terminated and vacuum ran, the same probe cost 1.2 ms.

## 3. Structural change — `20260924000100_audit_delivery_scoped_retention`

Old chain → new chain, and what was deleted:

```
outbox → claim → chain append → deliver → ack → (rows stay) → archive sweeper → archive table (dead copy)
outbox → claim → chain append → deliver → ack: DELETE outbox+chain+events + advance anchor — one transaction
```

| Problem | Removed/changed | Why still safe |
|---|---|---|
| orphan scan ∝ anchored history | ack deletes chain rows; `≤anchor` chain entries can no longer exist → `pending_orphan_exists` is a bounded probe | invariant now enforced by construction, not by periodic scanning |
| archive copy with zero readers | `security_audit_archive`, `security_audit_archive_state`, `nazo_archive_security_audit_prefix`, archive maintenance path | external receiver is the sole durable history (verify + fsync + signed receipt); restore/reconciliation already accounts for receiver history |
| `chain_state` write churn | `observe` throttled to ~30 s; `anchor_observed_at` refreshed inside ack | batch-level writes only (append/open/ack); no per-event singleton UPDATE |
| empty-chain liveness | append validates head against `chain_state` (not a `chain_entries` row); `chain_valid` accepts empty table with `last_sequence > 0` | state row is the authority — required for delete-at-ack to keep working after full drain |
| unused indexes | `idx_security_audit_events_occurred_at`, `idx_…_type_occurred_at` | no reader existed |
| queue-head tombstone window | `autovacuum_vacuum_scale_factor=0` + bounded thresholds on outbox/events/chain_entries | lifecycle bound: keeps dead prefix small between probes; the probes themselves LP_DEAD-kill entries between visits |
| pre-cut delivered residue | one-time `seq ≤ anchor` sweep under `nazo.audit_reclaim` permit | append-only trigger kept; permit renamed `nazo.audit_reclaim`; retired `nazo.audit_archive` name verified *not* to authorize deletes |

Function-level work stayed identical otherwise: claim still bounded ≤256, batch lease/fencing/digest verification unchanged, replay fence and tenant isolation unchanged.

## 4. Verification

- **Migration**: full 82-migration chain applies clean under `psql -1` and under the Diesel harness; `migration-head.txt` advanced; contract checksum manifest regenerated (`tests/contracts/migrations.sha256`).
- **SQL smoke**: persist→append→open→ack leaves events=outbox=chain=0 with anchor=head=2; append after full drain yields sequence 3 and `chain_valid=t`; append-only trigger rejects direct DELETE including under the retired `nazo.audit_archive` permit.
- **PG integration**: `security_state_maintenance` 15/15, `audit_ledger` 6/6, `audit_chain_cutover` 1/1 on PostgreSQL 18 (fresh databases).
- **Static gates**: `cargo fmt --check`, `cargo clippy --workspace --all-targets --all-features --locked --keep-going -- -D warnings`, `verify_static_contracts.py --check`, `check_persistence_dependency_graph.py` — all clean.
- **Real fixture**: migration applied in place to the live soak database (11.88M pending); post-migration `chain_valid=t`, `pending_orphan_exists=f`, receiver checkpoint == anchor `41,586,901`.

## 5. FAPI 10-minute short test — `fapi10m-r2`

`fapi2_logged_in_high_security`, constant-arrival-rate 30/s, 600 s, real seed (128 users, mTLS/DPoP/private_key_jwt clients, PAR):

- **18,001 iterations completed, 0 interrupted, 0 errors**; 90,005 HTTP requests @150.0 rps; p95 = 8.09 ms
- Vector pool auto-expanded `2000 → 19,230` (`ensure_vector_capacity`) — the prior `0 requests` failure mode is fixed
- Step latencies: authorize 0.85 ms, authorize_decision 4.84 ms, token_code 6.70 ms, token_refresh 5.40 ms, par_fapi 1.77 ms — all p50

## 6. 30-minute integrated test — `statemin-fix-int30-r1`

`cap_mixed` constant-arrival-rate **1800 ops/s** × 1800 s on the live fixture; exporter draining the residual backlog concurrently.

| Metric | Result |
|---|---|
| Iterations | 3,238,988 completed + 1,016 dropped (0.031 %) of 3,240,004 scheduled; measured 1,776.8 ops/s |
| HTTP | 4,706,596 reqs @2,614.7 rps; **error rate 0.0**; p50/p95/p99 = 5/20/30 ms |
| Audit arrival | 3,313,992 events (~1.04/op) |
| Anchor | 49,052,629 → 56,853,522 (+7.80M = 4.49M backlog + all arrivals) |
| Post-drain steady state | anchor tracks arrival ~1,850/s; `pending_estimate → 0`, `oldest_pending_age → 0 s` |
| Receiver | `last_sequence = 56,853,522` == DB anchor exactly; **duplicates 0, rejected 0** |
| End state | `outbox = 0`, `chain_entries = 0`, `events = 0`, `security_audit_archive` absent |
| Drain under load | ~4,100–4,300 ev/s sustained while absorbing ~1,850/s arrivals (µ ≈ 2.3×λ ≫ 1.2λ) |
| WAL | +31.9 GB → **9.98 KB/op** including the one-time 7.8M-event drain (prior: 16.8 KB/op) |
| DML/op | ins 5.5, del 7.9 → **0.57 ex-drain**, upd 0.35, commits ~8.0 |
| DB size | 23.26 GB → **7.38 GB** (−15.9 GB: audit events heap truncated by vacuum once emptied; no archive) |
| App RSS | 132.8 MB (VmHWM 326.8 MB) — flat, independent of DB shrink |
| Valkey | 136,682 → 154,088 keys (+5.4/op, TTL-bound session/token keys) |

Claim cost under load at multi-million backlog: `ORDER BY occurred_at,event_id LIMIT 256` = **6.5 ms**, 249 heap fetches — bounded, no backlog-proportional growth, no temp spill.

## 7. Verdicts

| Gate | Result | Basis |
|---|---|---|
| `APP_HOT_PATH` | **PASS** | 0 errors; p99 30 ms ≤ soak's 35 ms; RSS flat |
| `FAPI_PERF` | **PASS** | 18,001 real flows, 0 errors — standalone 10-min run (in-run fapi sidecar failed, see §8) |
| `AUDIT_CLAIM` | **PASS** | bounded probe ~2–7 ms at 15M backlog; O(batch) rows examined |
| `AUDIT_EXPORT_CAPACITY` | **PASS** | µ ≈ 4.1–8.3k ev/s vs λ ≈ 1.85k (≥2.3× margin; requirement ≥1.2×) |
| `AUDIT_RETENTION` | **PASS** | receiver is sole durable copy; delete-at-ack verified end-to-end; anchor==receiver; 0 dup / 0 rej |
| `WRITE_AMPLIFICATION` | **PASS** | 9.98 KB/op (< ~12 KB target) *including* one-time drain work; archive's ~7.5 KB/event WAL eliminated |
| `STORAGE_LIFECYCLE` | **PASS** | audit tables converge to 0 under load; DB −15.9 GB; `oauth_token_issuances` net +481k in-window is retention-horizon timing (soak demonstrated drain 5.19M→2.5M), bounded by `retain_until` |

## 8. Known gaps / disclosures

- **`target_miss` on the integrated run**: 1,016 dropped iterations (0.031 %) — k6 arrival scheduler hit transient VU saturation during the heaviest drain overlap. Business/HTTP errors were 0 and latency was unchanged; flagged honestly rather than re-run.
- **In-run sidecars produced no evidence**: `argon2`/`meta` sidecar k6 logs are empty (runner output lost when containers were removed); the `fapi` sidecar crashed every iteration because the main seed rewrote the shared `vectors.json` with a smaller pool — a real harness defect, now fixed by grow-only seeding (`d427343f`). The standalone `fapi10m-r2` run satisfies §9's FAPI requirements in full.
- **`pending_estimate`** remains a planner estimate (per design §10); runtime decisions use exact anchor/head/lease state — observed estimate froze mid-run while exact counts converged.
- **Test host transaction hygiene**: the tombstone episode that capped early drain at ~700/s was caused by a 17-minute seed `UPDATE` pinning the vacuum horizon — a fixture/maintenance artifact, but it demonstrates the failure mode (any long-lived transaction stalls tombstone reclamation). The bounded autovacuum params keep steady-state windows small; they cannot compensate for a permanently pinned xmin.
- The 73–105 ev/s figure from the soak report is superseded by the drain rates above; the earlier report's evidence files are unchanged and remain the record of the pre-fix behavior.

## 9. What is *not* claimed

- No 4h/8h soak was run — per instructions. Whether multi-hour behaviour stays clean (vacuum sawtooth on outbox's order index under sustained arrival, token-table growth ceilings) is asserted only for this 30-minute window; a long soak remains gated on user authorization.
- Receiver WORM durability / availability beyond this test's verify+fsync+receipt contract is not claimed.
- The drain-rate numbers are this host's; absolute values move with hardware, the shape (bounded claim, anchor-paced delete, no archive copy) does not.
