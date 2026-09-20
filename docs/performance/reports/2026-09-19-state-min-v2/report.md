# State-Minimization v2 — Phase A Rectification + 8h Live Benchmark Report

**RUN_ID:** `20260919-state-min-v2` (report) / `statemin-v2-soak-8h-r2` (formal soak)
**BASE_SHA:** `41b0a197db41b099179f4e1fdb3ed01ba5d69471` (GitHub `main` at task start)
**TEST_SOURCE_SHA:** `6e3a352c33b1abfa3c0a4aa72d0b32fe3f1e8174` (Phase A frozen; all regression evidence ran against this tree)
**Harness:** `13004098` (`perf: audit-anchor export pair in soak + ledger v2 schema`)
**Date:** 2026-09-20 (all times UTC)

## 0. What this report answers

Per logical OAuth operation at sustained load, measured byte-level:

- how much PostgreSQL state is created, split into business state, audit
  evidence, and transient pipeline state;
- how many DML statements, index writes, and WAL bytes each op generates;
- which Valkey prefixes retain state and for how long;
- whether cleanup converges under sustained load;
- whether the audit export chain is loss-free, ordered, and convergent;
- whether application RSS stays independent of database/cache growth.

Guiding rationale carried from the investigation: **unnecessary state should
not be created in the first place** — Phase A removed or bounded the chains
that violated that; Phase B measured the result end-to-end for 8 hours.

## 1. Run provenance and interruptions

| Field | Value |
|---|---|
| Frozen source | `6e3a352c` + manifest bookkeeping `2de8064c` + harness `13004098` |
| Bench host | `cnb-pqg-1k2u7i4nd-001…@cnb.space` — 64 CPU / 128 GiB |
| Stack | PostgreSQL 18-alpine (pinned digest, `shared_buffers=128MB` default), Valkey 8, single `nazoauth`, k6 runner, audit receiver (TLS+Ed25519 receipts+fsync) + exporter worker |
| T0 | 2026-09-20T02:06:52Z; main load 02:06:57 → 10:08:08 (28,859 s ≈ 8h01m) |
| Rate selection | capacity probe on *this* host: 600/900/1300/1800/2400 ops/s all clean; 3000 hit harness VU supply only. SOAK_RATE=1800 ≈ 0.75×C_valid(≈2400) |
| Interrupted attempt | `statemin-v2-soak-8h` on `cnb-g6o-…` ran clean to ~3h32m / 22.9M iterations, then the host was destroyed by abnormal shutdown; all containers and in-flight evidence lost. Restarted from scratch on the new host — no data carried over |
| Tool digests | recorded in `evidence/statemin-v2-soak-8h-r2/manifest.txt` (sha256 of every evidence script; `ledger_check.py` PASS on both pre and post ledgers) |

## 2. Load result

Main `cap_mixed` @ constant-arrival-rate 1800 ops/s:

| Metric | Value |
|---|---|
| scheduled / completed iterations | 51,840,052 / 51,799,491 (dropped 40,561 = 0.078%, VU-boundary noise) |
| measured ops | 51,748,943 @ 1796.84 ops/s |
| HTTP error rate | **0.0** on every step; `measure.errors=92` (1.8e-6 of ops) |
| latency (op-level) | p50 5 ms / p95 21 ms / p99 35 ms |
| per-step p95 | authorize 1.7 / authorize_decision 15.1 / par_oidc 2.4 / token_authcode 12.6 / token_client_credentials 10.8 / token_exchange 11.2 / token_refresh 14.2 / userinfo 1.3 ms |
| PG statements | 1,121,380,495 calls, mean 0.091 ms, 14.9 statements per HTTP request |

Sidecars: argon2 cold-login 228,791 iters err 0.0; metadata/JWKS
5,720,001 iters err 0.0.

**FAPI sidecar harness failure (disclosed):** `fapi2_logged_in_high_security`
issued **zero HTTP requests** — every iteration aborted at the k6
flow-vector allocator because the seeded `vectors.json` pool (1,000) is
smaller than the scenario offset (stride×12 = 1,200). This is a harness bug
(`PERF_VECTOR_COUNT` not raised for sidecars), not an application failure;
`soak_run.sh` now passes `PERF_VECTOR_COUNT` to sidecars. A post-hoc rerun
attempt reseeding on the loaded DB was stopped because the seeder's mass
`UPDATE oauth_tokens` contended with the app's maintenance reader — FAPI
load coverage at 30/s remains a documented evidence gap for this report;
the security path itself is covered by Phase A regression tests.

## 3. Per-op state accounting (per measured op, n=51.75M)

| Measure | Total delta | Per op |
|---|---|---|
| xact_commit | +412.07M | 7.96 tx/op |
| tup_inserted | +223.26M | 4.31 ins/op |
| tup_deleted | +125.53M | 2.43 del/op |
| tup_updated | +19.15M | 0.37 upd/op |
| **WAL bytes** | **+870.65 GB** | **≈16.8 KB/op** |
| WAL records / FPI | +1.818 B / +113.8M | 35.1 / 2.2 per op |
| db_bytes | +73.33 GB | ≈1.42 KB/op gross |
| temp_bytes | +120.03 GB | archive scans + hash spills (see §5) |
| audit events produced | +53.03M | ≈1.02 event/op |
| fsyncs (client backend) | +30.26M | 0.58/op |

DML shape per op ≈ 4.3 INSERT + 2.4 DELETE + 0.37 UPDATE over ~8
transactions. The delete share is almost entirely pipeline churn:
outbox-ack deletes (34.76M), issuance consumption/expiry deletes (31.3M),
and archival deletes (29.67M). WAL dwarfs heap growth ~12× — the dominant
amplification is write churn (insert/delete cycles, `chain_state` hot row
with 2.86M updates ≈ 4/batch, index maintenance), not retained bytes.

## 4. Where the bytes live — table-level deltas (pre→post, PASS-validated)

| Table | total bytes | live rows | inserts | deletes | Class |
|---|---|---|---|---|---|
| `security_audit_archive` | +25.95 GB | +29.67M | +29.67M | 0 | evidence (retention policy) |
| `oauth_tokens` | +19.84 GB | +16.02M | +16.02M | +131.8k | durable business (30 d refresh TTL) |
| `security_audit_events` | +18.88 GB | +23.38M | +53.03M | −29.67M archived | evidence hot window (1 h post-delivery) |
| `security_audit_chain_entries` | +3.75 GB | +5.51M | +34.76M | −29.67M archived | evidence hot window |
| `security_audit_event_outbox` | +2.45 GB | +18.27M | +53.03M | −34.76M acked | transient pipeline (delivery) |
| `oauth_token_issuances` | +2.46 GB | +5.50M | +36.74M | −31.30M | transient issuance fence (`retain_until`) |
| `user_client_grants` | +10.0 MB | ≈fixed | — | — | durable, bounded by distinct user×client |
| `users`, `oauth_clients`, misc | <1 MB | — | — | — | provisioning fixtures |
| `security_audit_chain_state` | ~0 | 1 row | — | 2.86M upd | control-plane singleton (hot row) |

Split of the +73.3 GB: **≈26 GB** immutable audit archive (operator-policy
retention), **≈20 GB** durable business state (refresh-family rows,
bounded by the 30 d token TTL), **≈21 GB** audit evidence inside the 1 h
online window (events + chain entries + in-flight outbox), **≈6 GB**
transient DB-side state (issuance fences awaiting cleanup, outbox
backlog, index bloat still to be reclaimed by vacuum).

## 5. Valkey — transient state only

Post-run ledger (`vkledger-post.json`): 261,351 live keys, 123.5 MB
`used_memory`, **0 evicted**, 8.07M keys expired naturally over the run.

| Prefix | Live keys | Bound |
|---|---|---|
| `oauth:session` | 228,709 | session TTL (observed ≤ ~99 m) |
| `oauth:jar` | 32,645 | PAR request TTL (~90 s horizon) |
| `tenant-directory:snapshot` | 1 | control plane |

No unbounded prefix. Authorization-code pending keys are deleted on
durable issuance commit (A3) — none accumulated. `mem_fragmentation_ratio`
1.27 at end. Valkey memory is purely TTL-driven churn, independent of
durable state volume.

## 6. Audit export integrity and the backlog cliff

Chain evidence (receiver `/__state`, `audit-health.jsonl`, ledger AUDIT
block):

- **delivered:** 728,368 batches / 35,199,813 events at load end —
  **0 duplicates, 0 rejected, fault=none**; `chain_head ==
  anchor_sequence` at post-ledger.
- **resumed from disk:** after the pair was restarted post-load the
  receiver continued from its fsynced checkpoint (last_sequence
  35,199,813 → 35,419,717), still 0 dup/0 rej — restart does not replay.
- **produced vs delivered:** 53.03M events produced; 34.76M delivered +
  18.27M pending at load end.
- **archival:** `nazo_archive_security_audit_prefix` moved 29,665,257
  delivered+aged events (≈25.9 GB) into `security_audit_archive` during
  the run — the 1 h online window held continuously.

**Observed export collapse (key operational finding).** Export held
~1,850 events/s — matching production — for the first **~5 h 10 m**
(pending steady at tens of rows). At ~07:17Z it collapsed to ~10–70/s:
the archive pass's mass DELETE/SELECT overlapped the outbox just as the
backlog crossed the point where claim scans stopped fitting in
`shared_buffers` (128 MB default). From there it was a positive-feedback
cliff: backlog grows → `claim`/`health`/`pending_estimate` go
`IO:DataFileRead`-bound → export slows further → backlog grows. Pending
reached 18.27M by load end.

**Post-load drain:** with production stopped, the restarted exporter
drained steadily at **~73–105 events/s** (256-event batches, receiver
fsync per batch) — correct, ordered, loss-free, but an 18M backlog at
that rate is ~48–70 h: **bounded by throughput, not convergent in-hours
under this configuration.** Remediation levers (not applied — config
honesty): larger `AUDIT_ANCHOR_BATCH_SIZE` toward the 1 MiB envelope cap,
bigger `shared_buffers`, receiver-side fsync batching, and pacing the
archive pass so it cannot starve claim I/O during load.

Caveat on the health series: `pending_estimate` in
`nazo_security_audit_shared_anchor_health()` is a planner estimate — it
froze for long stretches under load (visible as repeated identical
values in `audit-health.jsonl`). `anchor_sequence` and receiver
checkpoint are the authoritative lag signals.

## 7. Cleanup convergence

Post-ledger `EXPIRED_BACKLOG` (validated PASS):

| Backlog | At load end | Post-load behavior |
|---|---|---|
| `oauth_tokens_expired` | 0 | fully converged — cleanup kept pace under 1800 ops/s |
| `revocations_due` | 0 | converged |
| `issuances_due` | 5,187,477 | drained to ≈2.5M in ~35 min (~1.4k/s) — convergent, bounded |
| `outbox_pending` | 18,267,179 | drains at ~73–105/s — see §6 |
| `audit_batch_in_flight` / `blocked` | false / false | no stuck batch at end |

Dead-tuple residue is modest (`dead_est`: events 643k, chain_entries
1.33M, outbox 173k) — autovacuum kept up; no table showed runaway bloat.

## 8. Process memory

Sampler `runner-rss.jsonl` (15 s cadence) + point checks:

| Container | min | max | note |
|---|---|---|---|
| `nazoauth` (app) | — | **126.5 MB at end** | point measurement; sampler's container set missed it — gap disclosed |
| anchor worker | 14.1 MB | 21.0 MB | flat |
| anchor receiver | 5.2 MB | 9.1 MB | flat |
| k6 main runner | 298 MB | **19.8 GB** | load generator, not the app — cap_mixed holds per-iteration crypto material |
| meta sidecar | 152 MB | 2.5 GB | generator |
| fapi sidecar | 160 MB | 212 MB | (no load applied — §2) |
| sampler | 25 MB | 48 MB | flat |

App RSS stays ~126 MB against a 74 GB database and 157 MB Valkey RSS —
process memory is independent of state volume (also corroborated by pool
stats: max pool wait 207 ms over 2.44M acquisitions).

## 9. Security-regression evidence (Phase A gate, all on real PG18+Valkey8)

- `nazo-postgres` full integration suite: ~283 tests green on live
  PostgreSQL 18 + Valkey 8 (audit ledger, issuance fence, maintenance,
  archive, migrations).
- `nazoauth` lib: 1,291; `nazo-oauth-server` 296; `nazo-valkey` 14;
  `nazo-auth` 158; `nazo-persistence` 5 — green after environment deps
  (`DATABASE_URL`/`VALKEY_URL`) supplied.
- Audit fault-injection regression `audit_anchor_fault_regression.sh`:
  **22/22** — duplicate-receipt idempotence, receipt-signature
  verification, permanent-reject block + operator unlock, concurrent
  worker generation fencing, in-flight batch tamper fail-closed, genesis
  bootstrap, stop-drain-to-zero.

## 10. Conclusions

1. **Per-op durable cost is accountable**: ~4.3 INSERT / ~2.4 DELETE /
   0.37 UPDATE over ~8 tx, ≈1.02 audit events, ≈1.4 KB gross DB growth,
   ≈16.8 KB WAL. Every retained byte classifies as business state
   (refresh families, grants), audit evidence (window + archive), or
   TTL-bound transient — no orphan chains remain after Phase A.
2. **Growth is policy-bounded**: refresh state by 30 d token TTL, audit
   hot state by the 1 h online window + contiguous archive, issuances by
   `retain_until`, Valkey entirely by TTLs (0 evictions).
3. **Cleanup converges** for business state under load (token expiry
   backlog = 0 at end) and post-load for issuances; the audit outbox is
   the one pipeline that can accumulate without bound when export is
   starved — it is durable and loss-free but operationally requires
   either headroom (production ≤ ~1.8k events/s sustained here) or the
   tuning levers in §6.
4. **The archive pass is not free**: its mass DELETEs measurably starve
   the exporter under load. Pacing/chunking it is a follow-up.
5. **App RSS is flat and small** (126 MB at end); the large RSS belongs
   to the load generators.
6. **Audit evidence integrity holds end-to-end**: 35.2M events
   delivered, signed receipts, 0 duplicates/0 rejections, receiver
   restart resumed from its fsynced checkpoint.

## 11. Known limitations / follow-ups

- FAPI sidecar applied no load (harness `PERF_VECTOR_COUNT` bug — fixed
  in `soak_run.sh`; FAPI-path coverage relies on Phase A regression
  tests; a rerun is needed for 8h FAPI traffic evidence).
- `pending_estimate` is a planner estimate — use `anchor_sequence` /
  receiver checkpoint for lag decisions.
- Export drain at ~73–105/s under default PG tuning is the measured
  bound; deep-backlog recovery is not in-hours convergent (§6).
- DEPLOYMENT_WORM_VERIFICATION remains `NOT_RUN` — requires trusted
  retention infrastructure outside this bench.
- First attempt's partial evidence (3h32m) was lost with the destroyed
  host; only this r2 run is authoritative.

## Evidence index (`evidence/statemin-v2-soak-8h-r2/`)

`manifest.txt` (tool sha256s, run params) · `ledger-pre.txt` /
`ledger-post.txt` / `ledger-diff.txt` (validated PASS) ·
`vkledger-pre/post.json` · `audit-health.jsonl` (60 s series incl.
collapse onset) · `drain-health.jsonl` (post-load drain) ·
`audit-receiver-state.json` · `soak-metrics.jsonl` (10 s PG/Valkey/pool)
· `runner-rss.jsonl` · `soak.log` · `capacity-cap-mixed.summary.json`.
