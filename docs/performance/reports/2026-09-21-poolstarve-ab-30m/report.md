# Pool-Starvation A/B Diagnosis — max_wal_size 1GB vs 8GB

Date: 2026-09-21
Tested source: `FINAL_CANDIDATE_SHA = dffffa32` (unchanged; no business code modified)
Report type: focused diagnostic follow-up to `2026-09-21-final-soak-6h-formal-r1`

## 1. Verdict

**`PostgreSQL WAL/checkpoint envelope undersized for this write rate`** — confirmed by
controlled A/B.

With `max_wal_size` raised 1GB → 8GB (the *only* changed variable):

| Metric (in-window, main load active) | Run A `1GB` | Run B `8GB` | Δ |
|---|---|---|---|
| Requested checkpoints | **28** | **0** | eliminated |
| Timed checkpoints | 0 | 6 | all ~300s cadence |
| Checkpoint cadence | ~63s (WAL-forced) | ~323s (timeout-driven) | 5.1× |
| Checkpoint write duty | 85.8% | 74.8% | −13% |
| Checkpoint buffers written | 175,353 | 12,001 | −93% |
| WAL rate | 9.54 MB/s | 7.09 MB/s | −26% |
| WAL FPI/s | 538 | 152 | −72% |
| Pool wait ms/s mean | 275.7 | 147.8 | −46% |
| Pool wait ms/s p99 | 2,203.8 | 1,453.1 | −34% |
| Pool wait ms/s max | 57,725.9 | 28,362.3 | −51% |
| Seconds with wait > 5,000ms | 11 (sum 289s) | 2 (sum 54s) | −82% |
| Dropped iterations | 938 (0.029%) | 487 (0.015%) | −48% |
| vd* write await p99 | 5.00ms | 2.56ms | −49% |
| vd* write await max | 25.35ms | 10.00ms | −61% |

Per the pre-registered decision tree, this is a **deployment capacity / benchmark
environment configuration defect, not an application pool-size defect**. No
`DATABASE_MAX_CONNECTIONS`, `shared_buffers`, worker, batch-size, or hot-path change
is indicated.

## 2. Mechanism (directly demonstrated)

1. Every checkpoint in Run A was **requested** (WAL-capacity-driven), never timed:
   `num_requested=28, num_timed=0`, cadence ~63s ≈ `1GB / 9.54MB/s ÷ completion spread`.
   The checkpointer ran at 85.8% write duty for the entire run.
2. Pool-wait seconds are dominated by **synchronous-commit WAL flush stalls**, not
   locks or CPU:
   - Top wait events, Run A: `LWLock:WALWrite` 4,121 / `IO:WalSync` 1,242 backend-seconds
     of 9,244 active samples; zero ungranted `pg_locks` samples all run.
   - Top-1% pool-wait seconds: `WALWrite`+`WalSync` = 107/135 samples; representative
     second `1789998298`: **23 of 24 active runtime backends on `LWLock:WALWrite`**.
   - Top query_ids during those seconds map to the OAuth write transaction path:
     `COMMIT` (6097083398544187049), `nazo_persist_security_audit_event`
     (−7661260436254897414), `INSERT user_client_grants` (−3849542434411556545),
     `INSERT oauth_token_issuances` (−2887139335912015367),
     `INSERT oauth_tokens` (−162905062686737477), `SELECT oauth_clients`
     (4375303120003040442).
3. Run B removed every WAL-capacity checkpoint (`requested=0`; all 6 checkpoints timed
   at ~300s = `checkpoint_timeout`), cut FPI generation 72% (checkpoint spread writes
   stop forcing full-page images), reduced WAL 26%, and halved both pool wait and
   drops — **without touching durability** (`synchronous_commit=on`, `fsync=on`,
   `full_page_writes=on` in both runs).
4. Storage was never saturated: vd* write await p99 5.0ms (A) / 2.6ms (B), utilisation
   low; `client backend` fsync ≈1,056/s in both runs (per-transaction commit flushes —
   the workload shape, not a defect).

### What is *not* claimed

- The 6h soak's full ~15-minute starvation window (2h05m–2h20m, ~160k drops) was **not
  reproduced** in either 30-minute run; both runs stayed under the 0.1% drop gate.
  A/B establishes that the WAL envelope materially modulates commit-path wait
  pressure; it does not prove the 15-min cliff's trigger is fully eliminated —
  that requires the next formal-length run.
- `backend_xmin` lag (max 25,813 A / 48,893 B xids) and transient xmin spikes remain
  associated phenomena, not the blocker: zero ungranted locks, zero >60s xacts,
  and waits were on WAL primitives, not snapshots.
- Per-second pool-wait vs checkpointer write-time correlation was weak in Run A —
  the envelope harm acts by keeping backends inside `WALWrite`/`WalSync` commit
  waits (walwriter cannot drain fast enough while checkpoints continuously dirty
  and re-dirty buffers), not by second-aligned I/O collisions.

## 3. Run reports (required gate items)

### Run A — `statemin-poolstarve-30m-a` (max_wal_size=1GB, formal-soak config)

| Item | Value |
|---|---|
| Window | 13:21:44Z–13:52:49Z; main load 1800s |
| Configured target | 1800 logical iterations/s |
| Scheduled / completed | 3,240,003 / 3,239,065 |
| **Measured successful ops/s** | **1,771.834** (nominal ≠ measured) |
| Dropped / fraction | 938 / **0.029%** (≤0.1% gate passed) |
| HTTP / business errors | 0 / 0 (`error_rate=0.0`, measure.errors=0) |
| Pool acquisitions/s | 9,138 |
| Pool avg wait/acquire | 0.026ms |
| Pool wait peak | 57,725.9 ms/s (ts 1789998514; 13/21 active on WALWrite) |
| Checkpoints req/timed | **28 / 0** — cadence 62.7s |
| Checkpoint write duty | 78.6% full-run / 85.8% in-window |
| WAL | 8.39 MB/s full-run, 9.54 MB/s in-window; 54,961 rec/s; 538 FPI/s |
| Top DB wait events | `LWLock:WALWrite` 4,121 · `IO:WalSync` 1,242 · `ClientRead` 1,142 |
| Top query_ids in top-1% wait secs | `COMMIT` 55 · audit persist 37 · `user_client_grants` ins 21 |
| Storage (vd* agg) | wio 1,871/s · 40.4 MB/s · await p50 0.84 / p99 5.00 / max 25.35ms |
| xmin lag max / xacts>60s | 25,813 xids / 0 |
| Ungranted locks | 0 samples |

Audit: ledger pre/post PASS · misrouted 0 · dropped_required 0 · receiver
1,169,993 batches / 3,501,967 events · dup 0 · reject 0 · fault none ·
final pending 0 · **anchor == receiver 3,501,967** · events/outbox/chain 0/0/0.
Sidecars: argon2 12,800 iters 0 drop 0 err · fapi 48,001 / 0 / 0 · meta 320,001 / 0 / 0.

### Run B — `statemin-poolstarve-30m-b` (identical fixture, only max_wal_size=8GB)

| Item | Value |
|---|---|
| Window | 13:58:30Z–14:29:30Z; main load 1800s |
| Configured target | 1800 logical iterations/s |
| Scheduled / completed | 3,240,005 / 3,239,518 |
| **Measured successful ops/s** | **1,776.478** |
| Dropped / fraction | 487 / **0.015%** |
| HTTP / business errors | 0 / 0 |
| Pool acquisitions/s | 8,446 (full-window incl. bookends) |
| Pool avg wait/acquire | 0.014ms |
| Pool wait peak | 28,362.3 ms/s |
| Checkpoints req/timed | **0 / 7** — cadence 323s |
| Checkpoint write duty | 71.4% full-run / 74.8% in-window; buffers 12,001 |
| WAL | 5.91 MB/s full-run, 7.09 MB/s in-window; 50,429 rec/s; 152 FPI/s |
| Top DB wait events | `LWLock:WALWrite` 4,447 · `IO:WalSync` 1,432 · `ClientRead` 1,501 |
| Top query_ids in top-1% wait secs | `COMMIT` 60 · audit persist 33 · `oauth_tokens` ins 11 |
| Storage (vd* agg) | wio 1,662/s · 30.9 MB/s · await p50 0.82 / p99 2.56 / max 10.00ms |
| xmin lag max / xacts>60s | 48,893 xids / 0 |
| Ungranted locks | 1 sample (single transient) |

Audit: ledger pre/post PASS · misrouted 0 · dropped_required 0 · receiver
119,742 batches / 3,497,869 events · dup 0 · reject 0 · fault none ·
final pending 0 · **anchor == receiver 3,497,869** · events/outbox/chain 0/0/0.
Sidecars: argon2 12,800 / 0 / 0 · fapi 48,001 / 0 / 0 · meta 320,000 / 0 / 0.

## 4. Configuration delta (the only intended difference)

| Setting | Run A | Run B |
|---|---|---|
| `max_wal_size` | **1024 MB (PG18 default)** | **8192 MB** |
| `checkpoint_timeout` | 300s | 300s |
| `checkpoint_completion_target` | 0.9 | 0.9 |
| `shared_buffers` | 16384 × 8kB = 128MB | 16384 × 8kB = 128MB |
| `synchronous_commit` / `fsync` / `full_page_writes` | on / on / on | on / on / on |
| `track_wal_io_timing` (observation only) | on | on |
| App pool max (`DATABASE_MAX_CONNECTIONS`) | 32 (source default, no env override) | 32 |
| Image / binary / migrations / harness / seed | identical `dffffa32` build, fresh volumes per run | identical |

## 5. Recommendation — capacity formula, not a magic constant

Size WAL envelope to the workload's write rate, not to a fixed number:

```
max_wal_size >= peak WAL rate × checkpoint interval × safety factor
```

This benchmark: ~9.5MB/s WAL × 300s × ~2 ⇒ ~5.7GB ⇒ **8GB chosen** gives ~2× margin,
which moved checkpointing from WAL-forced (~63s) to timeout-driven (~300s) as designed.
Low-throughput deployments (e.g. <2MB/s WAL) need far less; the 1GB default is only
safe when `peak WAL rate × 300s × factor ≤ 1GB`. Same discipline applies to
`min_wal_size` headroom and archive/WAL-disk capacity planning.

## 6. Follow-ups (not executed — per instruction, no second 6h)

- Re-run the formal 6h soak in a correctly-sized benchmark environment
  (`max_wal_size` per the formula above) to verify the historical 15-min cliff
  class is eliminated at duration.
- Keep `FINAL_CANDIDATE_SHA=dffffa32`; treat `max_wal_size` as deployment config.
- The 1s observer (`evidence/observer/obs1s.py`, sha256 below) is worth keeping
  as the standard pool-starvation diagnostic for future soaks.

## 7. Evidence

- `evidence/statemin-poolstarve-30m-{a,b}/` — harness summaries, ledgers,
  receiver state, soak logs, manifests.
- `evidence/observer/obs-run{A,B}-compact.jsonl` — 1-second observer samples
  compacted during evidence minimization: all scalar series at full 1s
  resolution (pg_stat_activity state/wait histograms, locks, checkpointer/WAL
  deltas, pool counters, xact/xmin); cumulative `disk`/`io` counters kept
  every 30s; per-backend `rows` arrays folded into `state_hist`/`wait_hist`.
  The 32MB raw pair was removed.
- `evidence/observer/obs1s.py` — observer source, sha256
  `b7366b224671e82bf7c0756b89227df8019fe39ab97515fbbab19c450b621270`.
