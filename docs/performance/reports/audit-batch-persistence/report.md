# best-effort audit batch persistence — mixed A/B

Date: 2026-09-24 · Branch: `perf/audit-batch-persistence-69c79378`

## Identity

| Field | Value |
| --- | --- |
| BASE_SHA | `69c793783b261c9c783b3336909517fc915d3d3c` (source tip; carries RSA reuse) |
| RSA_BASE_SHA | `69c793783b261c9c783b3336909517fc915d3d3c` |
| COMMON_SHA | `bec5ff72dc17ae4f077fa492018435828e35bbc1` (RSA reuse + queue metrics, single-append worker) |
| BATCH_SHA | `d4f5c73478c9479b7565ce806ad562b8301f5167` (opportunistic ≤64 batch, one transaction) |
| HARNESS_SHA | `30c7f55643eb19dd21300c34fb3e69df158d0e89` |
| A image / binary sha256 | `abp-a:bec5ff72` / `a49d39bd54e355932f067e9a990a01d5b671e006ca6773c9f26ae8209c67e489` |
| B image / binary sha256 | `abp-b:d4f5c734` / `00237080631e0b16ad35782151b65fe61f0bb895715c3963992d8255ce427ae2` |

RSA native key-pair reuse is present and identical on both sides (marker
strings in both binaries, identical keyset fingerprints across all four
points on the shared `sisprsa-confirm-keys` volume). RSA is not the A/B
variable; the only production difference is the best-effort audit persist
path: `append` per event → `append_batch` in one checkout/transaction.
`AUDIT_PERSIST_BATCH_MAX = 64`; capacity 4096, workers 1, pool 24
unchanged.

## Protocol

`A1 → B1 → B2 → A2`, each `cap_mixed` constant-arrival-rate 3000/s,
duration 120s, warmup 15s, pre256/max1024 VUs, same four sidecars as the
RSA confirmation (refresh 600/s, argon2 8/s, metadata 200/s, FAPI 30/s,
each 120s). Load budget 720s. PostgreSQL 18.6, `pinset-exec` on the same
8 physical cores (app_cpus `24,26,132,134,136,138,140,142`), infra
pinned separately. Audit exporter + receiver ran through every point.

NEW_REAL_LOAD_TIME = **518.9s** (≤720s; zero failed attempts charged).

## Results

| Point | successful_ops/s | attainment vs 3000/s | p99 ms | drop frac | queue_full | queue dropped |
| --- | --- | --- | --- | --- | --- | --- |
| A1 | 2351.4 | 78.4% | 1375 | 0.211 | 42,435 | 42,435 |
| B1 | 2474.9 | 82.5% | 1206 | 0.180 | 0 | 0 |
| B2 | 2497.4 | 83.2% | 1212 | 0.160 | 0 | 0 |
| A2 | 2480.6 | 82.7% | 1240 | 0.158 | 44,906 | 44,906 |

`dropped_required` = 0 on all four points (required events never enter
the best-effort queue; unchanged semantics).

### Audit queue counters (post-drain, in-process)

| Point | enqueued | persisted | pending | batches | batch events | max batch |
| --- | --- | --- | --- | --- | --- | --- |
| A1 | 6,797 | 6,797 | 0 | 6,797 | 6,797 | 1 |
| B1 | 50,764 | 50,764 | 0 | 2,227 | 50,764 | 64 |
| B2 | 52,381 | 52,381 | 0 | 2,207 | 52,381 | 62 |
| A2 | 7,309 | 7,309 | 0 | 7,309 | 7,309 | 1 |

The single-append worker saturated at ~6.8–7.3k durable events/point and
dropped the rest (`queue_full` = dropped at `try_send`). The batch worker
persisted every enqueued event — ~22.8 and ~23.7 events per transaction
on average — with zero drops and zero post-drain pending.

### Supporting metrics (measurement window)

| Point | pool acq | wait avg ms | acq/op | WAL bytes | WAL/success | journal events |
| --- | --- | --- | --- | --- | --- | --- |
| A1 | 1,989,243 | 73.7 | 6.94 | 1.01 GB | 4,105 | 363,973 |
| B1 | 2,055,451 | 70.9 | 6.92 | 1.15 GB | 4,427 | 420,840 |
| B2 | 2,113,365 | 67.7 | 6.95 | 1.17 GB | 4,461 | 432,575 |
| A2 | 2,112,676 | 64.6 | 6.94 | 1.07 GB | 4,113 | 387,191 |

WAL per successful op is ~8% higher on B — expected, not a regression:
B durably writes ~7.4× more audit events per window (50–52k vs 6.8–7.3k).
The batch transaction count (~2.2k) replaced ~50k autocommits.

All four points: `unexpected=0`, `oom=false`, `restart=0`, sidecars
terminal-complete, DB outbox drained, DB head==anchor, receiver
checkpoint seq/hash/deployment equal, journal contiguous with no gaps or
duplicates, refresh invariants hold (active/scope ≤10, spent/family ≤64,
expired backlog 0). `cpu_per_success` is UNAVAILABLE for mixed by design
(journal is not a 1:1 completion counter there).

## Gates

- Reproduction (A): `queue_full` > 0 on both A points — PASS.
- Health (B): all checks in `evaluate_point` true on B1 and B2 — PASS.
- Throughput: `min(B)=2474.9 ≥ 0.97 × max(A)=2406.2` — PASS.

Verdict: **PASS** (`evidence/audit-batch-verdict.json`).

## Correctness evidence

- `nazoauth` queue-persistence unit tests: 6/6 (single event persists
  immediately, 130-burst batches ≤64 with multi-event batches, whole-batch
  retry preserving order and blocking later batches, sender-close drain,
  required-append bypasses queue, counter reconciliation).
- `nazo-postgres` audit_ledger on real PostgreSQL 18: 9/9 including
  `audit_ledger_append_batch_commits_atomically` — empty batch no-op,
  single-event path preserved, 64-event batch lands events+outbox rows,
  mid-batch event_id collision rolls back the whole batch, identical
  replay is idempotent, validation not loosened, exporter claim/ack
  works afterward.
- Driver evaluator unit tests: 12/12.
- RSA reuse: unchanged this task; `crypto` contract suite not rerun
  (no diff in `crates/crypto` since the confirmed `86c5907a`).

## Incidents and corrections

- Shared buildkit cargo caches produced identical A/B binaries twice
  (same failure mode as the RSA confirmation): cached-COPY +
  shared `nazoauth-target` mount let a stale binary survive. Resolved by
  full `--no-cache` rebuild; per-point in-container sha256 and marker
  strings verified during load.
- First evaluator run recorded FAIL on missing `audit_queue` evidence:
  the post-drain live `/__perf/metrics` fetch ran after the app was
  unreachable inside a fresh `docker run`. Corrected to read the soak
  sampler's final post-drain `audit_queue` row (`--evaluate-only` path);
  raw log `abp-run1.log` retains the superseded verdict.
- An earlier environment restart destroyed the first launch before any
  load; no load seconds were consumed by it.

## Final fields

- `RSA_REUSE_STATUS` = CONFIRMED_AND_PRESENT
- `AUDIT_BATCH_STATUS` = **PASS**
- `QUEUE_FULL_ELIMINATED` = **YES** (0 on B1 and B2)
- `TELEMETRY_DURABILITY` = COMPLETE_FOR_TEST_WINDOW
  (enqueued == persisted == batch_events, pending 0, journal contiguous)
- `MIXED_THROUGHPUT_CHANGE` = B_min/A_max = 0.998; B_mean/A_mean ≈ +2.9%
  (within-run noise band; non-regression gate ≥0.97 passed)
- `STRICT_3000_ARRIVAL_GATE` = FAIL (best attainment 83.2%)
- `PRIMARY_SCALING_BOTTLENECK_AFTER_FIX` = business DB pool contention:
  6.9 acquisitions per op with 64.6–73.7 ms mean pool wait at pool=24;
  audit persistence itself no longer saturates (single worker, batch ≤64)
- `READY_FOR_MERGE` = YES (both candidates retained on the branch)
- `DB_POOL_CHANGED` = NO · `DURABILITY_CHANGED` = NO
- `AUDIT_QUEUE_CAPACITY_CHANGED` = NO · `WORKER_COUNT_CHANGED` = NO
- `STRICT_30M_CAPACITY` = NOT_TESTED
