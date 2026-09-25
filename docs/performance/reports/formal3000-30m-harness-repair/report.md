# Formal 30-Minute 3000 ops/s Stability — Harness-Repair Rerun (F3000-30M-R2)

## Executive summary

| Field | Value |
|---|---|
| Verdict | **INVALID** |
| Fail class | `LOAD_MODEL_INVALID` |
| Failed gate | `capacity_gate_pass` |
| Invalidity reason | `stream_evidence_invalid: diag_overflow` — the k6 point-stream diagnostic artifact (`*.diag.jsonl.gz`) exceeded the analyzer's 512 MiB logical-byte budget (512,000,000 B); 8,587,268 points were rejected at write time |
| Scope of invalidity | Evidence-artifact truncation only. Every other pre-registered check — provenance, timing, sampler health, sidecar readiness/timing, measurement-cohort integrity, stability cliffs, audit queue, refresh invariants — **passed** |
| Rerun | None. `F3000-30M-R2` is a unique formal point; the protocol permits exactly one execution, and it is consumed |

This run does **not** establish `FORMAL_30M_3000_STABILITY = PASS`. The healthy SUT metrics below are diagnostic context only; a truncated required-evidence artifact cannot certify a formal point.

## Provenance (all PASS)

| Check | Value |
|---|---|
| `WORKSPACE_REALPATH` | `/workspace/.hr2` (remote `jgw_bot1` via CNB dev env `cnb-n1n-1k3b2cveg`) |
| `WORKSPACE_GIT_SHA` | `ebbfa79727063d69895125f0d7c9e1e150da8cf8` |
| Compose sha256 | `a95fdab1c1d5e24e71b72b203ee6dc6a32879ef1b350afec38402ec8b8932c1c` |
| RUNNING_PID1_BINARY_SHA256 | `046c7d40861b63bdb8b75303d36b3b89d7ad0ad1cd50d86d7cec253020bba60a` |
| IMAGE_BINARY_SHA256 | `046c7d40861b63bdb8b75303d36b3b89d7ad0ad1cd50d86d7cec253020bba60a` (image `sha256:7a8a436b…`, container `93d1b588…`) |
| Expected binary sha256 | `046c7d40861b63bdb8b75303d36b3b89d7ad0ad1cd50d86d7cec253020bba60a` — **all three match** |
| `PERF_METRICS_SCHEMA` | PASS — `db_pool` and `audit_queue` both present on `http://127.0.0.1:8000/__perf/metrics` via shared netns probe |
| Sampler sha set | soak `fb1e0b5a…`, proc-detail `e7c9cb73…`, residency `83d38b4d…` — all match active worktree, verified from stream meta rows |
| Prepared state | `perf-state-ready.json` written atomically after seed; all four sidecars verified `run_id` + `vectors.json`/`secrets.json` hashes before k6 exec |
| Report timestamps | `run_end (1790313896.15) ≤ report_generated_at (1790313998.74)`, Δ ≈ 102.6 s ≤ 6 h |

### Prior-run provenance contradiction — resolved

The previous run's unexplained binary hash (`046c7d40…` vs expected `bec5ff72…`) is **resolved as non-anomalous**: a fresh image built from the audited tree at `ebbfa797` still produces `046c7d40…`. The earlier `bec5ff72` expectation came from a local build whose artifact differed from the remote daemon's build for the same source. Additionally, the "binary lacks `db_pool`/`audit_queue` strings" observation was a false negative — the compiler embeds those identifiers as `movabs` immediate operands rather than contiguous rodata strings; the live endpoint serves both fields (preflight PASS). `RUNNING_PID1 == IMAGE == EXPECTED` now holds end-to-end.

## Timeline (remote host clock, epoch s)

| Event | Epoch |
|---|---|
| Driver start (`remote_host_time_start`) | 1790312034.32 |
| `run_start_epoch` (stack up + preflight begin) | 1790312075.01 |
| Preflight checks (binary, perf schema, sampler health) | …2098.80 |
| Measurement window | ≈1790312099 → ≈1790313884 (1785 s) |
| `run_end_epoch` | 1790313896.15 |
| `remote_host_time_end` | 1790313996.35 |
| `report_generated_at` | 1790313998.74 |
| `FORMAL_REAL_LOAD_TIME` (main k6 wall) | 1800.29 s |
| Total point elapsed | 1860.4 s (within 3700 s load budget) |

## Measurement cohort (stream-authoritative, complete)

The k6 point stream — not the theoretical arrival grid — is the accounting authority:

| Metric | Value |
|---|---|
| `measure_started_exact` | 5,355,005 |
| `measure_completed_exact` | 5,355,005 (started == completed ✓) |
| `measure_dropped_exact` | 0 (drops classified by real Point timestamps inside `[window_start, window_end)`) |
| `measure_scheduled_observed` | 5,355,005 |
| `measure_drop_fraction` | 0.0000 (gate ≤ 0.001 ✓) |
| `measure_rate` (completed / 1785 s) | 3000.003 ops/s (gate ≥ 2985 ✓) |
| `observed_schedule_rate` | 3000.003 ops/s — within 0.5% of target, no `GENERATOR_SCHEDULE_ANOMALY` |
| outcome counters | success 5,314,987 + fixture-flow categories; **Σ outcomes = 5,355,005 = completed ✓**, `unexpected = 0` |
| `cap_iter_ms` p50 / p95 / p99 | 6 ms / 41 ms / 135 ms (gates ≤ 100 / ≤ 250 — inside) |
| `cap_op_ms` p95 / p99 | 41 ms / 134 ms |
| `late_vu_fraction` | 0.0 (gate ≤ 0.001 ✓) |

### Rational-schedule diagnostics (non-gating, per new contract)

| Diagnostic | Value |
|---|---|
| `rational_planned_arrivals` | 5,355,000 |
| `schedule_delta_vs_rational` | +5 |
| `schedule_delta_vs_k6_scheduled_metric` | +1 |

The +5 delta is retained purely as an executor diagnostic. Under the new stream-authoritative accounting it does not gate; the identical +5 that invalidated the previous run is correctly non-fatal here.

Whole-run (non-measurement) diagnostics: 477 drops, all outside the measurement window (pre-window warmup); whole-run `drop_fraction` 8.8e-5 — diagnostic only, not gated.

## Stability analysis (30 one-minute buckets)

`SUSTAINED_CLIFF = false`; `REAUTH_HERD = false`.

- All 30 measurement buckets: 2995.1–3004.7 ops/s.
- Latency: bucket p95 ≤ 100 ms in 29/30 buckets; p99 ≤ 250 ms in 29/30.
- **One anomaly bucket (bucket 1)**: p95 = 270 ms, p99 = 707 ms, waiting_mean 192 ms — a transient in the first measurement minute immediately post-warmup, no associated checkpoint (`in_checkpoint_write_window = false`). The sustained-cliff rule (≥4 of 5 consecutive breaching buckets) is not met; isolated transients do not constitute a cliff.
- Minor isolated excursions: bucket 19 p99 = 210 ms, bucket 28 p95 = 86 ms / p99 = 219 ms — all within sustained-cliff tolerance (non-consecutive).
- Subject lifecycle: `initial_mint = 2048`, `refresh_update = 770,142`, `expired_reauth = 766` spread 18–38/min — no herd.
- `subject_reauth_rate` gate PASS.

### Checkpoints (pg_stat_checkpointer, PG18)

| Window total | Value |
|---|---|
| Timed checkpoints | 6 initiated, 5 completed inside window (6th in write phase at window end) |
| Requested checkpoints | 0 |
| `write_time` delta | 1,347.6 s cumulative across checkpoints |
| `sync_time` delta | 1.62 s |
| `buffers_written` delta | 31,016 |

No checkpoint-correlated latency cliff: buckets containing `num_done` transitions (9, 14, 19, 24, 29) show p95 29–58 ms — no material latency coupling. `CHECKPOINT_CORRELATED_CLIFF = false`.

### WAL / pool structure (diagnostics)

- `wal_writes_per_s` 1008.8, `wal_fsyncs_per_s` 1006.3, `wal_per_success` ≈ 4.68 KB, `commits_per_fsync` 2.84.
- Pool: configured 32; `checked_out` mean 24.5, max 32 (saturation reached in bursts); `waiting` mean ≈ 21/s instantaneous sampler ticks, max burst 1009 — queueing observed, no deadlock; `acquire_per_op` 6.50.
- `pg_statements_per_req` ≈ 21.

## Audit health (all PASS — full `audit_queue` observability restored)

| Metric | Value |
|---|---|
| `enqueued` | 895,378 |
| `persisted` | 895,378 (== enqueued ✓) |
| `dropped` / `dropped_required` | 0 / 0 |
| `pending_in_process` (end) | 0 |
| `queue_full` | 0 |
| `persist_batches` | 524,439; `persist_max_batch` 64 |
| Receiver reconciliation | `anchor_sequence` contiguous; DB outbox drained; journal gap = 0, dup = 0, fault = none |

## Generator resources (all PASS)

| Metric | Value |
|---|---|
| Late VU spawns | 0 (fraction 0.0) |
| Active VUs (stream bins) | mean 39.8, p95 120, max 778; first-300 s ramp max 2033 |
| k6 exit code | 0; `main_oom_killed` = false |
| Generator CPU | avg 4.6 cores, max 11.8 |
| Generator RSS | avg 19.65 GiB, max 20.63 GiB |
| Host `MemAvailable` min | 102.5 GiB (of 128 GiB) — no memory pressure |
| App RSS (proc-detail) | avg 223 MiB, max 232 MiB; app CPU ≈ 5.0 cores avg |
| Postgres RSS / CPU | ≈ 5.7 GiB avg / 8.3 cores avg |

## Sidecars (all PASS)

| Sidecar | Marker verified | k6 start | Deadline (measure_start − 5 s) | Exit | HTTP reqs |
|---|---|---|---|---|---|
| argon2 | run_id `F3000-30M-R2`, hashes OK | +15.1 s after deadline basis | 1790312094.16 | 0 | 86,376 |
| fapi | hashes OK | — | same | 0 | 269,950 |
| meta | hashes OK | — | same | 0 | 720,002 |
| refresh | hashes OK | — | same | 0 | 1,079,307 |

All four verified `perf-state-ready.json` (matching `run_id`, `vectors_sha256`, `secrets_sha256`) before exec; all started ≥ 15 s before measurement start; all `terminal_summary` present with `http_reqs > 0`.

## The single failing check — `stream_evidence_invalid: diag_overflow`

Analyzer stats for the 30-minute point:

| Field | Value |
|---|---|
| Points emitted | 165,104,262 |
| `parse_errors` | 0 |
| `reader_error` | null |
| `lag_over_5s` | 0 |
| `diag_overflow` | **true** |
| `diag_budget_exceeded` | 8,587,268 points rejected |
| `MAX_DIAG_BYTES` | 512 MiB logical cap (`checkpoint_analyze.py`) |

`checkpoint_analyze` enforces a hard diagnostic-artifact budget: after 512 MiB of logical diagnostic bytes it stops recording Point rows into `diag.jsonl.gz` (governed metrics `cap_iter_begin`/`cap_iter_end` remain fully counted in `series.json`/`window.json` — the accounting cohort above is **complete and exact**). What is lost is the tail of the raw forensic point log: 8.59 M of the ~165 M points, i.e. the last few percent of the run's fine-grained stream.

Per §9 of the pre-registered contract, formal/stability runs require `diag_overflow = false`. The artifact is truncated; therefore the point **cannot certify** `FORMAL_30M_3000_STABILITY`, regardless of how clean the cohort is. The verdict is `INVALID`, classed `LOAD_MODEL_INVALID` — a harness artifact-sizing defect, not a SUT or load-model (arrival/drop) failure.

## Evidence inventory

| Artifact | Status |
|---|---|
| `cap-cap-mixed.series.json` (binned aggregates) | complete |
| `cap-cap-mixed.window.json` (measurement cohort) | complete, `window_valid`, `cohort_valid` |
| `cap-cap-mixed.analyzer-stats.json` | complete |
| `cap-cap-mixed.diag.jsonl.gz` (19.8 MiB compressed) | **truncated at 512 MiB logical budget** |
| `summary` (k6 whole-run) | complete |
| `residency.jsonl` (72 MiB, 7,989 rows) | complete |
| `proc-detail.jsonl` | complete, 301 window samples |
| `soak-metrics.jsonl` | complete, 832 window samples |
| `audit_journal`, `audit_state`, `refresh_state` | complete, all reconciled |
| Sidecar `report/summary/state` per car | complete, exit 0 ×4 |
| Preflight + runtime provenance blocks | complete, all PASS |

## Verdict block

| Field | Value |
|---|---|
| `FORMAL_10M_3000_CAPACITY` | **PASS** (prior `F3000R2`, unchanged) |
| `FORMAL_30M_3000_STABILITY` | **INVALID** — `stream_evidence_invalid: diag_overflow` |
| `READY_FOR_MERGE` | **NO** |
| `PRIMARY_LIMIT` | **LOAD_MODEL** (evidence-artifact budget, harness-side) |
| `SUSTAINED_CLIFF` | NO |
| `CHECKPOINT_CORRELATED_CLIFF` | NO |
| `POOL_32` | PASS (`DATABASE_MAX_CONNECTIONS=32`, saturation 32/32 observed) |
| `RSA_REUSE_STATUS` | CONFIRMED_AND_PRESENT |
| `AUDIT_BATCH_STATUS` | PASS_AND_PRESENT (queue fully observable, zero drops) |
| `TOKEN_AUDIT_PREFLIGHT_STATUS` | PASS_AND_PRESENT |
| `GROUP_COMMIT_CANDIDATE` | FAIL (unchanged) |
| `COMMIT_DELAY` | 0 |
| `WAL_SYNC_METHOD_CANDIDATE` | NOT_TESTED this task (fdatasync retained) |
| `DURABILITY_CHANGED` | NO |
| `PRODUCTION_CODE_CHANGED` | NO |
| `NEXT_PRODUCTION_CANDIDATE` | NONE |

## Disposition

1. `F3000-30M-R2` is consumed and INVALID. Per protocol, **no second 30-minute formal point may be executed** in this task.
2. The 30-minute stability question remains **formally unanswered**: SUT behavior was nominally healthy throughout, but required evidence is truncated.
3. Prior `F3000-30M` remains INVALID and is superseded *for certification purposes only* — its verdict is preserved.
4. If a future task authorizes a new unique point, the harness defect to repair is the 512 MiB `MAX_DIAG_BYTES` budget vs ~590 MiB actual diagnostic volume at 3000 ops/s × 30 min (raise budget, downsample non-governed metrics, or stream-compact the diag artifact) — a tooling change, not a SUT change.
5. All production invariants stand: correctness, durability (`commit_delay=0`, `fdatasync`), audit integrity (enqueued == persisted, chain contiguous), refresh-family invariants, deactivation fencing, replay protection, pool=32 resource envelope.

---

**SUPERSEDED_EVIDENCE_CONTRACT_BY = `formal-evidence-contract-repair`**（`docs/performance/reports/formal-evidence-contract-repair`）。本报告原始 verdict `INVALID`（旧证据契约：`diag_overflow` 冒充 authoritative 证据完整性）保持不变。修复后的契约把 forensic diag 移出正式门，并对同一份原始证据离线重评（`NEW_REAL_LOAD_TIME = 0`），结果为 `PASS`——同一执行、同一证据、契约修正，不是重跑择优。
