# Offline review — corrected derived metrics

Single derived-evidence directory for the measurement-validity corrections.
Raw run artifacts are unchanged; every figure here is recomputed from the
archived inputs and records each input's sha256.

## Contents

- `reanalyze.py` — the exact script used (run remotely on the benchmark
  host against the raw run directories; no load was executed).
- `corrected-metrics.json` — per-point corrected values, input sha256s,
  and per-value evidence limits.
- `sampler-streams.tar.gz` — `soak-metrics.jsonl` + `proc-detail.jsonl`
  for all 7 points, archived so CPU/WAL/acquire figures stay
  independently reproducible.

## Corrections vs the original metrics

| metric | original | corrected |
| --- | --- | --- |
| `wal_per_success_bytes` | `pg_stat_wal` delta over seed+load+drain ÷ 105 s measure-cohort success — mixed window, `NOT_COMPARABLE` | sampler `wal_bytes` interpolated at the exact k6 window edges ÷ same-window success: ≈ 2 620–2 700 B/op |
| `acquire/op` | lifetime counter ÷ post-warmup cohort (4.567 for X8) — rejected | full-run ratio 4.007–4.012 (background-inclusive) and same-window sampler ratio ≈ 3.96–4.00 (still background-inclusive inside the window) |
| pgss deltas | keyed by `queryid` only; A1 crossed a `stats_reset` change (1790180347.988551 → 1790180369.652601) | deltas refused; old rows kept as since-reset observations only — no precise top-level RTT totals are derived |
| `statements_per_http_request` (19.25 → 17.22) | presented as ~19 → ~17 serial network RTT | since-reset `SUM(calls)` across all roles/levels ÷ full-run HTTP — a statement-count ratio, not protocol round trips |
| CPU | original values not reproducible from archived files | recomputed from `proc-detail.jsonl` jiffies inside the k6 window (≈96–104 s coverage): app X4 3.40 / X8 5.79 / X16 8.84 cores; postgres 3.7–6.5 cores |

## Evidence limits that remain

- Thread roles: `proc-detail` captured tid+jiffies only, so the 130
  observed pid1 threads cannot be split into tokio workers / blocking
  threads / tasks. 130 threads are **not** 130 HTTP workers.
- Audit: DB pending/anchor facts are preserved per point; receiver-side
  reconciliation logs were not preserved, so no end-to-end
  required-delivery claim is made for any point.
- PG wait-event evidence was never collected (separate channel from the
  `perf_event_paranoid` restriction) and remains an open gap.
