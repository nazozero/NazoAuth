# audit-findings — single-instance-throughput-scaling

Scope: what this investigation confirmed about the fresh
`client_credentials` issuance path, what was assumed, and what remains
uncovered. Status reflects evidence collected on the remote benchmark
host only, plus the 2026-09-24 offline measurement-validity review
(`offline-review/`).

## Confirmed by evidence

- **Fresh commit path structure (baseline)**: `BEGIN → SET LOCAL
  lock_timeout='2s' → client FOR SHARE → ownership INSERT →
  nazo_persist_security_audit_event(...) → COMMIT` — serialized
  top-level statement phases inside the transaction, confirmed by
  pg_stat_statements path classes (≈1.00 per request each on A).
- **Statement-count ratio**: since-reset `SUM(calls)` over all
  roles/levels ÷ full-run HTTP: ≈19.2 baseline, ≈17.2 candidate. This
  is a statement-count ratio — **not** a serial network round-trip
  count. Source inspection supports ≈6→4 application-side command
  stages as a structural fact only.
- **Pool pressure observed**: ≈4.0 pool acquisitions per request
  (full-run 4.007–4.012; same-window ≈3.96–4.00) with
  `DATABASE_MAX_CONNECTIONS=24` < 64 VUs; mean acquire wait
  1.5–3.1 ms. `24 < 64` alone does not prove the pool is undersized —
  hold time vs downstream wait was not decomposed. (The earlier ≈4.6
  figure was a lifetime counter ÷ post-warmup cohort and is retracted.)
- **Throughput model at fixed concurrency**: successful ops/s tracks
  `VU / op_latency` at all three CPU points — a closed-loop identity,
  not root-cause proof. Fixed arrival-rate capacity was not measured.
- **CPU scaling is real but partial**: X4→X8 +52%, X8→X16 +21% (SMT).
  Recomputed in-window cores: app 3.40/4 (X4), 5.79/8 (X8), 8.84/16
  (X16); postgres 3.7–6.4 — substantially busy, not proven saturated.
- **Candidate executed correctly but gained nothing**: combined
  statement present in pgss on B points only; correctness suite (11
  fresh-path tests incl. restricted role, deactivation fencing, lock
  timeout/abort, audit-failure rollback) green on candidate;
  same-window WAL/success ≈2.6–2.7 KB on every point; audit DB
  pending=0 with `anchor_sequence = last_sequence`; no OOM/restart.
- **Revert verified byte-identical**: production `src/` under
  `crates/persistence-postgres` diffs empty vs pre-candidate `66839aa3~1`.

## Assumptions / structure notes (not independently re-proven)

- `pinset` per-task affinity was applied **after** containers started
  on their original CPU set; threads created later inherit the
  parent's mask. Spot-verified via `proc_masks` dumps; not continuously
  re-audited. The points are not native 4-CPU/8-CPU boot deployments.
- X4/X8 sets use one SMT sibling per physical core by design; X16 is 8
  physical cores × 2 SMT threads.
- App pid1 ran ≈130 threads; tid names were not captured so tokio
  worker threads vs blocking threads vs spawned tasks cannot be
  separated — reported as `unknown`, never as "N HTTP workers".
- `sis-load` sampler accounting had sign artifacts on some points
  (negative avg where cumulative counters reset); k6's own summary
  remains the load source of truth.

## Uncovered edges / gaps

- **No PostgreSQL wait-event evidence**: `pg_stat_activity` wait
  sampling was never instrumented — an independent instrumentation
  gap. Separately, `perf_event_paranoid=2` blocked kernel profiling;
  the two are different channels and neither substitutes for the
  other. `PRIMARY_SCALING_BOTTLENECK = UNRESOLVED`.
- **Receiver-side audit reconciliation logs were not preserved**: DB
  facts (pending=0, anchor=last_sequence) are reported; `Required
  lost = 0` end-to-end is **not** claimed. The current
  `receiver_log_scan` collector only captures log health (collection
  status, error markers) — no final sequence/hash/deployment facts —
  so `audit_delivery_reconciled` can only be `False` or `UNKNOWN`; no
  `True` path exists from today's evidence
  (`AUDIT_DELIVERY_RECONCILIATION = UNAVAILABLE_FROM_CURRENT_COLLECTOR`).
- **pgss deltas not derivable for old points**: archived snapshots
  lack `dbid/userid/toplevel`, and A1 crossed a `stats_reset` epoch —
  retained as since-reset observations only.
- **Phase-3 mixed workload unmeasured**: skipped per gates; nothing is
  claimed about refresh/argon2/fapi interactions under the candidate.
- A-side spread 5.78% exceeded the 5% stability gate, so even a true
  small gain could not have been certified; the recorded verdict is
  INCONCLUSIVE, and the observed B≤A ordering makes "no benefit" the
  supported reading rather than "benefit masked by noise".
- The host's outer-tenant CPU contention is invisible from inside the
  nested container; absolute numbers are comparable between points on
  this host only.
