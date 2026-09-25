# NazoAuth Performance Benchmarks — Current Baseline

Date: 2026-09-23. This is the canonical entry point for the current
performance/storage/stability state. The per-scenario capacity matrix lives in
[performance-capacity-curve.md](performance-capacity-curve.md); this document
records the post refresh-storage-redesign steady state. Both describe the
committed production tree below — no working-diff baselines remain.

## 1. Tested version

- Historical refresh candidate fingerprint:
  `d416a1ee4595b1f9ed0fcc2201bf3c512fe4d73ae3378a7968455665954a30c5` — recovered
  exactly (`EXACT`, three independent reproductions).
- Committed refresh implementation: `50d896a8`
  (`fix(refresh): bound durable refresh state`) + `7f3bdaa4` (rustfmt only).
- Current capacity source (`TEST_SOURCE_SHA`):
  `fd52b556370fa8d72ecfef35947bae8241e722e6` — every commit after `7f3bdaa4`
  touches only `perf/` and `docker-compose.perf.yml`
  (`git diff 7f3bdaa4..fd52b556 -- crates/ migrations/ Cargo.toml Cargo.lock`
  is empty).
- Provenance chain for the current measurements: git checkout → app image
  `2bfa9c824d29` → running binary sha256
  `24d8067d395c624c7677e3d8c45d8e18c8be04182177bcb4d32ede17389fa0ae` →
  migration set sha256 `4b25e9660a74b4f62385336be5921e3636bc5c01ca3ca82ee1b8fead19f9d240`
  (84 migrations) → canonical schema fingerprint (see the current-capacity
  manifest; raw `pg_dump -s` is diagnostic only, not a stable identity).
- PostgreSQL `postgres:18-alpine`, `max_wal_size=8GB`; Valkey `valkey:8-alpine`;
  64C/128G container host; DB pool default; sustained workload `cap_mixed`
  plus refresh 600/s, argon2 8/s, metadata 200/s, FAPI 30/s sidecars, audit
  exporter + durable receiver, autovacuum on.

Current run set (report + evidence:
[reports/2026-09-22-current-capacity/](reports/2026-09-22-current-capacity/report.md)):

| RUN_ID | Duration | Result |
|---|---|---|
| capacity matrix, 8 isolated scenarios + `cap_mixed` | 600 s/point | see §2a |
| `current-capacity-final-30m-fresh` | 30 min, fresh DB, all sidecars | see §2b |
| `current-capacity-final-1900-30m` | 30 min, fresh DB, all sidecars | see §2b |
| `current-capacity-final-30m` (inherited 44.9M-event audit backlog) | 30 min | FAIL — degradation evidence (§9) |

Historical run set — the `d416a1ee…` candidate measured as a working diff
before it was committed; byte-equivalent to `50d896a8`/`7f3bdaa4`
(report + evidence:
[reports/2026-09-22-refresh-storage-redesign/](reports/2026-09-22-refresh-storage-redesign/report.md)):

| RUN_ID | Duration | Result |
|---|---|---|
| `20260922-refreshmin-10m-v2` | 10 min | PASS |
| `20260922-integrated-30m-r2` | 30 min | PASS |
| `20260922-storage-3h` | 3 h | storage PASS; raw drop gate `target_miss` (see §9) |
| `20260922-dropsfix-30m` | 30 min | PASS — repair verification |

## 2. Executive summary (current measurements, `TEST_SOURCE_SHA=fd52b556`)

- Capacity matrix (10 min/point): `cap_mixed` with full sidecars validated
  at 2000 ops/s (first fail 2500); see the
  [capacity baseline](performance-capacity-curve.md) for all nine scenarios.
- 30-minute sustained `cap_mixed` on a fresh database @2000 it/s delivered
  1967.4 ops/s (98.4% — strict arrival-fidelity gate miss); p95 11.9ms,
  p99 37.9ms, 0 unexpected errors, 0 audit queue shed, audit receiver
  anchored 5,417,360 events with 0 duplicates / 0 rejects.
- 30-minute sustained `cap_mixed` on a fresh database @1900 it/s delivered
  1889.1 ops/s (99.43% — strict arrival-fidelity gate miss by 0.07%);
  p95 11.2ms, p99 19.2ms, drops 0.091%, 0 unexpected errors, 0 audit shed,
  receiver anchored 5,218,207 events with 0 duplicates / 0 rejects.
  `STRICT_30M_CAPACITY_NOT_ESTABLISHED` — see §2b.
- The same 2000 it/s target on a database carrying a 44.9M-event inherited
  audit backlog delivered 1950.5 ops/s and shed 16,806 audit events via
  the bounded 4096 queue — all Telemetry-class (`not_queued`; zero
  `dropped_required`) — kept as degradation evidence, not a capacity
  claim (see §9).
- WAL 5.26 KB/op at 2000 ops/s mixed (gate <12KB/op); DB final 815MB
  on the fresh run.
- App RSS 91→224MB, uncorrelated with DB/WAL growth; no OOM/restart.
- Refresh durable state ~60MB after 30min mixed load; bounds 10
  families/scope and 64 spent proofs/family held on every sample.

### 2b. Fresh-DB 30-minute sustained results

| RUN_ID | Target | Measured | Attainment | Drops | p95 / p99 | Gate |
|---|---|---|---|---|---|---|
| `current-capacity-final-30m-fresh` | 2000 ops/s | 1967.4 ops/s | 98.4% | 0.158% | 11.9 / 37.9 ms | **FAIL** (rate <99.5%, drops >0.1%) |
| `current-capacity-final-1900-30m` | 1900 ops/s | 1889.1 ops/s | 99.43% | 0.091% | 11.2 / 19.2 ms | **FAIL** (rate <99.5% by 0.07%) |

`STRICT_30M_CAPACITY_NOT_ESTABLISHED`. Both fresh-DB runs missed only the
arrival-fidelity rate gate: the 2000 target delivered 1967.4 ops/s, the
1900 target delivered 1889.1 ops/s — deficits concentrate in periodic
checkpoint-flush dips while latency, pool, and backend counts stay healthy.
The gate measures arrival-schedule fidelity, not a server saturation
ceiling; neither run is a PASS and neither measured value is a "capacity"
claim. The validated sustained statement is the 10-minute matrix (§2a
capacity baseline: `cap_mixed` 2000 ops/s) plus these two observed 30m
deliveries; the 1900–2000 interval was not searched and no exact maximum
is claimed.

### 2c. Historical 3h candidate summary (provenance-labeled)

Measured under the `d416a1ee…` working diff — byte-equivalent to the
committed implementation, so it remains the long-window plateau evidence:

- 28.09M logical operations over 3 h; measured main throughput 1,784.65 ops/s
  (99.1% of the 1800/s target).
- Main p50 4.32ms / p95 11.98ms / p99 77.95ms; classified HTTP error rate
  0.0126%, all expected `invalid_grant` (retired-family semantics);
  unexpected business/security errors = 0.
- Database converges: final 509.9MB, last-hour slope −0.09MB/min.
- Refresh durable state: 43.9MB total, bounded by cap 10 families per
  (tenant,user,client) and 64 spent proofs per family.
- WAL 3.62KB/op; audit chain 29,919,738 events, receiver
  anchor == DB anchor, duplicates=0, rejected=0, pending=0.
- App RSS ~107→205MB plateau, uncorrelated with DB/WAL growth; no OOM/restart.

### 2d. Measurement contract (cap_* scenarios, `cap-scenario-window-v1`)

From the checkpoint-jitter-remediation change onward, all `cap_*` scenarios
measure on one scenario-wide window instead of per-VU clocks:

- Time origin: `exec.scenario.startTime` — identical for every VU, including
  VUs spawned mid-run by `constant-arrival-rate`. The VU-local init clock is
  retained only for workload lifecycle (warmup/gap phasing, refresh
  re-minting gating); it never decides measurement membership.
- Window: half-open `[scenario_start + measure_offset, scenario_start +
  duration)`. `measure_offset` is `CAP_WARMUP_MS` (default 15000) for
  standard runs, `CAP_MEASURE_START_MS` when a diagnostic gap is configured.
- Cohort membership is decided by iteration **entry** time. An iteration that
  enters inside the window and completes during `gracefulStop` keeps its
  cohort; completions are also recorded per-second by real completion time.
- Denominator: `cap_measure_ops / window_seconds`, where `window_seconds` is
  the emitted contract — never `Counter.rate` (total-elapsed) and never an
  evaluator's own `duration - warmup` recomputation. A `cap_*` summary
  without a consistent `measurement_contract` is INVALID.
- Outcome classes per measured iteration: `success`,
  `expected_rejection` (protocol-correct rejections, e.g. bounded-family
  `invalid_grant`), `local_no_request` (no HTTP request sent, e.g. missing
  refresh token mid-measure), `unexpected`, `prepare_failed`. Attempts are
  never relabeled as successes.
- Reconciliation: every iteration emits `cap_iter_begin{cohort,lw}` /
  `cap_iter_end{cohort,lw,outcome}`; `lw=1` marks what the legacy VU-local
  rule would have counted, so one execution stream reconstructs both the
  legacy and the unified accounting.
- Minute buckets (`cap_mN_*`) are derived from the configured duration on
  the scenario clock with an explicit overflow bucket; late minutes are
  never folded into a fixed-size last bucket.

## 3. Current storage steady state

Canonical 30 min fresh-DB run (`current-capacity-final-30m-fresh` sampler):

- Refresh durable state ~60MB: `oauth_refresh_families` 29.0MB /
  7,038 live rows, `oauth_refresh_spent_tokens` 30.1MB / ~47.5k,
  `oauth_refresh_contracts` 1.3MB / 1,160. `oauth_tokens` absent.
- Bounds held on every sample: ≤10 active families per
  (tenant,user,client), ≤64 spent proofs per family, expired spent
  backlog 0; churn converged (family inserts 608,732 − deletes 601,694
  = 7,038 live).
- Audit outbox stayed drained (pending ≈100–400; worst burst 54.8k during
  a checkpoint dip, fully recovered, zero shed).
- Valkey: ~135.7k keys / ~50MB used; TTL-only transient material
  (`oauth:session`/`oauth:jar`/`oauth:dpop`/`oauth:client_assertion`).

Long-window plateau evidence — 3h soak `20260922-storage-3h` (1,079
sampler bins) measured on the historical `d416a1ee…` candidate, which was
recovered exactly and committed; production-path byte equivalence verified:

| Phase | DB growth | Rate |
|---|---|---|
| 0–30min | +459.6MB | 15.34 MB/min (fixture warmup) |
| 30–60min | +14.7MB | 0.49 MB/min |
| 60–120min | +28.3MB | 0.47 MB/min |
| 120–180min | −5.5MB | −0.09 MB/min (net shrink) |

Final relation sizes (post-autovacuum): `oauth_token_issuances` 295.3MB
(retention-bounded issuance ledger, largest relation),
`security_audit_chain_entries` 35.7MB + `security_audit_event_outbox` 16.6MB +
`security_audit_events` 12.8MB (≈65MB reusable physical high-water, logical
rows drained to 0), `oauth_refresh_families` 23.1MB / 3,080 rows,
`oauth_refresh_spent_tokens` 20.2MB / 13,275 rows,
`oauth_refresh_contracts` 0.55MB / 452 rows.

Conclusion: database size is governed by current valid security state and
bounded retention windows, not by cumulative request history.

## 4. Refresh state

| Metric | Old model (6h formal soak) | New model (historical `d416a1ee…` candidate, 3h soak) |
|---|---|---|
| refresh relations | `oauth_tokens` 15.63GB | 43.9MB (3 tables) |
| refresh rows | 12.62M | 3,080 families + 13.3K proofs + 452 contracts |
| families | 6.64M (~25,956/user) | cap 10 per (tenant,user,client); plateau ~3,040 at t+2h11m |
| DB total | 15.97GB | 0.51GB |
| growth shape | ~2.6GB/h linear | converging; negative last hour |

- Rotation reuses the family slot; it does not create a new family.
- Contract dedupe ≈7,332:1 (3.31M family inserts → 452 live contracts).
- Spent proofs: create≈delete≈777/s in the final hour; cap 64/family;
  expired backlog 0.
- 30-day projection at this workload: refresh state ≈45–60MB; DB ≈500–600MB
  steady state, ~4× under the 2GB budget.

Growth model:
`DB(t) = B_active(scopes×10) + B_contract(unique grants) + B_spent(rotation×retention) + B_issuance(window) + B_audit_phys(high-water) + B_transient(TTL)` —
no term scales with cumulative requests.

## 5. PostgreSQL / WAL

- `max_wal_size=8GB` is the validated envelope
  ([A/B report](reports/2026-09-21-poolstarve-ab-30m/report.md)): the 1GB
  default caused requested-checkpoint storms and pool starvation; at 8GB,
  checkpoints are timeout-driven (27 timed / 1 requested in 3h).
- WAL per logical op: 5.26KB/op at 2000 ops/s mixed on the fresh-DB 30m
  run; 3.62KB/op on the historical 3h candidate at 1800 ops/s. Historical
  optimization trajectory ~16.8 → ~9.98 → ~7.79 → 3.62KB/op.

## 6. Audit

- Fresh 30m run: receiver accepted 5,417,360 events; duplicates=0,
  rejected=0; outbox pending ≈107 (in-flight at snapshot, drained to 0
  after load stop); zero `queue_full` shed.
- Backlog-degradation 30m run (`current-capacity-final-30m`, inherited
  44.9M-event pending backlog): **16,806 audit events were rejected
  `queue_full` between 00:41:22Z and 00:50:10Z and never reached the
  durable sink.** Taxonomy (verified against the run log and the event
  class table): all 16,806 carried `persistence_status="not_queued"` —
  Telemetry-class evidence (`authorization_approved` 16,474,
  `login_success` 332) on the best-effort queue path. Zero
  `dropped_required` occurred; Required-class events persist through the
  fail-closed transactional path (`record_required` → direct repository
  append) and were not lost. The run still fails as a capacity result —
  it measured the cost of shedding under a pathological inherited
  backlog and is retained as degradation/recovery evidence.
- Historical 3h candidate: 29,919,738 exported events; receiver
  `last_sequence` == DB `anchor_sequence`; duplicates=0, rejected=0,
  outbox pending=0.
- Historical 6h formal run delivered 42.2M events with the same
  anchor==receiver reconciliation
  ([report](reports/2026-09-21-final-soak-6h-formal-r1/report.md)).
- The historical ~5h10m exporter cliff (per-iteration orphan scan + archive
  contention) was fixed and did not recur in any later run
  ([report](reports/2026-09-19-state-min-v2/report.md)).
- The receiver is a test durable receiver; it is not a deployment-level WORM
  attestation.

## 7. Sidecars (historical `d416a1ee…` candidate — 3h soak / repair verify)

| Workload | Rate | 3h iterations | errors | p95 |
|---|---|---|---|---|
| refresh rotation | 600/s | 6,280,970 | 0 | 14.16ms |
| argon2 cold login | 8/s | 85,592 | 1 transient 503 | 131.4ms |
| metadata/JWKS | 200/s | 2,140,000 | 0 | 0.35ms |
| FAPI2 high-security | 30/s | 320,981 | 0 | 13.46ms |

Repair run (`20260922-dropsfix-30m`): all sidecars 0 drops / 0 errors
(argon2 14,241 iters, fapi 53,401, meta 356,001, refresh 1,067,999).

## 8. Stability / resources

Current fresh-DB 30m run (`current-capacity-final-30m-fresh`):

- nazoauth RSS: 91MB start → 224MB end; no sustained one-way growth after
  warmup; no crash, restart, or OOM.
- Pool: wait averaged 0.395ms; `pg` activity ≤26 backends; statement mean
  0.048ms — the server was never saturated.
- Valkey: ~135.7k keys / ~50MB, 0 evictions; TTL-only transient prefixes.

Historical `d416a1ee…` candidate 3h soak:

- nazoauth RSS: 107MB start → ~190–205MB plateau (max spike 245MB, final
  141MB); stable across 3h and independent of DB/WAL/key-count growth.
- Pool: ~14K acquisitions/s; per-bin avg wait ~20–50µs; one 957ms stall at
  t+7,849s coinciding with a checkpoint flush.
- Valkey: 193,507 keys / 82.0MB used, 0 evictions; prefix census —
  `oauth:session` 86,412, `oauth:jar` 51,231, `oauth:dpop` 39,336,
  `oauth:client_assertion` 16,532, `oauth:rate` 1. Transient TTL material
  only; no refresh durable state in Valkey.

## 9. Known caveats

- `current-capacity-final-30m` (inherited 44.9M-event audit backlog) is
  **degradation/recovery evidence, not a capacity result**: 1950.5 ops/s
  delivered but 16,806 Telemetry-class audit events were shed via
  `queue_full` (zero `dropped_required`; Required-class persistence is
  fail-closed and unaffected). Verdict: FAIL as a capacity claim.
- The 3h main workload recorded 115,560 dropped iterations (0.594%) —
  literally above the 0.1% gate, so the raw gate stands as `target_miss`.
  Root cause proven to be load-generator ceiling (k6 `MAX_VUS=256`, driver
  RSS 453MB→6.5GB): app-side pool wait stayed ~20–50µs/bin and p50 was flat.
  The repair run at identical rates with `MAX_VUS=512` dropped 0.0048% —
  PASS. Storage/lifecycle evidence from the 3h run is unaffected.
- One argon2 `503 temporarily_unavailable` in 85,592 iterations (00:46 UTC);
  zero recurrences in the 14,241-iteration repair run.
- `oauth_token_issuances` (295MB) is the largest relation — a
  retention-window ledger; its window sizing is a separate capacity
  parameter, not refresh state.

## 10. Retained evidence

Current-state reports:

- [Refresh storage redesign — final benchmark set](reports/2026-09-22-refresh-storage-redesign/report.md) (10min/30min/3h/repair evidence)
- [WAL/checkpoint envelope A/B](reports/2026-09-21-poolstarve-ab-30m/report.md) (`max_wal_size` 1GB vs 8GB root cause)
- [Formal 6h soak r1](reports/2026-09-21-final-soak-6h-formal-r1/report.md) — FAIL on drop gate; audit 42.2M complete; historical root-cause record
- [Final 6h soak r1](reports/2026-09-20-final-soak-6h-r1/report.md) — FAIL: required-audit loss root cause (bounded queue) + fix lineage
- [Audit retention fix / state-min v2 8h](reports/2026-09-19-state-min-v2/report.md) — historical 5h10m cliff and its elimination
- [Audit delivery & retention remediation](reports/2026-09-20-audit-delivery-retention/report.md)

Capacity baselines:

- [Current capacity baseline](performance-capacity-curve.md) — the only
  current capacity matrix; `perf/results/data/capacity/current-capacity.json`
  is its machine-readable form
- [2026-09-17](reports/2026-09-17-capacity-endurance/report.md) /
  [2026-09-18](reports/2026-09-18-capacity-endurance/report.md) capacity
  endurance runs (multi-endpoint ladder + soak baseline)
- [2026-09-19 state lifecycle](reports/2026-09-19-state-lifecycle/report.md)
  and [state minimization](reports/2026-09-19-state-minimization/report.md) —
  remediation rounds superseded by the redesign above, retained as fix lineage

## 11. Errata — 2026-09-23 measurement-window review

Audit of the 2026-09-22 current-capacity headlines found measurement
defects (historical numbers retained as recorded; this erratum does not
re-run or re-judge them):

- The two headline ops/s values used **different denominators**: the 2000
  figure (`1967.4`) is `cap_measure_ops` Counter.rate over the full
  elapsed 1800 s; the 1900 figure (`1889.1`) is count over the 1785 s
  evaluator window. They are not directly comparable.
- The measured cohort was keyed to **per-VU init time**, so late-created
  VUs were under-counted; a single scenario-wide measurement window did
  not exist. In the follow-up 20-minute diagnostic the same execution
  stream reconstructs 8,358 iterations the legacy rule missed.
- The 2000 run also failed the **0.1% drop gate** (0.158%), not only the
  99.5% rate gate.
- The "checkpoint-flush dips" attribution was **not phase-proven**; the
  write/sync/WAL/host/generator split was unmeasured.
- Sidecar terminal summaries were lost by container teardown in several
  historical runs (e.g. empty fapi k6logs), which hid a latent
  vector-pool defect that left the fapi sidecar issuing zero requests.

Follow-up evidence and the unified measurement contract
(`cap-scenario-window-v1`):
[checkpoint-jitter-remediation](reports/checkpoint-jitter-remediation/report.md).
Measurement remediation is complete; checkpoint runtime remediation was
not performed and remains unestablished.

### 2026-09-23 errata, revision 2 — analyzer/evaluator defects

Offline re-analysis of the same run
(`reanalysis-v2/`, zero new workload) found and corrected further
toolchain defects:

- The first report's "common window" (`07:11:50` start) used sidecar
  **container** timestamps, not scenario measurement bounds. The exact
  contract-covered pair is main∩refresh `[07:12:07.388, 07:29:52.388]`;
  the all-load common window is only recoverable as conservative bounds
  `[07:12:18, 07:29:48]` (1050 s) — argon2/meta/fapi emit no contract
  metrics.
- Checkpoint windows are now per-checkpoint (`ckpt-1..4`) rather than
  merged unions; the terminal drain artifact (1,482/s bin) is excluded
  from trough figures.
- The "≈900–950 fsync ms/s ≈ one CPU core" correlation is corrected:
  per-`(backend_type,object,context)` deltas show it is **client-backend
  WAL commit fsync** cumulative wait — and it is a *constant* ~900 ms/s
  baseline across the whole window (median 902 ms/s), not a dip-specific
  spike. Checkpointer fsync totals only 374 ms; the dip discriminator is
  the app pool-wait spike (up to ~26 s/s vs ~1.5 s/s median), not fsync.
- WAL/op on the stated basis is **4.846 KiB/op** (window WAL delta ÷
  measure-cohort begins); the earlier "≈3.58 KB/op comparable to 3.62"
  claim is withdrawn — the historical basis is not recoverable.
- Op-latency p95/p99 are bucketed intervals, not exact values;
  `1998.511/s` is measured *attempts* (whole-window success rate is
  1,962.780/s — neither is an error or a capacity ceiling).
- This run is **not** a controlled measurement-only A/B against
  historical runs (fapi's vector-pool fix changed its actual workload);
  "the long throughput hole did not reappear" is an observation, not a
  fix confirmation. Checkpoint runtime cause remains **UNRESOLVED**.

### 2026-09-23 errata, revision 3 — window/schema semantics

A final offline pass (`reanalysis-v3/`, zero new workload; v1 and v2 are
superseded derived analyses — the raw run is unchanged) corrected:

- Checkpoint-local evidence is two disjoint windows per checkpoint —
  `start + [-30 s, +90 s]` and `complete + [-30 s, +90 s]`, clipped to the
  all-load common window. The v2 single `start−30 → complete+90` span had
  swallowed the ~270 s middle write phase; middle-phase dips (e.g.
  1,712/s @07:21:28, 1,810/s @07:26:06) now stay visible inside steady
  state instead of being auto-excluded.
- Steady state is common-window bins minus the checkpoint local union:
  520 s, 1,999.98 completed/s, 1,961.33 successful/s, 0 drops — the
  v2 basis had leaked the pre-common VU-ramp drops.
- Histogram quantiles follow the artifact's declared stream-v1 schema
  (`v < bound`, `[lo,hi)`): steady op p50 [5,10) / p95 [20,50) /
  p99 [50,100) ms. Unknown schemas yield unavailable quantiles, never
  guesses.
- WAL/op numerator and denominator share one effective interval
  `[07:10:08, 07:29:52)`: 4,960.0 B/op = 4.844 KiB/op.
- The capacity evaluator no longer treats an all-null
  `measurement_contract` shell as capRun identity (a real non-capRun FAPI
  summary had been misclassified INVALID); stream evidence errors gate to
  INVALID.
