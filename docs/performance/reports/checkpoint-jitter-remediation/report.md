# checkpoint-jitter-remediation — bounded diagnostic report

Date: 2026-09-23. Run: `ckptjitter-20m-20260923070500` (the only valid run;
two earlier attempts failed on harness defects and are preserved as invalid
evidence on the remote host under `/workspace/perf-results/`).

This report covers two separate things that must not be conflated:

1. **Measurement remediation** — the benchmark now measures every scenario
   on one explicit scenario-wide window (`cap-scenario-window-v1`).
   Implemented, regression-tested, and exercised in this run. This part is
   complete.
2. **Checkpoint runtime cause** — a bounded, stage-separated diagnostic of
   the transient throughput dips historically blamed on checkpoints.
   Evidence is reported below. No PostgreSQL tuning was performed and no
   runtime fix is claimed.

## 1. Identity

| Field | Value |
| --- | --- |
| BASE_SHA | `bb5f42c60d24c18bf71d279ad50aee4935f0cca0` (= reviewed main) |
| IMPLEMENTATION_SHA | `ed67b8d37e2e456c334d0b17d601d468e835e32f` |
| TEST_SOURCE_SHA | `f842280c3d5935ca04c889b1db89f54b02e135a1` (run executed at this SHA) |
| ANALYZER_SOURCE_SHA (revision 3) | `030df6d5b3634352f4a03e8ddfb166edd1eab0a7` — offline re-analysis only, see §9 |
| ANALYZER_SOURCE_SHA (revision 2) | `72e4b9b82d3af3cb1a08c723dcbc3eed7527e9b7` — superseded, see §8 |
| EVIDENCE_COMMIT_SHA | this commit |
| App image | `nazoauth-perf-nazoauth@sha256:4d32274115a499614f7001ddb38f6ae5eeaa5b5be4066ce05d935981612a7bfc` |
| Running binary SHA-256 | `24d8067d395c624c7677e3d8c45d8e18c8be04182177bcb4d32ede17389fa0ae` (`/usr/local/bin/nazoauth`) |
| PostgreSQL | `postgres:18-alpine@sha256:d3e1620b…c88a65b2`, PostgreSQL 18.6 |
| Valkey | `valkey:8-alpine@sha256:e0eb7c48…d1dc471c84` (reports 7.2.4) |
| Deployment | `01a0cd18-b561-7580-8cc6-a80b1829d6eb` |
| Schema | `MIGRATION_SET_SHA256=4b25e966…`, `APPLIED=84dbbfd1…` (84 migrations), `CANONICAL_PG_SCHEMA_SHA256=c0e96dba…` (pre == post) |
| Perf image runner hash | `runner.py 6707e01e…`, `soak_run.sh 4e236b3f…`, `oauth.js 0c8624cd…`, `measurement_clock.js e9ee9309…`, `checkpoint_observer.py 55109458…` — all verified equal to the checkout before the run |
| Host | AMD EPYC 9K65, 64 CPUs, 128 GiB, kernel 5.4.241-1-tlinux4, PGDATA on `/dev/md0` (19-device RAID0, XFS) |

PostgreSQL performance/durability parameters: **unchanged**
(`max_wal_size=8GB`, `checkpoint_timeout=5min`,
`checkpoint_completion_target=0.9`, `fsync=on`, `synchronous_commit=on`,
`full_page_writes=on`, `shared_buffers=128MB`, `max_connections=100`,
`wal_compression=off`, `checkpoint_flush_after=256kB`,
`wal_buffers=4MB`, `wal_sync_method=fdatasync`).
Diagnostic-only `track_wal_io_timing=on` was enabled for the run and
restored to `off` afterwards; `log_checkpoints=on` was already on and
remains on. `track_io_timing=on` unchanged.

Workload: `cap_mixed` constant-arrival-rate 2000 iters/s × 1200 s,
warmup 15 s; sidecars joined ~120 s later for 1080 s
(refresh 600/s, metadata 200/s, fapi2 30/s, argon2 8/s), audit exporter +
durable receiver enabled. Fresh cluster: `nazoauth-perf_perf_postgres_data`
was recreated (`down -v`) immediately before this run; audit backlog empty;
Valkey state fresh (no volume, no persistence).

## 2. Exact changes

- `perf/k6/measurement_clock.js` (new): lazy `exec.scenario.startTime`,
  global window `[start+15s, start+duration)`, per-VU outcome/begin/end
  accounting, named contract metrics (k6 folds tagged gauges in summary
  output), begin/end reconciliation counters.
- `perf/k6/oauth.js`: `capRun` joins the global measurement cohort;
  `capPhase`/VU-local clock kept for workload lifecycle (gap idle,
  refresh re-mint); bounded minute buckets (`bucket_count=21`, no silent
  25–30 min collapse); outcome classification
  (success / local_no_request / expected_rejection / unexpected).
- `perf/runner.py`: window-contract extraction, unified denominator,
  outcome breakdown, FIFO streaming without the open-for-read deadlock
  (`import sys`, child-shell redirection), divergence invalidation,
  JSON `/__perf/metrics` pool stats.
- `perf/tools/capacity_search.py`: gates on explicit contract window;
  missing/divergent contract → invalid.
- `perf/tools/checkpoint_observer.py` (new): 1 s fixed-dimension JSONL —
  `pg_stat_checkpointer`, `pg_stat_wal`, full `pg_stat_io` keyed by
  (backend_type, object, context), `pg_stat_activity` wait classes,
  `pg_stat_database`, app pool, host disk/CPU/mem/pressure, self-metrics.
- `perf/tools/checkpoint_analyze.py` (new): streaming analyzer producing
  reconciliation, checkpoint windows, steady-state, WAL envelope,
  timeline CSV. **Revision 2 reworked it** (shared bin policy,
  per-checkpoint windows, episode recovery, role-preserving I/O deltas,
  interval quantiles, validity propagation) — §8; **revision 3** repaired
  checkpoint-local window semantics, common-window steady state, and
  artifact histogram-schema handling — §9.
- `perf/tools/soak_run.sh`: provenance capture (source/image/binary/schema/
  params/host), `docker run` for main/sidecars (compose-run containers are
  auto-removed on exit — that destroyed historical terminal evidence),
  sidecars allowed to finish naturally with bounded waits, artifact
  collection before container stop, diagnostic PG settings restored,
  analyzer invoked at end.
- `perf/k6/checkpoint_clock_test.js`, `perf/tests/test_checkpoint_measurement.py`
  (new): offline regressions + 90 s synthetic late-VU test.
- Docs: this report + dated errata in the two canonical performance docs.

PostgreSQL performance parameter changes: **NONE**
Durability changes: **NONE**
Workload behaviour changes: **NONE** (request logic untouched; one latent
fixture defect fixed — the shared vector pool now covers the fapi sidecar's
offset segment, so fapi issued real requests for the first time; see §5).

## 3. Measurement reconciliation

Contract `cap-scenario-window-v1`, `scenario_clock_ok=1`, `divergent_vus=false`.
Window: `2026-09-23T07:10:07.733Z` → `07:29:52.733Z` (1185 s =
1200 s − 15 s warmup). Main start `07:09:48`; sidecars `07:11:48`–`07:11:50`.

> **Revision-2 correction (2026-09-23):** the line originally read
> "common window `07:11:50` → `07:29:52.733` (1082.7 s)" — those bounds were
> sidecar *container* start/end timestamps, not scenario measurement bounds.
> Refresh's own contract records `measure_start=07:12:07.388Z`,
> `measure_end=07:29:52.388Z`. Reanalysis-v2 reports: exact contract-covered
> sub-window (main ∩ refresh) `[07:12:07.388, 07:29:52.388]`; the all-load
> common window is only recoverable as **conservative container-derived
> bounds** `[07:12:18, 07:29:48]` (1050 s, `basis=conservative_bounds`,
> `exact=false`) because argon2/meta/fapi are non-capRun scenarios that emit
> no `cap_window_*` metrics. See
> `evidence/ckptjitter-20m-20260923070500/reanalysis-v3/measurement-reconciliation.json
> $.common_window` and `analyze-config-v2.json`.

| Metric | Value |
| --- | --- |
| Expected arrivals (2000/s × 1200 s) | 2,400,000 |
| Started / completed iterations | 2,398,079 / 2,398,079 |
| Interrupted | 0 |
| Dropped | 1,921 (0.080%) — all in the first ~150 s VU ramp; 0 after steady state |
| Measure-cohort attempts | 2,368,236 |
| success | 2,325,894 |
| expected_rejection (bounded-family `invalid_grant` etc.) | 390 |
| local_no_request (local guard branches, no HTTP issued) | 41,952 |
| unexpected / prepare_failed | 0 / 0 |

Same-execution-stream reconstruction of the legacy rule vs the unified rule:

| Basis | Ops in measure cohort | ops/s | Note |
| --- | --- | --- | --- |
| Legacy per-VU warmup rule | 2,360,048 | 1991.602 | audit reconstruction only |
| Unified scenario window | 2,368,236 | 1998.511 | authoritative |
| Delta | +8,188 | +6.909 | `8,188 = 8,358 − 170`: `late_vu_ops_legacy_missed=8,358` minus `pre_window_legacy_counted=170`, `post_window=0` |

So the historical headline `1967.4 ops/s` (legacy `Counter.rate` over the
full elapsed 1800 s including warmup) and `1889.129` (evaluator window)
under-counted the same physical work by ~0.3–1.6%; neither is reproduced as
a new capacity claim — they are audit comparisons only.

Gate check on the unified basis for this 20-minute diagnostic window:
measured **attempt** rate 1998.511/2000 = 99.93 % ≥ 99.5 %; drops 0.080 %
≤ 0.1 %; unexpected errors 0. Latency: HTTP p95 16.8 ms / p99 38.9 ms;
per-op (cap_measure_ms) p95/p99 from the persisted per-second buckets are
intervals — see §8, not the HTTP figures.
**The corrected measurement passes the cap_mixed gate within this bounded
run.** This is not a 30-minute capacity certification.

> **Revision-2 correction:** `1998.511/s` is measured *attempts* per second
> over the contract window (`cap_iter_begin{cohort=measure}` /
> `measurement_contract.window_seconds` = 2,368,236 / 1185). The
> whole-window *success* rate is `cap_measure_success` / 1185 =
> 2,325,894 / 1185 ≈ **1962.780/s** — the difference is the 41,952
> local_no_request iterations + 390 expected rejections, not a server
> error and not a new capacity ceiling.

## 4. Checkpoint evidence

`pg-checkpoints.log` (`log_checkpoints=on`); all events `reason=time`
(timed, not WAL-forced — distances 1.86–3.05 GB < the ≈4.21 GB segment
trigger floor(max_wal_size/(1+0.9))).

| # | start → complete (UTC) | write s | sync s | buffers | WAL distance |
| --- | --- | --- | --- | --- | --- |
| 1 | 07:13:54.85 → 07:18:24.55 | 269.22 | 0.293 | 2,433 (14.8%) + 101 SLRU | 1,899,116 kB |
| 2 | 07:18:54.58 → 07:23:24.46 | 269.43 | 0.180 | 2,292 (14.0%) + 109 SLRU | 2,928,923 kB |
| 3 | 07:23:54.17 → 07:28:24.39 | 269.84 | 0.174 | 6,135 (37.4%) + 110 SLRU | 3,123,487 kB |
| 4 | 07:28:54.06 → (after window) | — | — | — | — |

Three checkpoints are complete timed pairs inside the measurement window;
ckpt-3's complete-local window is truncated at the common-window end and
ckpt-4 has only a `starting` record (the terminal drain artifact — never a
throughput trough). **Revision-3 window semantics:** each checkpoint has
two disjoint local windows — `start_local = start + [-30 s, +90 s]` and
`complete_local = complete + [-30 s, +90 s]` — clipped to the all-load
common window `[07:12:18, 07:29:48]`; `local_union` is the deduped union
of the two and never includes the middle write phase between them
(revision-2 wrongly used one continuous `start−30 → complete+90` span):

| Checkpoint | start_local (UTC) | complete_local (UTC) | union bins | min completed/s | hole_area (ops) | episodes |
| --- | --- | --- | --- | --- | --- | --- |
| ckpt-1 07:13:54.85→07:18:24.55 | 07:13:25–07:15:24 | 07:17:55–07:19:54 | 238 | 1,946 | 927 | 12 (all 1–2 s, recovered) |
| ckpt-2 07:18:54.58→07:23:24.46 | 07:18:25–07:20:24 | 07:22:55–07:24:54 | 238 | 1,741 | 1,382 | 14 (all 1–2 s, recovered) |
| ckpt-3 07:23:54.17→07:28:24.39 | 07:23:25–07:25:24 | 07:27:55–07:29:48 (truncated at common end) | 232 | 1,741 | 1,433 | 10 (all 1–2 s, recovered) |
| ckpt-4 07:28:54.06→(no complete) | 07:28:25–07:29:48 (truncated; drain artifact, `evidence_sufficient=false`) | — | 83 | 1,960 | 263 | 2 |

Source: `reanalysis-v3/checkpoint-windows.json $.checkpoints[]`
(`start_window`, `complete_window`, `local_union` — each with
`requested_interval`, `effective_interval`, `selected_bins`,
`covered_bins`, `missing_bins`, `min_completed_s`, `hole_area_ops`,
`episodes`).

Dips inside checkpoint *middle write phases* — bins between `start+90`
and `complete−30`, i.e. NOT checkpoint-local — remain visible separately
inside steady state: 1,712/s @07:21:28 (ckpt-2 write phase), 1,810/s
@07:26:06 (ckpt-3 write phase) are the deepest; 40 of the 42 steady-state
dip bins lie inside checkpoint middle phases and 2 predate ckpt-1
(`steady-state.json $.dips_in_steady`). Each is an isolated 1–2 s episode
that recovers; completion totals catch up afterwards.
Dip bins correlate with: app pool wait spiking (dip-bin range
0.018–158.5 s/s; all-window median ≈1.58 s/s, p95 ≈16.7 s/s),
`write_bytes` bursts up to 178 MB/s near checkpoint completion,
Dirty 65–182 MB, iowait ≈0, WAL generation steady ≈9.9 MB/s.
Client-backend WAL `fsync_time` is ~900 ms/s at the dip bins — but it is
also ~900 ms/s *everywhere else* (median 902, p5 840, p95 945 ms/s
across the window): cumulative commit fsync wait of ~0.45 ms per commit
at ~2,000 commits/s. It is a sustained baseline, not a dip-specific
elevation, so fsync level does **not** discriminate dip seconds from
steady seconds. All figures are recomputable from
`reanalysis-v3/wal-envelope.json` (`$.pool.wait_ms_per_s_median`,
`$.pool.wait_ms_per_s_p95`, `$.pool.wait_ms_per_s_at_dip_bins`,
`$.io.client_backend_wal_fsync_ms_per_s_at_dips`).

> **Revision-2 correction:** the v1 text attributed "≈900–950 fsync ms/s"
> to checkpoint fsync. Recomputed per `(backend_type, object, context)`:
> virtually all fsync time is **client-backend `object=wal`** commit fsync
> (1,439,644 fsyncs / 1,059.6 s cumulative over the effective window;
> `wal-envelope.json $.io.by_dimension["client backend|wal|normal"]`);
> checkpointer fsync totals only 374 ms. And the earlier "fsync spikes at
> dips" claim is further weakened: the ~900 ms/s figure is the run-wide
> baseline (median 902 ms/s), not a dip anomaly. What actually
> distinguishes dip bins is the pool-wait spike plus their placement
> inside checkpoint write phases.

Steady state — **common-window bins minus the union of checkpoint local
windows** (`basis=common_window_minus_checkpoint_local_windows`; NOT
checkpoint-free — the middle write phases remain inside): 520 of the
1,050 common bins remain, completed 1999.983 ops/s, successful
1961.331 ops/s, unexpected 0, drops 0 (the pre-common VU-ramp drops are
outside the common window by construction). 42 dip bins sit inside steady state (40 inside checkpoint middle
write phases, 2 predate ckpt-1) and are listed under `dips_in_steady`.
op p95 interval [20, 50) ms —
bucketed stream-v1 (`v < bound`, `[lo,hi)`), not exact.
Source: `reanalysis-v3/steady-state.json`.

WAL envelope (observer `pg_stat_wal` counter deltas clipped to the
measurement window's effective interval `[07:10:08, 07:29:52)` — counter
*publication* deltas, not physical I/O timings): mean 9.91 MB/s
(11.74 GB / 1184 s covered), 1 s peak counter rate 113.5 MB/s,
rolling-volume peaks 10 s 202.1 MB / 300 s 3.23 GB / 600 s 6.34 GB (time
windows, not sample counts); `stats_reset` segments unbroken.
Source: `reanalysis-v3/wal-envelope.json`.
`wal_write_time`/`wal_sync_time` were null in this PG18 observer capture
→ reported as unavailable, not zero.

Causal statement (bounded): transient dips of ~86–97 % of target lasting
1–2 s exist and sit inside checkpoint write phases — both inside
checkpoint-local transient windows AND inside the middle write phase
(kept distinct in v3); the distinguishing runtime signal at dip bins is
a pool-wait spike. WAL commit fsync is a constant ~900 ms/s baseline and
does not differentiate dips. At 1 s resolution the evidence does not
separate DataFileWrite backpressure, commit-path contention, or
scheduling effects; the specific phase is **UNRESOLVED**. No runtime
remediation performed. "The long historical throughput hole did not
reappear" is an observation about this run, not evidence that the old
issue is fixed.

## 5. Safety / invariants

- Audit: receiver accepted 55,684 batches / 3,580,431 events,
  `duplicates=0`, `rejected=0`, `pending_estimate=0`; chain
  `ins=del=3,580,431`; drain ok.
- Refresh: 4,593 live families, `max_active_per_scope=10` (≤10),
  `spent_max_per_family=64` (≤64), `expired_backlog=0`, revoked 0.
- PostgreSQL: deadlocks 0, rollbacks 1, temp_bytes 0, no xact >60 s.
- WAL/op (**revision-3 corrected**): `pg_stat_wal.wal_bytes` deltas inside
  the effective interval `[07:10:08, 07:29:52)` = 11.74 GB over 1184 s;
  divided by measure-cohort begins on the *same* effective interval
  (2,366,235) ≈ **4960.0 B/op = 4.844 KiB/op**
  (`wal-envelope.json $.wal_per_op`; numerator and denominator now share
  `effective_interval` — v2 mixed midpoint-clipped and bin-effective
  extents). The numerator includes WAL generated by *all* scenarios and
  background work; the denominator counts only main-scenario
  measure-cohort begins (sidecar ops and local_no_request iterations are
  not in it). The earlier "≈3.58 KB/op" figure used a different window
  and denominator. **It is not comparable to the historical 3.62 KB/op
  claim** — that historical number's numerator window, operation
  denominator, sidecar coverage and unit convention are not recoverable,
  so no direct comparison is made.
- App RSS at end ≈141.9 MB; restarts 0; no OOM.
- Sidecars: argon2/meta/fapi/refresh all exit 0 with terminal summaries
  (first run where that evidence exists). Actual sidecar load:
  refresh 647,786 iters / 648,190 HTTP req (599.8 iters/s, 215 ramp drops,
  unexpected=0); meta 216,001/432,002; argon2 8,641/51,846;
  fapi 32,400/162,000 — fapi issued real requests for the first time.
  The vector-pool offset fix changed the *actual* workload of this run
  relative to any historical run whose fapi sidecar failed locally; the
  declared request recipe did not change, but "recipe unchanged" does
  not mean "workload unchanged". There is no per-run evidence that all
  historical fapi sidecars issued zero requests, and this run is not a
  controlled measurement-only A/B against them.
- pg_stat_statements top cumulative: audit persistence
  (`nazo_persist_security_audit_event` 3.31 M calls, 0.172 ms mean).
  The pre/post pgss snapshots bracket the whole run including sidecar
  startup and any mid-run stats activity — they are **not** a
  common-window net delta and are not presented as one.

## 6. Evidence gaps / caveats

- The in-container digest loop in `soak_run.sh` recorded `unavailable`
  because the helper perf container used for the exec had been removed
  before the run; image↔source hash equality was verified out-of-band
  immediately before launch (identical sha256 for all five harness files).
- `docker stats` reports 0 under this rootless cgroup-v1 host; host
  CPU/disk/mem evidence comes from `/proc` via the observer instead.
- ckpt-3's complete-local window is truncated by the end of the all-load
  common window; its statistics are marked accordingly.
- The 310 MB `capacity-cap-mixed.diag.jsonl.gz` diagnostic stream is
  retained on the remote host (`/workspace/perf-results/
  ckptjitter-20m-20260923070500/main/`, sha256
  `d99d38339ccf09b26a39da4bbcd88cfee5c1535dcf4f1156d95ee3c80db84e2b`);
  the fixed-dimension 1 s observer series is committed here compressed.
- Two earlier attempts are preserved on the remote host as invalid runs
  (`055713`: stale perf image → runner NameError before load;
  `061800`: missing `/perf-state` mount → sidecars dead at init; its main
  20 min load and observer series are valid standalone evidence but the
  run does not satisfy the all-sidecars gate).
- **Unrecoverable in revision-3 reanalysis** (`reanalysis-v3/REANALYSIS.json
  $.unrecoverable`):
  - exact scenario measurement bounds of the argon2/meta/fapi sidecars —
    non-capRun scenarios emit no `cap_window_*` contract metrics, so their
    windows exist only as container-derived bounds; the all-load common
    window is therefore `conservative_bounds`, not exact;
  - sub-second placement of events inside a 1 s series bin;
  - exact op-latency quantiles — only bucketed per-second histograms were
    persisted, so p95/p99 are reported as containing intervals;
  - `pg_stat_wal.wal_write_time`/`wal_sync_time` were null in this
    capture — reported as unavailable, not zero;
  - the saved main contract carries `measure_offset_ms=null` (the
    `cap_window_offset_ms` naming defect fixed in this revision) — the
    bound fields themselves were consistent and are trusted.

## 7. Verdict

```
CORE_CLOCK_ACCOUNTING        = REPAIRED (single scenario window, cohort
                               accounting reconciles exactly: begins ==
                               ends == 2,368,236; named counters equal
                               stream reconstruction)
EVALUATOR_VALIDITY           = REPAIRED (contract enforced strictly;
                               INVALID aborts search; non-capRun uses a
                               labelled full-scenario basis; no fallback
                               denominators remain)
CHECKPOINT_ANALYSIS_VALIDITY = REPAIRED (per-checkpoint start/complete
                               local windows with the middle write phase
                               kept separate, common-window steady state,
                               episode recovery, WAL reset breaks,
                               role/dimension-preserving I/O deltas,
                               artifact-schema bucketed-quantile
                               intervals)
HISTORICAL_COMPARABILITY     = PRESERVED (raw evidence untouched; v1 and
                               v2 derived artifacts kept alongside
                               reanalysis-v3; legacy-vs-unified
                               reconciliation 8,188 = 8,358 − 170
                               unchanged)
CHECKPOINT_RUNTIME_CAUSE     = UNRESOLVED (dips sit inside checkpoint
                               write phases and coincide with pool-wait
                               spikes; WAL commit fsync is a constant
                               ~900 ms/s baseline, not dip-specific;
                               no causal experiment)
RUNTIME_REMEDIATION          = NOT_PERFORMED (no PostgreSQL/durability/
                               workload change; measurement repair is
                               not a runtime fix)
STRICT_30M_CAPACITY          = NOT_RETESTED
```

## 8. Revision-2 reanalysis (2026-09-23)

All revision-2 numbers were produced offline by
`perf/tools/checkpoint_analyze.py` at `72e4b9b8…` (commit
`fix(perf): correct checkpoint analysis windows and validity`) over the
original evidence files — **zero new workload time**. Outputs live in
`evidence/ckptjitter-20m-20260923070500/reanalysis-v2/` with input
hashes and provenance in `REANALYSIS.json`. Revision-1 artifacts remain
untouched next to it.

| Item | v1 value | v2 corrected | Source |
| --- | --- | --- | --- |
| All-load common window | `07:11:50→07:29:52.733` (1082.7 s, container ts) | conservative `[07:12:18, 07:29:48]` (1050 s); exact contract sub-window main∩refresh `[07:12:07.388, 07:29:52.388]` | `measurement-reconciliation.json $.common_window` |
| Checkpoint windows | merged union reported as 4 windows | per-checkpoint ids ckpt-1..4; ckpt-3 truncated, ckpt-4 drain artifact | `checkpoint-windows.json $.checkpoints[]` |
| Hole area | 501 / 540 / 1023 ops | 1,707 / 2,403 / 2,753 ops (sum of per-episode deficits under one bin policy) | `$.checkpoints[].metrics.hole_area_ops` |
| Min completed/s | 1946 / 1963 / 1741 (+1482 artifact) | 1914 / 1712 / 1741; drain bin excluded | `$.checkpoints[].metrics.min_completed_s` |
| Recovery | 5 / 1 / 5 s from window min | per-episode, 6–14 s, all recovered | `$.checkpoints[].metrics.episodes[]` |
| fsync correlation | "≈900–950 ms/s ≈ one CPU core" at dips | ~900 ms/s is the *run-wide* client-backend WAL commit-fsync baseline (median 902 ms/s), not a dip anomaly; checkpointer fsync 374 ms total; dip discriminator is the pool-wait spike | `wal-envelope.json $.io.by_backend`, `$.pool` |
| Steady state | common-window based, p95 42.2 ms | post-exclusion bins only: 197 bins, 1990.98 completed/s, op p95 ∈ (10,20] ms | `steady-state.json` |
| WAL/op | "≈3.58 KB/op, comparable to 3.62" | 4962.8 B/op = 4.846 KiB/op on stated basis; historical comparison withdrawn | `wal-envelope.json $.wal_per_op` |
| WAL mean | 9.74 MB/s | 9.91 MB/s time-weighted over covered seconds | `wal-envelope.json $.mean_Bps` |
| In-flight boundary | not reconciled | `completed = begins + Δin_flight` holds exactly (7 → 16 in-flight) | `measurement-reconciliation.json $.in_flight_boundary` |
| Quantiles | interpolated pseudo-exact values | containing-bucket intervals + flagged estimates | `steady-state.json`, `checkpoint-windows.json` |
| measure-cohort outcomes | by_outcome summed all cohorts | filtered to `cohort=measure`; success 2,325,894 = `cap_measure_success` counter | `$.measure_cohort` |

## 9. Revision-3 reanalysis (final offline repair)

Lineage: the raw run is **unchanged**; revision-1 and reanalysis-v2 are
**superseded derived analyses** kept for provenance; reanalysis-v3
(`evidence/ckptjitter-20m-20260923070500/reanalysis-v3/`) is the current
authoritative offline derivation, produced by
`perf/tools/checkpoint_analyze.py` at `030df6d5…` — **zero new workload
time** (`NEW_REAL_LOAD_TIME = 0s`). Input hashes and provenance in
`reanalysis-v3/REANALYSIS.json`.

| Item | v2 value | v3 corrected | Source |
| --- | --- | --- | --- |
| Checkpoint window shape | one continuous `start−30 → complete+90` span (~389 s), swallowing the middle write phase | two disjoint locals `start±[-30,+90]` and `complete±[-30,+90]` clipped to the all-load common window; `local_union` = their deduped union | `checkpoint-windows.json $.checkpoints[].start_window/complete_window/local_union` |
| Window clip basis | main measurement window | all-load common window `[07:12:18, 07:29:48]` (conservative bounds — still not exact) | `$.checkpoints[].clip_basis` |
| Steady state | measurement bins minus checkpoint union: 197 bins, 1990.98 ops/s, drops 1,765 (pre-common VU ramp leaked in), op p95 (10,20] | common bins minus local union: 520 bins, 1999.983 ops/s, successful 1961.331 ops/s, drops 0, op p95 [20,50) | `steady-state.json` |
| Middle write phase | invisible (merged into checkpoint windows and excluded from steady) | kept inside steady; 40 of 42 steady dips are middle-write-phase bins incl. 1,712/s @07:21:28 and 1,810/s @07:26:06 | `steady-state.json $.dips_in_steady` |
| Histogram schema | analyzer's internal buckets applied to stream-v1 artifacts | artifact-declared stream-v1 schema (bounds `[1,2,5,…,10000]`, `v < bound` → `[lo,hi)`); unknown schema → quantiles unavailable | `steady-state.json $.histogram_schema` |
| WAL/op | 4962.8 B/op on mixed midpoint/bin extents | 4960.0 B/op = 4.844 KiB/op — numerator and denominator share `effective_interval [07:10:08, 07:29:52)` | `wal-envelope.json $.wal_per_op` |
| min_at_s | positional bin index | epoch seconds | `checkpoint-windows.json $.checkpoints[].*.episodes[].min_at_s` |
| Missing observer rows | continuity breaks never counted (`prev` cleared before check) | breaks counted; missing checkpoint bins make that checkpoint's evidence insufficient and feed validity | `analysis-validity.json` |
| Pool wait at dips | report-only figures (2.3–25.8 s/s; median ~1.54; p95 ~17.5) | machine-recomputable: median 1,582.1 ms/s, p95 16,660.4 ms/s, dip-bin range 17.5–158,478.7 ms/s with per-dip timestamps | `wal-envelope.json $.pool` |
| I/O dimensions | by_backend + by_object only | `by_dimension` keyed `backend\|object\|context` (nonzero dims only); `null_field_deltas` preserved | `wal-envelope.json $.io` |
| capRun detection | any present `measurement_contract` object classified capRun → real FAPI summary INVALID | identity from real `cap_*` markers only; all-null contract shells no longer mark capRun; `measurement_evidence` errors → INVALID | `perf/tools/capacity_search.py` |
