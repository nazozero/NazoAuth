# NazoAuth Current Capacity Baseline

Canonical capacity record for the current release. Every number below was
measured against `TEST_SOURCE_SHA` on a clean checkout; the full provenance
chain (git → image → binary → migration set → canonical schema) lives in
[reports/2026-09-22-current-capacity/manifest.md](reports/2026-09-22-current-capacity/manifest.md).

- `TEST_SOURCE_SHA`: `fd52b556370fa8d72ecfef35947bae8241e722e6`
- Run date: 2026-09-22/23 UTC
- Host: AMD EPYC 9K65, 64C/128G container host, kernel 5.4.241
- Topology: 1× nazoauth, 1× PostgreSQL 18 (`postgres:18-alpine`,
  `max_wal_size=8GB`, `fsync=on`, `synchronous_commit=on`,
  `checkpoint_timeout=5min`, `checkpoint_completion_target=0.9`,
  `shared_buffers=128MB`), 1× Valkey 8 (`valkey:8-alpine`, `maxmemory=0`,
  `noeviction`)
- Method: adaptive 10-minute constant-arrival-rate points
  (`perf/tools/capacity_search.py`). `PASS` = drops ≤0.1%, measured rate
  ≥99.5% of target, zero unexpected errors, p95 ≤100ms, p99 ≤250ms.
  For `cap_*` runs every gate input is the **measurement cohort**
  (iteration entry ∈ `[measure_start_ms, measure_end_ms)`): drops are
  `scheduled_arrivals − cap_iter_begin_measure`, errors are
  `cap_measure_unexpected`, latency is `cap_iter_ms`; whole-run k6
  counters are diagnostics only and k6 whole-run thresholds do not
  override a clean cohort verdict.
- Structured results: `perf/results/data/capacity/current-capacity.json`.

## Current capacity matrix (10-minute points)

| Scenario | Highest validated 10m | First fail above | measured ops/s | HTTP rps | p95 ms | p99 ms | drops |
|---|---:|---:|---:|---:|---:|---:|---:|
| `cap_mixed` (full sidecars) | 2000 | 2500 | 1998.3 | 2862 | 10.3 | 16.2 | 0.011% |
| `cap_client_credentials` | 3200 | 3400 | 3198.4 | 3198 | 7.3 | 15.2 | 0.05% |
| `cap_authorization_code` | 1125 | 1250 | 1125 | 4499 | 12.2 | 17.4 | 0.012% |
| `cap_refresh_token` | 1440 | 1600 | 1441.7 | 1442 | 9.7 | 14.0 | 0% |
| `fapi2_logged_in_high_security` | 731 | 913 | 731 | 3655 | 11.0 | 17.3 | 0.007% |
| `cap_introspect` | 7812 | 8788 | 7815.1 | 7815 | 1.0 | 1.3 | 0.028% |
| `cap_revoke` | 787 | 875 | 787 | 3935 | 8.5 | 12.4 | 0% |
| `mtls_client_credentials` | 3515 | 3906 | 3515.0 | 3515 | 7.4 | 14.4 | 0% |
| `par_signed_request_object` | >=6102 | not found within ladder | 6102 | 6102 | 1.2 | 8.5 | 0% |

`cap_mixed` carries sidecars on every point: refresh 600/s, argon2 8/s,
metadata 200/s, FAPI 30/s, audit exporter + durable receiver. Its 2500
point attained 2486.7 ops/s (99.47% of target) — a borderline miss against
the 99.5% gate.

`par_signed_request_object` reached the 6-point ladder cap still passing;
no failing point was established, so the entry records `>=6102/s`, not a
maximum.

## Argon2 (`oidc_cold_login_refresh`, separate class)

Argon2 concurrency stays at 8 (not raised for a better number).

| VU | attempted login/s | successful login/s | login 503 | login p50/p95/p99 ms |
|---:|---:|---:|---:|---|
| 8 | 55.1 | 55.1 | 0 | 121.0 / 127.6 / 138.0 |
| 16 | 93.3 | 56.6 | 22,016 (`temporarily_unavailable`) | 156.1 / 255.8 / 269.8 |

At 16 VU the concurrency-8 Argon2 slot limit is the active backpressure:
39.3% of login attempts return `503 temporarily_unavailable`; all other
steps clean. This is the designed protective rejection, reported as
measured.

## Mixed sustained (30 minutes, fresh DB, all sidecars)

| Target | Measured | Attainment | Drops | p95 / p99 ms | Gate |
|---:|---:|---:|---:|---|---|
| 2000 ops/s | 1967.4 ops/s | 98.4% | 0.158% | 11.9 / 37.9 | **FAIL** |
| 1900 ops/s | 1889.1 ops/s | 99.43% | 0.091% | 11.2 / 19.2 | **FAIL** |

`STRICT_30M_CAPACITY_NOT_ESTABLISHED` — both fresh-DB runs missed only the
≥99.5% arrival-fidelity gate via periodic checkpoint-flush dips; the
measured deliveries are reported as observations, not validated capacity.
The 1900–2000 interval was not searched, so no exact maximum is claimed.
Full evidence:
[reports/2026-09-22-current-capacity/report.md](reports/2026-09-22-current-capacity/report.md).

### 2026-09-23 errata — measurement denominators and measurement-window fix

Review of the two runs above found measurement defects (numbers kept as
recorded; this is an audit note, not a re-run):

- **Inconsistent denominators.** The 2000 headline `1967.4 ops/s` used the
  k6 `Counter.rate` over the full elapsed 1800 s including warmup
  (`3,541,338/1800`), while the 1900 headline `1889.1 ops/s` used the
  evaluator window (`3,372,095/1785`). The two FAILs are therefore not
  measured on the same basis.
- **VU-local clock.** `capPhase`/bucket membership keyed on each VU's
  init timestamp, so dynamically created VUs re-lived a local warmup and
  were under-counted in the measured cohort — a unified scenario-wide
  window did not exist.
- **2000 ops/s also violated the drop gate** (0.158% > 0.1%) in addition
  to the rate gate.
- **Checkpoint phase unattributed.** "checkpoint-flush dips" was a
  plausible label, not a demonstrated mechanism; the write/sync/WAL/host
  split had not been measured.

The measurement window has since been unified (`cap-scenario-window-v1`)
and a bounded 20-minute checkpoint diagnostic was executed:
[checkpoint-jitter-remediation](reports/checkpoint-jitter-remediation/report.md).
On the corrected basis that diagnostic measured 1998.5 measured attempts/s
at target 2000 (99.93%, drops 0.080%, unexpected errors 0; whole-window
success rate 1,962.8/s) within a 20-minute window — this does not
constitute the 30-minute capacity certification, which remains
`NOT_RETESTED`. Historical results above are preserved as recorded.

### 2026-09-23 errata, revision 2 — analyzer corrections

Offline re-analysis (`reanalysis-v2/`, no new load) corrected:

- The all-load common window is only conservatively recoverable
  (`[07:12:18, 07:29:48]`, 1050 s); the earlier 07:11:50 bound was a
  container timestamp, not a measurement bound.
- Dip-time fsync correlation is client-backend **WAL commit fsync**
  cumulative wait — but ~900 ms/s is the run-wide baseline, not a dip
  anomaly; checkpointer fsync totals only 374 ms. The dip discriminator
  is the pool-wait spike, not fsync level.
- WAL/op is 4.846 KiB/op on the stated basis; the historical
  3.62 KB/op comparison is withdrawn (basis not recoverable).
- Op p95/p99 are bucketed intervals; the run is not a controlled A/B
  versus historical runs (fapi's actual workload changed with its
  vector-pool fix).
- Non-reappearance of the historical long throughput hole in this
  20-minute diagnostic is an observation, not evidence of a fix;
  runtime cause `UNRESOLVED`, remediation `NOT_PERFORMED`.

### 2026-09-23 errata, revision 3 — window/schema semantics

Final offline re-analysis (`reanalysis-v3/`, no new load; supersedes v1
and v2 derivations, raw run unchanged):

- Checkpoint-local windows are `start ± [-30,+90]` and
  `complete ± [-30,+90]` — two disjoint locals, not one continuous span;
  the middle write phase stays inside steady state.
- Steady state (common window minus checkpoint local union): 520 s,
  1,999.98 completed/s, 1,961.33 successful/s, 0 drops.
- Quantiles follow the artifact's stream-v1 histogram schema:
  steady op p95 ∈ [20,50) ms, p99 ∈ [50,100) ms.
- WAL/op: 4.844 KiB/op on the shared effective interval
  `[07:10:08, 07:29:52)`.
- capRun detection uses real `cap_*` markers; empty contract shells no
  longer misclassify non-capRun summaries.
