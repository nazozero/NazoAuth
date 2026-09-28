# Current-B incremental capacity acceptance — 2026-09-28

This continuation includes `04146234c578e61797aacee7ef7c4687b75653a1`.
It first reassessed the original selected points using the shared main,
sidecar, health and maintenance evaluator, then made targeted one-factor
load-calibration experiments. Application source, binary and migrations are
unchanged from the [original run](../2026-09-28-current-b/report.md).
The application image is reused; no application build runs during measurement.

## Offline reassessment

The [separate reassessment](../../../../perf/results/diagnostics/2026-09-28-current-b-reassessment.json)
retains original point hashes and evaluator identities. All 28 selected
measurements remain valid: 20 PASS, 8 FAIL. Both original 660-second mixed
confirmations and all four sidecars pass. Multicore mixed 2400/s additionally
fails the FAPI and refresh sidecar gates. A valid measured failure is not
automatically a demonstrated backend limit.

## Mixed calibration experiments

All rows below use one application instance allowed 16 logical CPUs, users
256, the same business/sidecar rates and data, and the same images. Success
and drops are the exact measurement-cohort values used by the evaluator;
interpolated whole-second diagnostics are not substituted for these counters.
The [calibration evidence](../../../../perf/results/diagnostics/2026-09-28-current-b-calibration.json)
records each independent recipe, effective configuration, exact main/sidecar
cohorts, component cost, analyzer lag, warning timing and source hashes.

| Offered ops/s | Main VUs | Pool | Sidecar VUs: cold/meta/FAPI/refresh | Effective s | Main success/s | Complete P95/P99 ms | Main drops | Overall gate |
|---:|---:|---:|---|---:|---:|---|---:|---|
| 2400 | 1024 | 32 | 8/16/32/64 | 180 | 2400.006 | 18/30 | 0 | PASS, all sidecars PASS |
| 3000 | 1024 | 32 | 8/16/32/64 | 180 | 2999.994 | 20/37 | 0 | PASS, all sidecars PASS |
| 4000 | 1024 | 32 | 8/16/32/64 | 60 | 3935.3 | 137/381 | 3882 | FAIL |
| 4000 | 2048 | 32 | 8/16/32/64 | 60 | 3996.317 | 62/266 | 221 | FAIL |
| 4000 | 1024 | 64 | 8/16/32/64 | 60 | 4000 | 122/450 | 0 | FAIL |
| 4000 | 1024 | 64 | 8/16/32/256 | 60 | 3985.6 | 128/443.65 | 864 | FAIL |
| 4000 | 1024 | 64 | 64/16/32/256 | 60 | 3981.05 | 174/719 | 1139 | FAIL |

The 2400/s main-VU experiment holds users, pool and every sidecar resource
constant against the original 256-VU recipe. Its longer 180-second pass
disproves use of the original 2400/s failure as a backend maximum. The
subsequent 3000/s point also passes under the same 1024-VU recipe.

At 4000/s, the 2048-VU control compares only main concurrency with the
1024-VU/pool-32 row. The pool-64 control compares only pool size with the
1024-VU/pool-32 row, not with the 2048-VU row. The next two controls separately
increase refresh-sidecar VUs, then cold-sidecar VUs. User cardinalities,
offered rates, password strength, audit and PostgreSQL durability are retained.
Different recipes are not combined into one capacity interval.

The pool-64 control completes all 4000/s main arrivals with no main drops but
still misses complete-operation latency SLO. With refresh VUs 256, refresh
completes its full 600/s offered rate with zero drops and P95 283 ms. With cold
VUs 64, cold login completes its full 8/s rate with no drops, while FAPI
completes 30/s with no drops and P95/P99 776/868 ms; refresh completes 599.63/s
with only 50 drops and P95 260 ms. The sidecar latency misses therefore do not
depend on failing to offer their workload. VU warnings are retained with their
phase rather than being used alone to label a result invalid or a backend limit.

The app used about 7.23/16 CPU and PostgreSQL 7.81/16 at the pool-32 4000/s
point, with 3.802 ms mean pool wait/acquisition. Pool 64 reduced the mean to
2.946 ms, with PostgreSQL 8.81/16 CPU; it did not remove the latency miss.
Analyzer lag remained below 0.5 seconds in these controls. PostgreSQL wait
samples include idle backends and are not wait-time or per-SQL attribution.
The 2048-VU injector reached about 18.2 GiB RSS versus about 5.4 GiB at 1024;
the visible deployment memory limit is 128 GiB. Increasing VUs indefinitely
would add cost without proving a backend ceiling.

## Accepted multicore mixed boundary

The frozen 1024-VU/pool-64/side-VU-64,16,32,256 recipe has an observed
**[3750, 4000) complete operations/s** interval. Both endpoints were verified
for 180 effective seconds. A 60-second 3750/s FAPI latency failure was followed
by a valid 180-second pass; the longer result, not the shorter failure, is used
for the final boundary. Original observations remain in the external evidence.

| Offered / effective window | Main success/s | Complete P95/P99 ms | Main drops | Sidecar result |
|---|---:|---|---:|---|
| 3750/s / 180 s | 3750.017 | 22/37 | 0 | all PASS |
| 4000/s / 180 s | 3995.583 | 31/243 | 796 | FAPI and refresh FAIL |
| 3750/s / 660 s | 3750.009 | 22/32 | 0 | all PASS; maintenance PASS |

At the upper point FAPI completes all 30/s with no drops but P95/P99
822.55/859 ms; refresh completes all 600/s with no drops but P95/P99
269/290 ms. These fully delivered populations miss their unchanged business
latency gates independently of the main VU warning during warmup. The main
drop fraction is 0.1106%, slightly beyond 0.1%. No runtime/audit health gate
fails. This establishes a configured workload SLO boundary, without attributing
it to a specific SQL statement or intrinsic hardware maximum.

The [selected checkpoint evidence](../../../../perf/results/diagnostics/2026-09-28-mixed-incremental-acceptance.json)
retains exact cohorts, per-point effective sidecar windows, image/source/tool
identity, analyzer health, component cost and input hashes. Main analyzer lag
is 0.349 s at U and 0.478 s in the confirmation, below the unchanged 5-second
observer gate. During confirmation, mean app/PG CPU is 6.908/8.053 logical CPUs
and mean pool wait is 0.037 ms/acquisition; the U wait is 1.698 ms. Sampled PG
wait counts include idle clients and do not prove a per-SQL bottleneck.

## Multicore mixed maintenance, audit and WAL confirmation

| Evidence | Result in 3750/s, 660 effective seconds |
|---|---|
| Maintenance mature interval / samples | 300 s / 143; maximum gap 2.231 s |
| Oldest expired issuance age | maximum 59.232 s, below declared 120 s SLO |
| Sampled due count first / last / maximum | 39079 / 132083 / 194730 |
| Inserted / deleted in same mature span | 983205 / 924120 |
| Process queue enqueued / persisted / dropped / pending after drain | 440084 / 440084 / 0 / 0 |
| Durable events / token-issued events, whole point | 3696610 / 2397896 |
| Journal gaps / duplicates / malformed lines | 0 / 0 / 0; both anchors reconciled |
| Generated WAL bytes (`pg_stat_wal`) | 9980130918.750 |
| WAL write bytes (`pg_stat_io`) | 22501491263.410 |
| WAL writes / fsyncs | 643515.690 / 641700.012 |
| Generated / written WAL bytes per main success | 4032.366 / 9091.490 |

Age passes across the declared retention horizon, and audit drains without
loss. The sampled due inventory grows during this finite span; the pass is
the existing expiry-age SLO, not proof of indefinitely bounded total inventory.
WAL/op includes every sidecar and background activity and uses 2,475,006 main
successes as denominator. The two WAL counters have different meanings, and
interpolated counts are fractional. WAL timing is N/A because its timing GUC
is off. Audit event totals include warmup and drain, unlike window throughput.

The original receiver journal is retained externally: 3,296,382,335 bytes,
SHA-256 `91d1f43c46433c271c25dd220534f0784f8db77d4ed3d669262c84852c1e2f43`,
equal to the runtime reconciliation hash. It is not committed to Git.

The early multicore introspect probe now validly passes 8000/s for 60 seconds,
8000 successful operations/s, complete P95/P99 1/1 ms, zero drops and analyzer
lag 1.105 s. It remains a short probe while its upper boundary and both
180-second endpoints are being established. Other scenes continue with explicit
targeted adaptive steps; this checkpoint does not replace the final 20-row table.

## Reproduction and verification

Use the [targeted runner](../../../../perf/README.md) with the recorded application
image and runner image `sha256:64b272744b87acc391c9a628ed37aa070d8517471527e6b2adc5066ae61664ef`.
The tested app source remains `ac266e7a93749694022efd1aeea6ed4d316fbbcc`.
For each table row, explicitly supply `--mode multi --scenarios cap_mixed
--rates <offered> --window <effective> --vus <main> --users 256
--pool-connections <pool> --sidecar-vus <cold> <meta> <FAPI> <refresh>`, alongside
the required future `--stop-at` timestamp and existing runner environment.
The controller allocates CPU sets from process affinity and saves independent
recipe-specific configuration and state files. Do not start an unscoped matrix.

The calibration checkpoint's [CI](https://github.com/nazozero/NazoAuth/actions/runs/36367997622)
passed on `6b6c4cbb` (Rust job 24m41s): all 11 applicable checks succeeded and the two PR-event
conditional checks were skipped. Final publication will be checked on its
own exact commit; this checkpoint's green CI is not substituted for that result.
