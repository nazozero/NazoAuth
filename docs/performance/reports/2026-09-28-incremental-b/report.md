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

The calibrated 1024-VU/pool-64/side-VU-64,16,32,256 recipe is now being bracketed
and checked at 180 seconds; its final mixed candidate will receive its own
660-second maintenance/audit confirmation. Other scenarios continue with
targeted staircase measurements. This calibration checkpoint is not the final
capacity table and does not combine its 4000/s failures with another recipe's
passing lower bound.

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

The offline checkpoint's [CI](https://github.com/nazozero/NazoAuth/actions/runs/36365317444)
passed on `dee98252`: all 11 applicable checks succeeded and the two PR-event
conditional checks were skipped. Final publication will be checked on its
own exact commit; this checkpoint's green CI is not substituted for that result.
