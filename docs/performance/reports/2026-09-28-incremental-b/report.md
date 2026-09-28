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

## Original-container multicore mixed boundary

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

## Mixed maintenance, audit and WAL confirmations

| Evidence | Single CPU: retained 600/s, 660 s | Sixteen CPUs: new 3750/s, 660 s |
|---|---|---|
| Maintenance mature interval / age samples | 300 s / 148 | 300 s / 143 |
| Maximum age sample gap | 2.056 s | 2.231 s |
| Oldest expired issuance age, maximum; SLO 120 s | 58.435 s | 59.232 s |
| Sampled due count first / last / maximum | 8413 / 8339 / 8413 | 39079 / 132083 / 194730 |
| Inserted / deleted in same mature span | 138877 / 141626 | 983205 / 924120 |
| Process queue enqueued / persisted / dropped / pending after drain | 67827 / 67827 / 0 / 0 | 440084 / 440084 / 0 / 0 |
| Durable events / token-issued events, whole point | 536367 / 335282 | 3696610 / 2397896 |
| Journal gaps / duplicates / malformed lines | 0 / 0 / 0; anchors reconciled | 0 / 0 / 0; anchors reconciled |
| Generated WAL bytes (`pg_stat_wal`) | 1371739627.976 | 9980130918.750 |
| WAL write bytes (`pg_stat_io`) | 5721142050.762 | 22501491263.410 |
| WAL writes / fsyncs | 406231.228 / 405983.228 | 643515.690 / 641700.012 |
| Main successful operations, window denominator | 396000 | 2475006 |
| Generated / written WAL bytes per main success | 3463.989 / 14447.328 | 4032.366 / 9091.490 |

Both confirmations pass across the declared retention horizon, and audit drains
without loss. Multicore sampled due inventory grows during this finite span; the pass is
the existing expiry-age SLO, not proof of indefinitely bounded total inventory.
WAL/op includes every sidecar and background activity. Due inventory is a sampled
diagnostic; age samples and inventory samples have different frequencies.
The two WAL counters have different meanings, and
interpolated counts are fractional. WAL timing is N/A because its timing GUC
is off. Audit event totals include warmup and drain, unlike window throughput.

The original receiver journal had 3,296,382,335 bytes,
SHA-256 `91d1f43c46433c271c25dd220534f0784f8db77d4ed3d669262c84852c1e2f43`,
equal to the runtime reconciliation hash. It is not committed to Git.
The old container was then closed. Its emergency full-stream transfer was
interrupted: the aggregate runtime evidence survived, but this multicore
journal and its maintenance sampler did not. That confirmation cannot be
independently replayed from the migration backup and is excluded from final
authority pending a new complete confirmation. The new deployment uses a
separate result namespace; its endpoints are never combined with old endpoints.
The retained single-CPU journal has 478,326,657 bytes and SHA-256
`45dcd4a33f270d59632022f246d5cb453a2b14eda38969947159717ac33a8d72`,
also reconciled against its original runtime hash. It is retained externally.
Its restored maintenance sampler passes offline reassessment after migration.

## Container migration and execution window

The resumed six-hour window began at 2026-09-28 09:58:28 UTC, with a hard
deadline of 15:58:28 UTC. New exploration stops by 14:28:28 UTC to reserve
90 minutes for publication and final-commit CI. The application image,
benchmark images and required fixture key material were restored without an
application build. Fixture secrets are excluded from public evidence.

The new container exposes 64 logical CPUs and 128 GiB memory. Allocation is
derived from its process affinity: application single `[24]`, application
multicore `24-39`, PostgreSQL `40-55`, Valkey `[56]`, and generator/observers
`57-79,184-191`. Each formal point still verifies actual process affinities.
Both deployments remain explicitly identified; differences in CPU numbering
or recipes are not treated as a performance improvement.

Offline reassessment of the 13 retained non-confirmation selected endpoints
preserves their original PASS/FAIL verdicts. The retained single mixed
confirmation also passes with its complete restored sampler. The multicore
confirmation's missing sampler correctly produces INVALID when replaying the
metadata-only backup; it is not converted into a service failure or success.

## Sparse sidecar observer repair

The first new-container multicore mixed 3750/s, 180-second point is INVALID:
the main stream is valid (3749.439 successful operations/s, complete P95/P99
54/95 ms), runtime and audit pass, but Argon2/FAPI stream lag reaches
22.528/6.383 seconds. This is excluded from capacity endpoints.

The multi-reader dispatcher added a second 64 KiB buffer after `read1` had
already returned an available block. Sparse input could wait for subsequent
operations or EOF before reaching consumers. Complete input blocks now reach
workers immediately, while partial trailing rows remain buffered until their
newline. No sample selection, accounting, five-second lag gate, worker
partition or business assertion is changed.

A real-worker sparse-input regression holds subsequent input for six seconds:
the old dispatcher reproduces artificial lag and fails; the repaired dispatcher
consumes the point without lag rejection. The updated CI measurement suite
passes 261 tests locally (two platform-conditional skips). Native-block,
fallback-layout, cohort, quantile and forensic-population equivalence remain
covered. The sparse-input regression is added to the existing quality job.
Affected new endpoints are measured using a new recorded runner identity.

## Accepted single-core mixed boundary

The original 600/s, 660-second confirmation remains PASS under the updated
main, four-sidecar, maintenance and audit evaluator. Its effective deployment
and workload recipe matches the new 64-VU upper points: application binary,
runner image, workload hash, CPU sets, 64 users, pool 32, seed cardinality,
60-second warmup, expiry policy and all sidecar rates/resources. The retained
raw point is unchanged; its schema predates recipe IDs, so the
[checkpoint evidence](../../../../perf/results/diagnostics/2026-09-28-mixed-cold-boundary-acceptance.json)
includes explicit equivalence and input-hash proof. Journal capture differs
between a confirmation and a short point; application audit remains enabled.

The observed frozen 64-VU interval is **[600, 650) operations/s**. At 650/s for
180 effective seconds, main success is 644.15/s with 1053 drops (0.9%) and
complete P95/P99 130/233 ms. FAPI completes every 2/s operation with zero drops
but P95/P99 181.2/273.82 ms; refresh completes every 38/s operation with zero
drops but P95 131 ms. At 675/s these sidecar failures also occur.

The one-factor 128-VU control at 650/s holds users, pool, images and sidecars
constant. Main success increases to 649.572/s with 77 drops (0.066%), satisfying
the offered-success and drop gates, but main P95 remains 130 ms. FAPI completes
every operation with zero drops and P95/P99 309/436.5 ms; refresh also has zero
drops and P95 135 ms. The latency failure therefore survives removal of the
main-VU delivery constraint. This separate control is not used as a bound in
the 64-VU interval. App/PG/load mean CPU is 0.801/1.347/0.833; mean pool wait
1.538 ms and maximum analyzer lag 0.253 s. No specific SQL or continuously
saturated CPU is inferred from these averages.

## Accepted multicore cold Argon2 boundary

Cold login is reported under its existing protocol/HTTP guard and exact
operation/health/audit gates, separately from the ordinary 100/250-ms latency
gate. The frozen C3 runner recipe uses 1024 VUs, 256 users, pool 64, one
stream worker and 16 application CPUs. Both endpoints have 180 effective
seconds: **[52, 56) operations/s**.

At 52/s, all arrivals complete successfully with zero drops and complete
P95/P99 179/187 ms. At 56/s, all 10080 arrivals start and complete with zero
drops; 12 measurement-cohort outcomes are unexpected, giving 55.933 successful
operations/s and P95/P99 239/263 ms. Retained failed HTTP samples are
`POST /auth/login` 503 responses. No VU warning occurs, analyzer lag is 0.270 s,
load CPU is 0.273 and application CPU 8.053/16; pool wait is 0.001 ms. This
establishes a server-response upper failure. The exact response body is absent,
so the eight-permit hash-admission queue is not claimed as a proven root cause.
Password strength and admission policy are unchanged.

## Accepted single-core client-credentials boundary

The frozen C3 recipe uses 512 VUs, 64 users, pool 32 and one stream worker.
Its 180-second endpoints give **[1375, 1500) operations/s**. At 1375/s,
successful throughput is 1375.006/s with complete P95/P99 24/46 ms and no
drops. At 1500/s, success is 1491.167/s, complete P95/P99 339/395 ms and
1590 drops (0.5889%). The upper misses latency and delivery gates.

The one-factor 1024-VU control at 1500/s does not restore the SLO: complete
P95/P99 rise to 701/760 ms, with 1553 drops. Native whole-point HTTP waiting
P95 is 335.189 ms at 512 VUs and 697.629 ms at 1024 VUs; sending, receiving
and blocked P95 are below 0.05 ms in both. These request diagnostics support
the attribution and do not replace complete-operation measurement quantiles.
At the 512-VU upper, load CPU is 0.797/31, analyzer lag 0.257 s, application
CPU 0.912/1 and mean pool wait 16.985 ms. The control's pool wait increases
to 60.062 ms. At 1500/s the 250-ms P99 SLO needs 375 busy VUs, below the
frozen 512-VU allocation. The evidence supports service response and queue
latency; it does not identify a particular SQL or continuously saturated CPU.
The separate 1024-VU recipe also fails at 1375/s and is not mixed into the
accepted 512-VU interval.

## Accepted multicore introspection boundary and producer repair

The high-rate producer experiment keeps the C3 Python/observer image, 1024
VUs, 256 users, pool 64, four stream workers and workload unchanged. It
replaces only native k6 and enables omission of six unused HTTP timing
series from streamed JSON. Native summaries and thresholds still retain
these timings; the operation cohorts, window contracts, latency populations,
HTTP counts/errors, drops and all evaluator inputs remain exhaustive.
Both flag modes pass native HTTP equivalence tests. The overlay's base,
binary, patch and policy identities are in the
[seven-point checkpoint evidence](../../../../perf/results/diagnostics/2026-09-28-issuer-introspect-boundary-acceptance.json).

The unchanged producer dropped 9345 arrivals (0.324%) at 16000/s over 180
seconds. The repaired producer passes the same offered rate: success
15997.911/s, complete P95/P99 3/15 ms, 376 drops (0.0131%), no unexpected
outcomes and no unfinished operations. This resolves the measured producer
delivery constraint; no causal speedup percentage is inferred.

The frozen repaired recipe gives **[16000, 17000) operations/s**. At 17000/s,
99.938% of arrivals start and every started operation completes, with 1892
drops (0.0618%) and complete P95/P99 4/24 ms. Measurement is valid, but 50802
outcomes are unexpected and successful throughput falls to 16707.406/s.
Retained responses are HTTP 429 `temporarily_unavailable`, matching the
unchanged management request budget of 1000000 per source IP per 60 seconds.
The bounded whole-point log retains 40960 such samples; this is not an exact
measurement HTTP-status count. This interval describes the configured
single-source-IP admission boundary, not an intrinsic CPU maximum.

At the upper, load/app/PG CPU averages are 8.120/4.579/8.233 of 31/16/16
allocated CPUs, mean pool wait is 0.090 ms and maximum analyzer lag is
3.345 seconds, below its unchanged five-second validity gate. Parse and
reader failure counts are zero. The failure is independent of injector
delivery and observer validity. Security and admission settings are unchanged.

## Accepted single-core authorization-code and refresh boundaries

Both frozen C3 recipes use 256 VUs, 64 users, pool 32 and one stream worker.
The [six-point evidence](../../../../perf/results/diagnostics/2026-09-28-code-refresh-boundary-acceptance.json)
keeps 180-second endpoints and separate one-factor 512-VU controls.

| Scene | L / U ops/s | Success at L / U | Complete P95/P99 at L / U ms | Drops at L / U |
|---|---|---|---|---|
| Authorization code | 325 / 350 | 325 / 342.806 | 50/158 / 809/881 | 0 / 1295 |
| Refresh | 750 / 812 | 749.994 / 808.95 | 34/74 / 311/341 | 0 / 549 |

At 350/s the 512-VU authorization-code control delivers and completes every
one of 63000 arrivals, without drops or warnings, yet complete P95/P99 remain
394/497 ms. The service latency failure survives removal of the delivery
constraint. Load CPU is 1.139/31, observer lag 0.284 s and mean pool wait
2.617 ms. At the frozen upper, application CPU is 0.978/1, load CPU 1.251/31,
pool wait 28.991 ms and observer lag 0.266 s.

The refresh 512-VU control does not restore the SLO: complete P95/P99 become
771/813 ms. It still warns about VUs and drops 9.6654% of arrivals, so that
control is not evidence of full target delivery. Independent service-response
and queue measurements support the original upper's latency failure: native
whole-point HTTP waiting P95 is 320.549 ms at 256 VUs and 769.863 ms at 512;
send/receive/blocked P95 are below 0.062 ms. Pool acquisition wait rises from
15.396 to 128.371 ms, while load CPU remains 0.485/31 and 0.490/31 and observer
lag 0.259/0.262 s. Application CPU averages 0.958/1 and 0.927/1. At the unchanged
250-ms P99 SLO, 812/s needs 203 busy VUs, below the frozen 256 allocation.
The warning and drop counts are not used alone to attribute a backend failure.

Every started operation completes, with no unexpected outcomes, preparation,
runtime or audit failures at these endpoints and controls. Native HTTP timings
are whole-point diagnostics; capacity quantiles remain complete-operation
measurement cohorts. Bounds use the 256-VU recipe throughout; the controls
are separate. No specific SQL or continuous component saturation is inferred.

## Observer experiments and checkpoint CI

The native metric-partition experiment preserved its equivalence tests but
regressed in the actual high-rate pipeline. Its points are INVALID because
observer lag exceeds the unchanged five-second gate, and they are excluded
from capacity intervals. The experiment was removed in `286ab34a`; its
[compact diagnostic](../../../../perf/results/diagnostics/2026-09-28-native-partition-probe.json)
retains the evidence. Remaining measurements use their explicitly recorded
known-valid runner images; the application image is reused.

Checkpoint `60d46dff` has 11 successful checks and two conditional skips:
Rust advisory audit runs outside pull requests, and official-source fetching
runs outside pull requests. The
[Rust quality job](https://github.com/nazozero/NazoAuth/actions/runs/36388420548/job/108818684745)
passes in 1115 seconds with a two-second queue. Its resource-derived build
concurrency is four; shared-state test threads remain one. Compilation inside
the workspace step takes 166 seconds, and all 13 audit-ledger tests pass in
375.54 seconds. Clippy takes 43 seconds, schema setup 31 seconds, cache restore
25 seconds and avatar setup nine seconds. These costs overlap their enclosing
job/step totals; cache and runner variation prevent causal speedup percentages.
[Recorded timings](../../../../perf/results/diagnostics/2026-09-28-ci-cost-60d.json)
do not substitute for the final publication commit's checks.

Producer checkpoint `6511b3ab` also has all 11 applicable checks successful
and the two justified PR-event skips. Its
[native producer tests](https://github.com/nazozero/NazoAuth/actions/runs/36393855474)
and [Rust quality gate](https://github.com/nazozero/NazoAuth/actions/runs/36393855477/job/108835545322)
pass on that exact commit. This remains checkpoint evidence, not the future
publication commit's CI proof.

The remaining scene boundaries and their VU controls continue as targeted
incremental tests. This checkpoint is not the final 20-row current baseline.

## Retained evidence checkpoint after migration

All eighteen retained original-container endpoint/confirmation/control records
have been [reassessed again](../../../../perf/results/diagnostics/2026-09-28-retained-reassessment.json)
with the current shared evaluator at `ec638ce7`. Their verdicts are unchanged;
the recovered single-core mixed maintenance confirmation remains PASS.
The superseded old multicore mixed confirmation is excluded from this set.

The [selected retained archive](../../../../perf/results/diagnostics/2026-09-28-incremental-retained-archive.json)
preserves 463 available files, including complete native gate inputs and the
recovered single-core mixed journal. It contains 522743064 uncompressed bytes;
`20260928-incremental-retained-evidence.tar.gz` is 121025108 bytes with SHA-256
`45143b887df5a2008d2321dcc93078597523560d924e81886c7265af577e2b7c`.
Its embedded manifest hashes every archived file. Seventeen unavailable
auxiliary raw logs are listed explicitly; their absence is not presented as
complete raw preservation. The archive is held outside Git in the task workspace.

Checkpoint `ec638ce7` has all eleven applicable checks successful and the two
existing PR-event conditional skips. Its [Rust job](https://github.com/nazozero/NazoAuth/actions/runs/36409414900/job/108885814020)
takes 1110 seconds, with workspace compilation 176 seconds and all thirteen
audit-ledger tests 374.16 seconds. Cache restore takes 26 seconds, native
dependencies eleven, avatar setup ten, schema setup 27, clippy 38 and the
workspace step 951. These [nested timings](../../../../perf/results/diagnostics/2026-09-28-ci-cost-ec638.json)
overlap enclosing steps and do not support a causal speedup percentage.
The final current-baseline publication will still require its own exact-head CI.

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


## New-container mixed duration checkpoint

With the same frozen recipe, 3537/s passes the 180-second effective window
but fails the 660-second confirmation. The long point completes 3244.852
successful operations/s, with complete-operation P95/P99 of 751/1146 ms and
192821 dropped starts out of 2334423 scheduled (8.260%). Its refresh sidecar
also fails, with 582.725 successful operations/s at 600 offered and P95/P99
494/640 ms. These are [duration diagnostics](../../../../perf/results/diagnostics/2026-09-28-mixed-duration-checkpoint.json),
not a confirmed passing capacity interval.

The long point's connection-pool wait averages 34.35 ms per acquisition,
compared with 0.038 ms at the same 180-second load. Application, database
and main generator average 6.915, 8.941 and 3.781 logical CPUs respectively.
Valid observer lag and complete business counters preserve the failure's
measurement validity. These observations support service-side waiting;
they do not identify one SQL statement or prove a CPU ceiling.

Maintenance and durable audit still pass. The mature maintenance period has
135 samples, maximum gap 2.456 s and maximum expired age 67.496 s. Cleanup
passing does not make the latency failure pass. The short passing point is
not promoted to a successful long confirmation. A lower frozen-load
confirmation is required and remains in progress.

The 6000/s client-credentials control with 2048 VUs remains INVALID after
increasing stream workers from four to eight: only eight stale samples cross
five seconds. Native forensic member prefixes show VU gauges starting at
12:53:10.515 UTC while business/window samples begin at 12:53:19.082 UTC.
The native stdout writer is buffered but its periodic flusher does not flush
that buffer. Sparse initialization rows therefore wait for 4 KiB or shutdown.
The repair flushes that existing buffer at each periodic boundary, preserving
every emitted sample and the unchanged validity gate. A two-batch native
regression fails on the old implementation and passes after the repair; both
native JSON and metrics packages pass. Live affected-point validation is
pending and the invalid point has not been promoted to a backend upper.

The reporting repair at `6e0eeafb` has eleven applicable CI checks successful,
with the two existing PR-event conditional skips. Its
[Rust job](https://github.com/nazozero/NazoAuth/actions/runs/36417493911/job/108912021942)
is successful; a later publication still requires its own exact-head checks.
