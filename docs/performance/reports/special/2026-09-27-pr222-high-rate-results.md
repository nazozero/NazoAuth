# PR #222 high-rate follow-up — short-matrix checkpoint

Timestamp: 2026-09-27 09:28 UTC. New-stage T0: 2026-09-27 05:13:25 UTC. Stop starting load at 11:43:25 UTC; delivery deadline 12:13:25 UTC.

## Scope and frozen configuration

- Production source A/main: `0c70d7464576138af0b3f8a39530d6615ee7a363`.
- Production source B/candidate and shared harness H: `462626b29be202c04f2e4482ade6ab5f5f6267c5`.
- PGSS diagnostic change: `dc72cf469a2c5465cbb8a8185e0cff7d9999ad96`; container compatibility changes are task-local and their file hashes are in the evidence JSON.
- Existing A/B binaries and runner image were reused. Application and infrastructure were each bound to 32 logical CPU IDs from the task-local runtime plan; pool size was 90.
- The final common multi profile is SHA-256 `e459bfe9e77c2bbd043cd1f9ed31627345b0450cbcd77e160298691e9667ef0b`: main pre/max VU 1600, sidecar pre=max VU 16/33/66/258, total budget 1973, users 200, vectors 38400. Sidecar operation rates remained 8/200/30/600 per second at all main rates.
- The 1200/s calibration profile used main pre=max 600, total VU budget 973, users 75, vectors 14400. Pool, sidecars and all other group parameters matched A and B.

## Short calibration results

Each point used 60 seconds warmup and 60 seconds effective measurement. These are supply/calibration pilots, not the required 600-second formal points or 1800-second steady tests. P95/P99 below are complete logical iteration percentiles from `point.json.metrics.iter_pXX_ms`; the gate fields were cross-checked with the existing evaluator.

| Run | Source | Target ops/s | Successful ops/s | Complete P50/P95/P99 ms | Main drop | Main capacity gate | Refresh cap gate | Audit |
| --- | --- | ---: | ---: | ---: | ---: | --- | --- | --- |
| `pilot-mid-a-retry3` | A | 1200 | 1200.000 | 4 / 22 / 30 | 0 / 72,000 | PASS | PASS | PASS |
| `pilot-mid-b-round1` | B | 1200 | 1199.983 | 4 / 18 / 25 | 1 / 72,000 (0.0014%) | PASS | PASS | PASS |
| `pilot-high-a-3200-round2-retry1` | A | 3200 | 3200.017 | 5 / 26 / 41 | 0 / 192,001 | PASS | PASS | PASS |
| `pilot-high-b-3200-round2` | B | 3200 | 3200.000 | 4 / 21 / 33 | 0 / 192,000 | PASS | PASS | PASS |

The one B/1200 drop is 0.0014%, below the prescribed 0.1% maximum; its actual success rate exceeds the 1194/s gate floor. High-pilot raw summary status fields show `target_miss`; the prescribed capacity evaluator returned PASS using the observed complete measurement stream. The refresh sidecar's raw `target_miss` in the A/3200 pilot was independently evaluated with the refresh cap gate and also passed.

All four pilots had zero unexpected errors, zero SUT preparation failures, zero unfinished main iterations, no late-VU starts, and all point health/audit checks passed. Required audit drops and post-drain pending work were zero; audit sequence/hash/journal reconciliation passed. Refresh-family invariants remained within the recorded limits. A/B sidecar readiness checks passed; Argon2, metadata and FAPI completed naturally with zero drops/errors, and each refresh window passed the refresh cap evaluator.

## Calibration resource observations

The task-only `/proc` sampler recorded component process RSS and CPU ticks. At 3200/s, sampled peak process-summed RSS was about 234/230 MiB for the application, 14.19/14.13 GiB across PostgreSQL processes, and 11.44/11.54 GiB for the main load-generator process group (A/B). These are RSS sums, not PSS or unique physical memory; shared pages can be counted more than once. Docker stats returned unusable `0B/0B` values. No OOM or application restart was observed, and the generator completed with zero late VUs. Host-wide or parent-cgroup values were excluded.

Across the approximately 184-second process-sampler intervals for the high pilots, average observed CPU use was A/B: application 5.04/4.77 cores, PostgreSQL 7.60/6.35, Valkey 0.31/0.17, main generator 4.88/4.59. These intervals include run setup, warmup, measurement and drain; they are not a 60-second-only CPU attribution.

## WAL and wait observations (pilot only)

The point telemetry reports a 60-second normalized WAL sample while the underlying sampler spans 177 seconds (A) and 179 seconds (B). Concurrent sidecars and database background work are included, so this is not per-main-operation WAL attribution.

| Pilot | Generated WAL bytes | WAL write operations | WAL write bytes | Mean bytes/write | WAL fsyncs | Bytes write/generated | Pool wait/acquire |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| A/3200 | 818,792,373 | 59,189.9 | 2,152,229,188 | 36,361 | 59,041.5 | 2.629 | 0.010 ms |
| B/3200 | 747,723,564 | 61,243.1 | 2,027,988,230 | 33,114 | 61,107.8 | 2.712 | 0.006 ms |

PostgreSQL WAL write/fsync timing counters were zero in this environment and are reported as **N/A**, not as zero wait. This short pilot does not answer WAL statement Top10, checkpoint correlation, or the 1800-second source attribution. No WAL, sync, audit, or checkpoint settings were changed.

## Invalid tooling attempts and remaining work

The following attempts produced no business load and are retained as `INVALID_TOOLING`: `pilot-mid-a` (Compose override schema), `pilot-mid-a-retry1` (helper signature mismatch), `pilot-mid-a-retry2` (task-scoped external volumes missing), and `pilot-high-a-3200-round2` (profile copied outside `SIS_RESULTS`; generator guard stopped before traffic). Their reasons and task-tool hashes are recorded in `calibration-evidence.json`; no candidate-specific configuration change was made.

**Completed since the calibration checkpoint:** all six prescribed 600-second points, in order A2400 → B2400 → B3000 → A3000 → A3200 → B3200. Every point used 120 seconds warmup plus 600 seconds effective measurement. All six main gates passed. The requested target range is validated through 3200 successful logical operations/s; a maximum-capacity boundary was not searched or established.

**Completed since the calibration checkpoint:** all six prescribed 600-second points, in order A2400 → B2400 → B3000 → A3000 → A3200 → B3200, plus the B3000 steady point with 120 seconds warmup and 1800 seconds effective measurement. All six short main gates passed. B3000 steady main and separately evaluated refresh-capacity gates passed; its evidence is committed. The requested short-point target range is validated through 3200 successful logical operations/s; a maximum-capacity boundary was not searched or established.

**Completed since the calibration checkpoint:** all six prescribed 600-second points and the B3000 steady point (120 seconds warmup + 1800 seconds measured). The six short main gates and B3000 main/refresh gates passed. The B3000 result and its WAL evidence are recorded below. A3200 steady completed as a valid FAIL: 3187.346 successful ops/s, complete-iteration P95/P99 283/985 ms, 0.3954% measured drops, refresh/Argon2/FAPI gate misses, 1748 audit queue full/drops, and issuance expiry age up to 608.5 seconds against the predeclared 120-second SLO. Required audit drops remained zero and the journal reconciled, but the all-queue health gate failed.

**Current run state:** A3000 steady was launched at 10:37:30 UTC and confirmed active at 10:37:53, but the original container was subsequently destroyed. The replacement container has no task directory or final A3000 artifacts. A3000 is BLOCKED/UNVERIFIED and was not restarted because the fixed no-new-load cutoff is 11:43:25 UTC. B3200 steady is NOT_RUN after A3200 audit/issuance constraints failed; no higher-pressure run was started.

**Remaining at this checkpoint:** A3200 sanitized evidence/report checkpoint is complete. A3000 steady is BLOCKED/UNVERIFIED after original-container destruction; its replacement-container status record is committed, with no metric inferred. B3200 1800-second steady is NOT_RUN for the safety-gate reason above. The final summary checkpoint remains. PGSS statement Top10 remains INVALID/INCOMPLETE for short, B3000 long and A3200 long snapshots.

## Six-point formal short matrix

These are 600-second effective measurements, not 1800-second steady-state results. P95/P99 use complete logical iteration metrics (point.json.metrics.iter_pXX_ms) and match the existing evaluator gate_p95/gate_p99. Each row is independent; P99 values are not averaged. HTTP request rate is separate from successful logical business operations.

| Run | Variant | Target successful ops/s | Successful ops/s | HTTP req/s | Complete iteration P95/P99 ms | Main drops | Expected rejections | Audit enqueued=persisted |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| A2400 | A | 2400 | 2400.003 | 3486.243 | 28 / 90 | 0 | 1 | 295051 |
| B2400 | B | 2400 | 2400.002 | 3483.965 | 19 / 29 | 0 | 0 | 294511 |
| B3000 | B | 3000 | 3000.003 | 4356.893 | 20 / 31 | 0 | 0 | 360016 |
| A3000 | A | 3000 | 3000.003 | 4356.885 | 25 / 38 | 0 | 0 | 360019 |
| A3200 | A | 3200 | 3200.000 | 4646.738 | 26 / 40 | 0 | 0 | 381583 |
| B3200 | B | 3200 | 3200.000 | 4647.887 | 21 / 32 | 0 | 0 | 381845 |

Every main point had zero unexpected errors, zero SUT preparation failures, zero unfinished iterations, zero main drops, all health checks true, and no observed restart or OOM. All sidecar gates and refresh-capacity gates passed. A2400 refresh produced 599.667 successful ops/s with 210/378000 drops (0.0556%); although its raw sidecar label was target_miss, the prescribed capacity evaluator passed the >=99.5% success and <=0.1% drop gate. Other refresh points achieved 600/s with zero drops. Refresh invariants passed (active <=10 per scope, spent <=64 per family, expired backlog 0). Audit enqueued and persisted counts reconciled exactly, with dropped=0 and post-drain pending=0.

The common profile SHA-256 is e459bfe9e77c2bbd043cd1f9ed31627345b0450cbcd77e160298691e9667ef0b; per point, main preallocated=max VU=1600, pool=90, actual seed=1600 users and 38400 vectors, app CPU binding count=32, and sidecar targets/VUs were fixed at Argon2 8/s (16), metadata 200/s (33), FAPI 30/s (66), refresh 600/s (258). A/B binary hashes and source/harness provenance are preserved in the sanitized matrix evidence.

Compared with the earlier 1024/s run in this same CNB container, both used the same observed 32-logical-CPU application/infra plan and pool=90, but the prior run had main cap=512 VU, 64 users, 12288 vectors, smaller sidecars (3/68/10/205 per second), and only 120 seconds of measurement. This round used 1600 main VUs, 1600 effective users, 38400 vectors, sidecars 8/200/30/600 per second, and 600-second measurements. The earlier point therefore does not establish supply for this round's 3200/s target.

## B3000 1800-second steady point and WAL evidence

B3000 used the same frozen profile SHA-256 e459bfe9e77c2bbd043cd1f9ed31627345b0450cbcd77e160298691e9667ef0b: app/infra bindings each 32 logical CPUs, pool 90, main pre=max VU 1600, users 1600, vectors 38400, with Argon2 8/s, metadata 200/s, FAPI 30/s and refresh 600/s. All four sidecars used fixed equal pre/max VUs. Production B and shared harness H are both 462626b29be202c04f2e4482ade6ab5f5f6267c5; diagnostic patch dc72cf469a2c5465cbb8a8185e0cff7d9999ad96.

| Target successful ops/s | Effective measurement | Successful logical ops/s | HTTP req/s | Complete-iteration P95/P99 ms | Main drop | Main / refresh gates |
| ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 3000 | 1800 s | 3000.003 (5,400,005 ops) | 4641.967 | 21 / 32 | 0 | PASS / PASS |

Unexpected errors, prepare failures, unfinished iterations, restarts and OOM were zero. point.json.metrics.iter_p95_ms/iter_p99_ms were used. Refresh's raw sidecar label was target_miss, but its required independent stream gate passed at 599.998 successful ops/s over 1830 s with 4 drops / 1,098,000 scheduled (0.000342%), P95/P99 12.075/22.534 ms. Its bounded forensic diagnostic stream was TRUNCATED; that limits request-level diagnostic detail, not the stream-based capacity gate. Argon2 8/s, metadata 200/s and FAPI 30/s all passed with zero drops. Audit queue enqueued=persisted 954,709, dropped=0, post-drain pending=0; the 8,168,539-event journal was contiguous with zero gaps, duplicates, malformed lines or foreign batches.

The predeclared issuance-maintenance helper passed: 687 samples over the 24-minute mature window after 360 s retention; maximum observed expired age 60.013 s (declared maximum 120 s), final age 30.411 s, maximum sample gap 2.294 s. The due-count samples ranged 2,779–165,995; table inserts/deletes and count variation are retained as diagnostics, not a zero-backlog requirement.

The exact 1800 s effective-window global counters were WAL generated 23,676,248,889 bytes, WAL write bytes 45,120,221,348, 1,802,228.61 write operations, mean 25,035.8 bytes/write, and 1,797,924.855 fsyncs. Write/generated was 1.9057. PostgreSQL write-time and fsync-time deltas were raw zero and are reported N/A, not as zero wait or free I/O. These are concurrent database-wide counters, including the fixed sidecars and background work; write bytes are not disk net growth or SSD media writes.

pg_stat_io had 28/28 matched (backend_type,object,context) rows, identical stats_reset per row, and no missing or negative deltas. Its pre/post snapshots span 1998.402 s (setup, warmup, measurement and drain), not the exact 1800 s window. In that snapshot interval, the largest WAL writers were:

| backend_type / context | WAL write bytes | writes | fsyncs |
| --- | ---: | ---: | ---: |
| client backend / normal | 41,618,497,536 | 1,947,885 | 1,943,285 |
| client backend / init | 7,801,405,440 | 465 | 465 |
| autovacuum worker / normal | 9,617,408 | 236 | 235 |
| walwriter / normal | 7,471,104 | 224 | 223 |
| checkpointer / normal | 155,648 | 6 | 6 |

The client-backend rows total 49,419,902,976 bytes, about 99.965% of the 49,437,147,136 bytes in these full-point pg_stat_io snapshots. This identifies the broad writer category, not SQL identity. Full-snapshot pg_stat_wal delta was 25,319,223,288 bytes, 224,451,076 records, 339,041 FPI and zero wal_buffers_full; these full-point counters are not relabeled as effective-window values.

The strict PGSS check is INVALID/INCOMPLETE: pre had 4 statements, post had 171; only 4 shared the full (dbid,userid,toplevel,queryid) identity and identical stats_since, while 167 post-only rows were excluded. Their matched WAL-bytes delta was zero, so no SQL Top10 is claimed. Raw PGSS snapshots are excluded from the archive because they contain normalized SQL text.

cap_iter_ms complete-iteration per-second histograms provide 31 UTC-minute buckets: 29 P99 brackets were [20,50) ms, one [100,200) ms at 09:20 UTC and one [200,500) ms at 09:19 UTC; the exact whole-window P99 remained 32 ms. The two higher-tail minutes had no sampled checkpoint completion; their maximum simultaneous sampled IO wait-event-type counts were 4 and 2, with LWLock counts 84 and 38. Sampled counters show about 6 timed and 5 completed checkpoints over the measurement. pg_waits records event-type concurrency only, not WALWrite/WALSync names or durations; the time buckets therefore cannot establish a causal WAL/checkpoint-to-P99 link. Pool wait per acquisition was 0.070 ms.

Process-detail samples within the effective window show average CPU use of app 6.431 cores, PostgreSQL 7.555, Valkey 0.235, point worker 0.126 and receiver 0.079. Process-group summed peak RSS was app 237,024 KiB, PostgreSQL 15,457,276 KiB, and Valkey 100,312 KiB; PostgreSQL RSS sums repeat shared mappings and are not physical-memory use. PSS and reliable Docker stats were unavailable (0% / 0B readings were discarded); no effective ancestor limit was investigated. The generator's completed-process CPU/RSS was not captured and is N/A. No OOM or restart was observed.

Per-table sampled counter and size deltas, the minute correlation series, refresh gate, issuance helper output, PG18 WAL snapshots, and source hashes are in diagnostics/pr222-high-rate-2026-09-27/steady-b-3000/. The raw per-second histogram is included; PGSS SQL text, raw audit material, and unsanitized soak rows are not.

## A3200 1800-second steady point: valid FAIL and WAL evidence

A3200 used the same frozen common profile and all fixed sidecars as B3000. The 120-second warmup was excluded from the 1800-second effective measurement. This is a valid evaluator FAIL, not an invalid generator run.

| Target success ops/s | Effective measurement | Successful logical ops/s | Successful ops | HTTP req/s | Complete-iteration P95/P99 ms | Drops / scheduled | Main gate |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 3200 | 1800 s | 3187.346 | 5,737,223 | 4624.455 | 283 / 985 | 22,777 / 5,760,000 (0.3954%) | FAIL |

The successful rate met the 99.5% rate floor (3184/s), but full-iteration P95/P99 and measured drop gates failed. Unexpected errors, SUT preparation failures and unfinished iterations were zero; there was no OOM or app restart. HTTP request throughput is reported separately and is not the logical-operation rate.

The metadata sidecar passed at 400.001/s with zero drops. Argon2 cold login had 176 drops and raw `target_miss`; FAPI had 8 drops and `target_miss`. Refresh independently failed its capacity evaluator at 588.599/s against 600/s, 20,865 / 1,098,001 drops (1.9003%), P95/P99 404.795/659.323 ms. These sidecar outcomes are retained separately from the main gate.

Audit queue health failed: 1,748 queue-full events and 1,748 dropped queue entries. Required audit drops remained zero; enqueued=persisted 1,006,707 and post-drain pending=0. The 8,559,715-event journal was contiguous with no gaps, duplicates, malformed records or foreign batches. Thus journal reconciliation passed while the independent all-queue health gate failed. Issuance maintenance also failed its predeclared 360 s retention / 120 s expiry-age SLO: 680 mature-window samples, maximum expired age 608.546 s and final age 588.910 s; due count reached 1,730,084. This is why no higher-pressure steady point was started.

During the exact 1800 s effective window, database-wide WAL generated was 26,381,077,238 bytes. WAL write operations accumulated 47,675,232,975 bytes over 1,719,683.744 writes (mean 27,723.3 bytes/write), with 1,714,890.077 fsyncs. Write/generated was 1.8072. WAL write-time and fsync-time deltas were raw zero and are N/A, not evidence of zero wait. These global counters include all fixed sidecars and database background work; write bytes are not net disk growth or SSD media writes.

The full-identity PG18 `pg_stat_io` comparison had 28/28 consistent rows and no missing/reset/negative deltas, but spans 2003.634 s (setup, warmup, measurement and drain). Its largest WAL writer categories were:

| Backend / context | WAL write bytes | Writes | Fsyncs |
| --- | ---: | ---: | ---: |
| client backend / normal | 43,817,828,352 | 1,858,167 | 1,853,043 |
| client backend / init | 8,522,825,728 | 508 | 508 |
| autovacuum worker / normal | 21,299,200 | 676 | 675 |
| walwriter / normal | 10,780,672 | 260 | 255 |
| checkpointer / normal | 540,672 | 17 | 17 |
| background writer / normal | 98,304 | 2 | 2 |

Client backend rows contributed 52,340,654,080 of 52,373,372,928 bytes (99.94%) in that wider snapshot interval. The full-snapshot `pg_stat_wal` delta was 28,257,228,002 bytes, 262,156,271 records and 293,179 FPI, with `wal_buffers_full=0`; these are not relabeled as exact effective-window deltas.

Exact SQL Top10 remains INVALID/INCOMPLETE. PGSS pre/post had 3/172 rows, with 3 matching the full `(dbid, userid, toplevel, queryid)` identity and identical `stats_since`; their WAL-byte delta was zero. All 169 post-only rows were excluded. No statement ranking is inferred from top-level/nested rows or post-only counters.

The 31 complete-iteration minute buckets had P99 brackets: 22 at [20,50) ms, 2 at [50,100), 1 at [100,200), 1 at [200,500), and 5 at [1000,2000); the whole-window P99 was 985 ms. The five highest-tail minutes were 10:01–10:05 UTC, with sampled pool-waiting maxima of 1817–1835; the whole-window pool wait/acquisition average was 7.622 ms. A checkpoint completed in the first such minute, but none completed in the following four. Sampled IO concurrency stayed at 1–2 sessions, with LWLock concurrency 33–75 and Lock 1–2; the sampler does not record WALWrite/WALSync event names or durations. The queue/P99 overlap is observed, while WAL/checkpoint causation is not established.

During the 1795.522 s process-detail sampling interval, average CPU use was app 7.362 cores, PostgreSQL 9.635, Valkey 0.459, task worker 0.100 and receiver 0.066. Peak process-summed RSS was app 329,392 KiB, PostgreSQL 15,538,560 KiB, Valkey 103,852 KiB, worker 22,640 KiB and receiver 10,444 KiB; PostgreSQL RSS sums repeat shared mappings and are not physical memory. PSS and useful Docker stats were unavailable; generator post-cleanup CPU/RSS is N/A. No OOM or restart was observed.

The sanitized evidence archive is in `diagnostics/pr222-high-rate-2026-09-27/steady-a-3200/`; SHA-256 `72477b9780627e5bb72bda8923db6b7d42e9e5202b2fd00ab372d9f3886951ee`. Raw PGSS SQL rows, request diagnostics, soak rows and raw audit material are excluded.

## A3000 steady point: BLOCKED/UNVERIFIED

A3000 at 3000/s was launched on the original CNB test container at 10:37:30 UTC with 120 s warmup plus 1800 s effective measurement and the frozen common profile. Its process was confirmed running at 10:37:53 UTC. The user later reported the original container had been destroyed. The replacement container was checked at 11:37:41 UTC; it had no `/tmp/pr222-high-rate-20260927-051325` task directory, A3000 log, exit code or point result. SSH to the original endpoint had been disconnecting during authentication since 10:45 UTC.

The point was not restarted or overwritten. The fixed no-new-load cutoff is 11:43:25 UTC, leaving insufficient time for a fresh 120+1800 s run. Therefore A3000 steady is **BLOCKED/UNVERIFIED**, not NOT_RUN and not a performance PASS/FAIL. No A3000 steady P95/P99, successful throughput, WAL, queue, audit or resource conclusion is inferred. Its availability record is under `diagnostics/pr222-high-rate-2026-09-27/steady-a-3000-status/`.

## Global WAL counters from the six effective windows

The WAL counters below are concurrent database-wide observations across the exact point's effective 600-second window, including the fixed sidecars and database background work; they are not per-main-operation attribution. Byte units are GiB (2^30 bytes). PostgreSQL's reported write-time and fsync-time counters were raw zero in every snapshot and are therefore N/A, not zero wait. The write-to-generated ratio is not itself an attribution or disk-usage measure.

| Run | WAL generated GiB | WAL write bytes GiB | Write ops | Mean bytes/write | Fsyncs | Write/generated |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| A2400 | 6.441 | 15.409 | 576574.2 | 28697 | 575319.2 | 2.392 |
| B2400 | 6.002 | 14.993 | 625256.7 | 25748 | 624083.0 | 2.498 |
| B3000 | 7.102 | 16.872 | 625637.1 | 28957 | 624245.3 | 2.376 |
| A3000 | 7.593 | 17.624 | 607709.3 | 31140 | 606225.8 | 2.321 |
| A3200 | 7.967 | 18.295 | 610778.1 | 32163 | 609224.5 | 2.296 |
| B3200 | 7.476 | 17.483 | 624380.2 | 30065 | 622920.2 | 2.338 |

These global counters show WAL writes averaging about 2.30–2.50 times generated WAL bytes over each sampled interval. This is an observed ratio only; the cause remains open pending full-identity PGSS deltas and checkpoint/lock correlation. PGSS pre/post snapshots span setup/warmup/drain as recorded in the raw evidence, so statement rankings will use their own actual timestamp interval and reset/stats_since checks rather than being mislabeled as the exact 600-second window. Top-level and nested statement rows will remain separate.

## PGSS statement WAL attribution status

The captured A3200/B3200 PGSS intervals are 781.454 seconds (2026-09-27 08:17:50.271Z to 08:30:51.725Z) and 781.534 seconds (08:33:37.116Z to 08:46:38.651Z). In both, stats_reset was unchanged and dealloc stayed 0. However, the pre snapshots contain only 3 statement identities while post contains 172/171. Only 3 rows per point had both the full identity (dbid, userid, toplevel, queryid) and identical stats_since; their combined WAL-bytes delta was 0. The remaining 169/168 post-only rows are excluded, not assigned a zero baseline.

Therefore the short-point PGSS Top10 is INVALID/INCOMPLETE under the fixed taskbook's same-stats_since rule. The earlier interim ranking based on post-only counters is withdrawn and must not be used as a WAL delta or accepted attribution. This is an attribution-evidence limitation; the six short business points and their independent health/audit/sidecar gates remain valid. The sanitized evidence records the exact row coverage and raw snapshot hashes without storing normalized SQL text. The B3000 long-point snapshots were also checked by the same strict rule and are INVALID/INCOMPLETE as detailed below; A3200 long-point attribution is INVALID/INCOMPLETE under the strict full-identity and identical-stats_since rule; no SQL Top10 is claimed.
## Queue, wait and checkpoint observations from the 3200/s short windows

| Point | Complete P95/P99 ms | Pool wait per acquire ms | Wait samples | Max IO-type sessions sampled | Max Lock-type sessions sampled | Checkpointer delta: timed/done/requested | Checkpointer write/sync time ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| A3200 | 26 / 40 | 0.008 | 286 over 599s | 3 | 1 | +2 / +1 / 0 | +269999 / +323 |
| B3200 | 21 / 32 | 0.011 | 287 over 597s | 3 | 2 | +2 / +1 / 0 | +269490 / +242 |

The sampler exposes pg_stat_activity wait_event_type counts per snapshot, not event names or accumulated wait duration. IO and Lock maxima above are simultaneous sessions observed at a sampling instant, not totals. It therefore cannot distinguish WALWrite from WALSync. PostgreSQL WAL write/fsync timing counters were raw zero and remain N/A. The observed pool wait per acquisition was under 0.012 ms, but this alone does not rule out other causes of latency. One completed checkpoint and two timed-checkpoint counter increments were observed over the sampled boundary interval; no time-bucketed complete-iteration latency series is available, so the short-point data cannot prove or rule out point-in-time correlation between checkpoint activity, WAL waits, and P99. Do not interpret checkpointer cumulative write time as request latency or CPU.

The sanitized PGSS/wait evidence and checksums are in diagnostics/pr222-high-rate-2026-09-27/short-wal-3200/. Raw PGSS snapshots remain with their point results in the CNB task directory and are excluded from the repository archive because they contain normalized statement text. The exact source hashes and snapshot times are recorded in the sanitized JSON.

## Current evidence and remaining attribution

The six short points are preserved under `diagnostics/pr222-high-rate-2026-09-27/short-points/`. B3000 steady passed the main and refresh gates with evidence under `steady-b-3000/`. A3200 steady is a valid FAIL across main latency/drop, sidecars, queue health and issuance expiry-age SLO; its complete sanitized attribution bundle is under `steady-a-3200/`. B3200 steady is NOT_RUN after the A3200 safety/retention failures. The A3000 steady comparison was launched and observed active, but is BLOCKED/UNVERIFIED because the original container was destroyed before evidence retrieval; the replacement had no task directory and the cutoff prevented a rerun. Its status record is under `steady-a-3000-status/`. PGSS Top10 remains INVALID/INCOMPLETE for short, B3000 and A3200 snapshots; PG18 pg_stat_io shows client backends dominate broad WAL write bytes, but exact SQL identity and WALWrite/WALSync wait timing remain unresolved.

## Evidence

Sanitized stage evidence and its checksum manifest are in `diagnostics/pr222-high-rate-2026-09-27/calibration/`. The evidence includes the exact common resource profile, gate/sidecar/audit summaries, process-sampler summary, and hashes tying these summaries to the retained CNB raw point artifacts. Raw SQL text, request diagnostics, credentials, key material, and audit journal contents are excluded.
## A3000 rerun update — INVALID_TOOLING

The prior A3000 BLOCKED/UNVERIFIED availability record is superseded by the retry2 attempt: the full scheduled load ran and exited 0, but required main/sidecar summary artifacts were not captured, so the formal performance and audit gates remain INVALID/NOT_VERIFIED. See [`2026-09-27-pr222-a3000-rerun.md`](2026-09-27-pr222-a3000-rerun.md) and the sanitized evidence bundle under `diagnostics/pr222-high-rate-2026-09-27/a3000-retry2-20260927-125155/`. This is a tooling output-capture failure, not a capacity PASS or FAIL; a valid A3000 retest remains NOT_RUN pending volume-backed main/sidecar output collection.


## Retry3 output-capture repair in progress

The A3000 retry2 output-capture gap has a task-local harness repair: main and sidecar `/out` files are copied through the Docker API before their runner containers are removed. A minimal bind-mounted `docker cp` probe passed. Retry3 is running with the same fixed A3000 profile and full 120 s warmup + 1,800 s measurement; no performance conclusion is available yet. The task-local patch and its hashes are in `diagnostics/pr222-high-rate-2026-09-27/a3000-retry3-tooling/`.


