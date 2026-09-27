# PR #222 high-rate follow-up — short-matrix checkpoint

Timestamp: 2026-09-27 09:03 UTC. New-stage T0: 2026-09-27 05:13:25 UTC. Stop starting load at 11:43:25 UTC; delivery deadline 12:13:25 UTC.

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

**Currently running:** B3000 steady-state, 120 seconds warmup plus 1800 seconds effective measurement. After it completes, the planned remaining steady points are A3200 and B3200 at the highest common short-point pass; the completed short B3200 is not a substitute for its separately required steady-state point. Issuance maturity checks, statement-level PGSS Top10, lock/WAL correlation, final evidence archive, and final report remain pending.

**Remaining NOT_RUN at this checkpoint:** B3000 1800-second steady-state completion; A3200/B3200 1800-second steady-state pair; issuance maturity/reclamation evidence; final PGSS Top10 and WAL attribution; final evidence archive. No evidence is claimed for those items yet.

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

## Current evidence and remaining attribution

The sanitized short-point bundle is under diagnostics/pr222-high-rate-2026-09-27/short-points/, including the six point summaries, frozen profile/provenance hashes, issuance retention declaration, checksum manifest, and retrievable tar archive. No SQL text, request query strings, credentials, keys, or audit journal contents are included. The detailed PGSS Top10, statement categories (audit/issuance/refresh/maintenance), WALWrite/WALSync and checkpoint correlation, 1800-second steady results, issuance maturity check, and final archive remain pending.
## Evidence

Sanitized stage evidence and its checksum manifest are in `diagnostics/pr222-high-rate-2026-09-27/calibration/`. The evidence includes the exact common resource profile, gate/sidecar/audit summaries, process-sampler summary, and hashes tying these summaries to the retained CNB raw point artifacts. Raw SQL text, request diagnostics, credentials, key material, and audit journal contents are excluded.