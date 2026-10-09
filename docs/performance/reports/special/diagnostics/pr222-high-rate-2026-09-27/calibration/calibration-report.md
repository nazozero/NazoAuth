# PR #222 high-rate follow-up — calibration checkpoint

Timestamp: 2026-09-27 07:05 UTC. New-stage T0: 2026-09-27 05:13:25 UTC. Stop starting load at 11:43:25 UTC; delivery deadline 12:13:25 UTC.

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

**NOT_RUN at this checkpoint:** all six 600-second formal points; B3000 1800-second steady; the highest common-pass A/B 1800-second pair; B3200 1800-second steady; issuance maturity/reclamation evidence; final PGSS Top10 and WAL attribution; final retrievable evidence archive. Capacity boundary is not established. Continue with the required serial order A2400 → B2400 → B3000 → A3000 → A3200 → B3200.

## Evidence

Sanitized stage evidence and its checksum manifest are in `diagnostics/pr222-high-rate-2026-09-27/calibration/`. The evidence includes the exact common resource profile, gate/sidecar/audit summaries, process-sampler summary, and hashes tying these summaries to the retained CNB raw point artifacts. Raw SQL text, request diagnostics, credentials, key material, and audit journal contents are excluded.
