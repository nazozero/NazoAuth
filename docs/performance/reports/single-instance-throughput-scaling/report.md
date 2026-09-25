# single-instance-throughput-scaling — bounded A/B report

Date: 2026-09-24 (load runs); measurement-validity review 2026-09-24
on `cnb-r49-1k38f54tm-001…@cnb.space` with `NEW_REAL_LOAD_TIME = 0s` —
no new load, no candidate restoration, no new optimization matrix.
Original load runs on the remote benchmark host
(`cnb-9dp-1k378qhr6-001…@cnb.space`, `/workspace/.sis-worktree`).

This task asked whether collapsing the fresh `client_credentials`
issuance critical path (client `FOR SHARE` lock + ownership `INSERT` +
required security-audit append) into one PostgreSQL statement raises
effective single-instance business throughput. **It did not.** The
candidate produced no repeatable benefit; the production change is
reverted on this branch while the harness, regression tests and
evidence are kept.

> Review note: this revision corrects measurement windows, identity
> handling and causal attribution. "Measurement repair" and "checkpoint
> jitter repair" are separate claims — this report only covers the
> former. Corrected derived values live in `offline-review/`; raw
> artifacts are unchanged.

## 1. Identity

| Field | Value |
| --- | --- |
| BASE_SHA | `c6df5b4fd13e399e181854f86b8b4d3c5eabc520` (measurement-repair tip; main is its ancestor line — rule B) |
| REVIEWED_MAIN_SHA | `bb5f42c60d24c18bf71d279ad50aee4935f0cca0` |
| REVIEWED_HEAD | `bcdc4768422e3d57f1c8bbad65fcff44e0c85789` (pre-review evidence tip) |
| BASELINE_APP_SHA | `7332cb6f1b3dc68b424105bdb39f0687e4400ec2` → image `sis-app:A`, binary `24d8067d395c624c…` |
| CANDIDATE_APP_SHA | `66839aa32fc461b6a6cc396265aadb40f6008bf7` → image `sis-app:B`, binary `6b0d63ffd2b01b1f…` |
| FINAL_CODE_SHA | `4875c7b889e2b84f88253f2dae697bfd99007f4d` (candidate reverted; production `src/` byte-identical to pre-candidate) |
| PostgreSQL | `postgres:18-alpine@sha256:d3e1620b…`, PG 18 |
| Valkey | `valkey:8-alpine@sha256:e0eb7c48…` |
| Schema | `applied_migrations_sha256=0b4cb38907d4d10b…` identical on every point |
| Host | nested cgroup-v1: allowed CPUs `87-150` (64), quota 6400000/100000 = 64 CPUs |

PG durability/perf params unchanged on every point (`fsync=on`,
`synchronous_commit=on`, `full_page_writes=on`, `max_wal_size=8GB`,
`checkpoint_timeout=5min`, `checkpoint_completion_target=0.9`,
`shared_buffers=128MB`). Same harness, images, fixtures and
`DATABASE_MAX_CONNECTIONS=24` for A and B; only the app binary differs.

CPU pinning — actual sequence: each application container **first
started with its original available CPU set** (the nested host's
`87-150`), and only then were its already-running threads restricted to
the point's affinity mask by the `pinset` helper (docker
`--cpuset-cpus` is a no-op in nested cgroup-v1). These are **not**
native 4-CPU/8-CPU boot deployments; threads created after pinning
inherit the parent's mask. Per-point evidence carries `proc_masks`
dumps. Plan: app reserved `88-103` (8 physical cores × SMT 2);
infra `87,104-150`. X16 means **8 physical cores × 2 SMT threads**, not
16 physical cores.

## 2. Correctness evidence (real PG18, remote)

All runs on the remote host against real migrations; restricted runtime
role exercised (`nazoauth_perf_runtime`, function-boundary-only audit
access).

| Suite | Result |
| --- | --- |
| `token_issuance_fresh` (candidate build) | 11/11 pass — commit atomicity, inactive/missing client, tenant isolation, id-conflict, oversized payload, deactivation both directions, lock timeout/abort connection discard, restricted role, audit-failure rollback |
| `token_issuance_atomicity` | 4/4 |
| `refresh_family_capacity` | 7/7 |
| `auth_repositories` | 28/28 |
| `pool_async_contract` | 6/6 |
| `audit_ledger` (isolated `NAZO_AUDIT_TEST_DATABASE_URL`) | 8/8 |
| `nazo-postgres` unit tests | 56/56 |
| `token_issuance_fresh` re-run on the **reverted** build | see `evidence/correctness/revert-fresh2.log` |

## 3. Phase 1 — baseline app-CPU scaling (image A, constant-vus=64, 120s + 15s warmup)

| Point | App set | successful ops/s | op p50/p95/p99 (ms) | app cores† | PG cores† | WAL/success‡ |
| --- | --- | --- | --- | --- | --- | --- |
| X4 | 4 physical cores (`88,90,92,94`) | 2988.5 | 20/30/43 | 3.40 | 3.71 | 2649 B |
| X8 | 8 physical cores (`+96,98,100,102`) | 4530.2 | 13/19/31 | 5.79 | 5.19 | 2671 B |
| X16 | 8 physical × 2 SMT (`88-103`) | 5462.6 | 11/17/30 | 8.84 | 6.37 | 2701 B |

† CPU recomputed from `proc-detail.jsonl` jiffies inside the k6
measurement window (≈96–104 s coverage) — see
`offline-review/corrected-metrics.json`. The original point metrics
used a different span; the archived sampler stream makes these values
independently reproducible.

‡ Same-window WAL: sampler `wal_bytes` interpolated at the window edges
÷ measure-cohort success. The original table used the
seed+load+drain `pg_stat_wal` delta ÷ cohort (≈2.9–3.1 KB) — a mixed
window, retained only in the raw `point.json`.

All windows valid (`cap-scenario-window-v1`, 105s), zero
unexpected/local_no_request/dropped outcomes, audit DB pending=0 with
`anchor_sequence = last_sequence` on every point, no OOM/restart. These
are fixed-concurrency scaling points, not maximum capacity.

## 4. Phase 2 — controlled A/B on the X8 set (same infra, same fixtures)

| Point | Image | successful ops/s | op p50/p95/p99 (ms) | app cores† | PG cores† | stmts/req§ | WAL/success‡ |
| --- | --- | --- | --- | --- | --- | --- | --- |
| A1 | baseline | 4266.8 | 13/22/43 | 5.34 | 5.07 | 19.25 | 2678 B |
| B1 | candidate | 4151.3 | 14/25/38 | 5.06 | 6.46 | 17.22 | 2635 B |
| B2 | candidate | 4442.3 | 13/20/35 | 5.42 | 6.31 | 17.25 | 2622 B |
| A2 | baseline | 4528.3 | 13/19/31 | 5.71 | 5.29 | 19.25 | 2680 B |

§ `statements_per_http_request` = `SUM(pg_stat_statements.calls)` since
the scenario reset across **all roles and nesting levels** ÷ full-run
HTTP requests. It is a statement-count ratio, **not** a count of serial
network round trips per business operation (see §5).

Formal gate evaluation (`eval` output, `evidence/phase2-eval.json`):

- window validity: pass on all four points
- **a_stability: FAIL** — spread 5.78% > 5% (A1 4266.8 vs A2 4528.3)
- **b_gain: FAIL** — B1 −8.3%, B2 −1.9% vs max(A)=4528.3 (gate needs ≥ +5% on both)
- p99 regression: pass (B p99 lower, 35-38ms vs 43ms A1 — noise-level)
- clean outcomes / WAL-per-success / runtime health / audit drain: pass
  under the original (fail-open on missing) gate code; the corrected
  gates now fail closed on absent evidence — see §8.

**Verdict: INCONCLUSIVE on environment stability, and the candidate
shows no gain even at face value (B ≤ A on both repeats).**
`retain=false` → phase 3 not run → candidate production code reverted
(`4875c7b8`). The combined statement demonstrably executed on B
(`pgss` path classes: `combined` ≈ http_reqs, separate
`issuance_insert`/`audit_append` = 0), so the negative result is not a
wiring error.

## 5. Statement ledger — what 19.25 → 17.22 actually is

Per HTTP request on `cap_client_credentials` (same business op), the
pg_stat_statements evidence separates four distinct quantities:

- **Application-side command stages**: source inspection confirms the
  fresh path issues ≈6 serialized command stages on baseline vs ≈4 on
  the candidate (lock, insert, audit call fold into one combined
  statement). This is a *structural* fact, not a measured throughput
  gain.
- **Protocol round trips**: not directly measured. Fewer top-level
  statements does not translate 1:1 into fewer wire round trips
  (pipelining/extended-protocol batching is not observable in this
  evidence).
- **PG top-level statements**: 19.25 (A) vs 17.22 (B) — a
  `SUM(calls)`-since-reset ÷ full-run-HTTP ratio over all roles. It
  must not be read as "19 → 17 serial RTTs".
- **PG internal statements** (inside functions/triggers): unchanged by
  the candidate — audit event insert, chain entry, outbox insert and
  checks still execute inside `nazo_persist_security_audit_event`.

A1 additionally crossed a `stats_reset` epoch between pre and post
snapshots (`1790180347.988551 → 1790180369.652601`); per the corrected
harness, cross-reset pre/post subtraction is refused and all old
snapshots — which lack `dbid/userid/toplevel` identity — are demoted to
since-reset observations. Precise per-request top-level statement
totals are therefore not derivable from the archived pgss files.

## 6. Bottleneck attribution — corrected

What the evidence supports:

- At fixed 64 VUs, `ops/s ≈ VU / op_latency` holds (X4: 64/0.0214 ≈
  2988; X8: 64/0.0141 ≈ 4530; X16: 64/0.0117 ≈ 5463). This is a
  closed-loop arithmetic identity at fixed concurrency — consistent
  with, but not proof of, any particular limiter.
- **Pool-acquire waiting is observed**: ≈4.0 acquisitions per request
  (full-run ratio 4.007–4.012; same-window sampler ratio ≈3.96–4.00 —
  the earlier 4.6 figure divided a lifetime counter by the post-warmup
  cohort and is retracted), mean acquire wait 1.5–3.1 ms. `pool=24 <
  VU=64` alone does not prove the pool is undersized: connection hold
  time and downstream wait were not decomposed.
- **Adding CPU affinity resources raised throughput**: X4→X8 +52%,
  X8→X16 +21% (SMT). App cores in-window: 3.40/4 (X4), 5.79/8 (X8),
  8.84/16 (X16); postgres 3.7–6.4 cores — the app set is substantially
  busy but neither side is proven saturated.
- Removing two ~0.1–0.5 ms statement phases is below run-to-run noise
  at this concurrency (A-side spread alone was 5.78%).

`PRIMARY_SCALING_BOTTLENECK = UNRESOLVED`: pool-acquire waiting was
observed and extra CPU affinity raised throughput, but connection hold
time and downstream wait were not sufficiently decomposed to name a
dominant bottleneck. PostgreSQL wait-event evidence was never
collected — that is an independent instrumentation gap, not explained
away by `perf_event_paranoid=2` (a separate channel that only blocked
kernel profiling).

## 7. Audit evidence — scoped to what exists

Per point, the evidence separates three scopes:

- **DB facts** (preserved): `security_audit_event_outbox` pending = 0
  and `anchor_sequence = last_sequence` on every point (e.g. A1:
  512556 = 512556). The chain advanced through every persisted event.
- **Receiver reconciliation**: the `sis-rcv-*` container logs were not
  preserved. `Required lost = 0` is therefore **not** claimed; what is
  claimed is only the DB-side pending/anchor state above.
- **Log anomaly scan**: original scans covered container stdout only.
  The corrected harness scans combined stdout+stderr and records the
  collection status; empty logs and failed collection are distinct
  states.

## 8. Harness corrections in this review (no new load)

- **Cleanup ownership**: `stack_down` no longer enumerates containers
  by `sis-`/`soak-` name prefix or the shared `nazoauth-perf` project.
  `SIS_PROJECT` must now name an explicit, exclusive compose project.
  Allowed to clean: (a) resources owned by that compose project
  (`compose down -v --remove-orphans`), (b) extra containers this run
  recorded by ID at creation whose `sis.owner` label still matches.
  Forbidden: `sis-test-pg` and any other task's resources, old
  soak/sis projects, the shared `nazoauth-perf` project, and any
  same-named resource whose ownership label does not match. The prior
  incident (scratch `sis-test-pg` removed mid-task) is the bug this
  fixes; cleanup regression tests simulate foreign docker responses —
  no real resource deletion was used to test.
- **`wait_healthy`**: exact `Status == "healthy"` comparison —
  `"unhealthy"` no longer passes the old substring check.
- **pgss identity/reset**: snapshots now capture
  `dbid/userid/toplevel/queryid/calls/total_exec_time` + `stats_reset`
  + capture time; deltas use the full identity key and refuse
  cross-reset subtraction; runtime top-level vs nested vs exporter vs
  observer roles are classed separately.
- **Reset ordering**: the harness owns the only reset, executed before
  the pre snapshot; runner containers carry
  `PERF_SKIP_PG_STATS_RESET=1` so nothing resets mid-window or after
  the baseline.
- **Window consistency**: WAL/success and acquire/op use same-window
  numerators and denominators (see `offline-review/`); unrecoverable
  values are `None`/`NOT_COMPARABLE`, never silently averaged.
- **Fail-closed gates**: missing WAL, outcome, health or audit fields
  no longer pass as zero/healthy; collection failure is distinguished
  from zero anomalies.
- **Required evidence first** (acceptance-definition fix): all four
  phase-2 points and their required fields are validated before any
  comparison; missing baselines can no longer be filtered into a
  one-sided stability or WAL check — the verdict is `INVALID` with the
  exact point+field gap named. Legal zero throughput is a value, not a
  gap, and cannot divide-by-zero or auto-approve.
- **Audit gate split** (acceptance-definition fix): `audit_db_drained`
  (pending == 0 AND anchor_sequence == last_sequence, both present) is
  distinct from `audit_delivery_reconciled`, which additionally
  requires real receiver/DB reconciliation evidence — never log
  keyword counts. Historical points lack receiver evidence, so the
  corrected acceptance can no longer emit `retain=true` for them.

Acceptance status after this review:

| Check | Status |
| --- | --- |
| `REQUIRED_EVIDENCE_GUARD` | **REPAIRED** — per-point field validation precedes all comparisons; missing → `INVALID` with named point+field |
| `AUDIT_DB_DRAIN_CHECK` | **REPAIRED** — pending == 0 AND anchor_sequence == last_sequence, both present |
| `AUDIT_DELIVERY_RECONCILIATION` | **UNAVAILABLE_FROM_CURRENT_COLLECTOR** — `receiver_log_scan` reports log health only (collection status, error markers); it carries no final sequence/hash/deployment reconciliation facts, so `audit_delivery_reconciled` can only be `False` (drain failed or receiver errors observed) or `None` (UNKNOWN). No `True` path exists until a real reconciliation collector is added. |
- **Load budget**: a point whose load container started but whose
  orchestration failed is recorded as `unknown` seconds — never
  silently zero.

## 9. Budget & anomalies

Load wall-clock actually recorded: 895.8s over 7 points (≈15min of the
30min cap including failures). Four additional attempts failed before
load (harness bugs fixed in commits `73c9ac5d`…`61810d97`: app
readiness probe, non-root pinset exec, PID-1-uid pinning, vkledger
text write) and consumed ~0 load seconds; one early X4 attempt was
killed before load. Phase 3 was not run (phase-2 gates failed).
This review added `NEW_REAL_LOAD_TIME = 0s`.

## 10. Decision

`PRIMARY_OPTIMIZATION_RETAINED = NO`. The revert keeps: the harness
(`perf/tools/single_instance_scaling.py`, `proc_detail_sampler.py`),
the fresh-path contract tests (`token_issuance_fresh.rs`, which pass
identically on the serial implementation), the runner gate
(`PERF_SKIP_PG_STATS_RESET`), all raw evidence under `evidence/`, the
corrected derived metrics under `offline-review/`, and the gate
evaluation showing why the candidate was rejected.

Final state: `CANDIDATE_RETAINED = NO`, `MEASURED_GAIN =
NOT_ESTABLISHED`, `PRIMARY_SCALING_BOTTLENECK = UNRESOLVED`,
`PRODUCTION_CHANGES = NONE`.
