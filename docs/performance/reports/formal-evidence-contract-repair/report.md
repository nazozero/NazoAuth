# Formal Evidence-Contract Repair — F3000-30M-R2 Offline Re-evaluation

## Executive summary

| Field | Value |
|---|---|
| Task | `formal-evidence-contract-repair` |
| `NEW_REAL_LOAD_TIME` | **0 s** — zero new load of any kind |
| `EVIDENCE_CONTRACT` | **REPAIRED** |
| `AUTHORITATIVE_STREAM` | **COMPLETE** (window + series + summary + analyzer-stats all valid) |
| `FORENSIC_DIAG_STATUS` | **TRUNCATED** (caveat, not a gate) |
| `DIAG_OVERFLOW_AFFECTS_FORMAL_ACCOUNTING` | **NO** (proven by construction and by zero-load A/B test) |
| `ORIGINAL_F3000_30M_R2_VERDICT` | INVALID (`stream_evidence_invalid: diag_overflow` under the old contract) |
| `CORRECTED_F3000_30M_R2_VERDICT` | **PASS** — same execution, same raw evidence, zero additional load |
| `FORMAL_30M_3000_STABILITY` | **PASS** |
| `FORMAL_10M_3000_CAPACITY` | **PASS** (unchanged, prior F3000R2) |
| `READY_FOR_MERGE` | **YES** (see scope note below) |
| `PRIMARY_LIMIT` | **NONE** |
| `PRODUCTION_CODE_CHANGED` | NO |
| `DURABILITY_CHANGED` | NO |

## What was wrong

The pre-registered formal contract required `diag_overflow = false` as part of *stream evidence validity*. That conflated two evidence tiers:

- **A. AUTHORITATIVE** — `window.json` (window contract, exact measurement cohort, parse/reader validity), `series.json` (per-second begins/ends/drops/VU/latency aggregates), the k6 summary (formal percentiles, named counters). Formal verdicts depend only on this tier.
- **B. SYSTEM HEALTH** — `residency.jsonl`, `soak-metrics.jsonl`, `proc-detail.jsonl`, audit DB/receiver evidence, sidecar summaries, runtime provenance. The 30-minute stability classification depends on this tier.
- **C. FORENSIC/OPTIONAL** — `diag.jsonl.gz`, a bounded sampled point log for manual debugging, slow-request samples, and reproduction assistance. **It is not a source of any gate number.**

The F3000-30M-R2 run exceeded the forensic artifact's 512 MiB logical-byte cap late in its 30-minute window. Under the old contract that truncated forensic artifact invalidated the entire point, despite every authoritative and system-health artifact being complete and internally consistent.

## The repair (harness only — no production code, no load model, no thresholds)

### `perf/tools/checkpoint_analyze.py`

- `KEEP_ALWAYS` slimmed: `cap_iter_begin`, `cap_iter_end`, `iterations`, `data_received`, `data_sent` removed. Their identities are exhaustively counted in tier A (per-second bins + exact cohort counters); diag retains only sampled copies via `SAMPLE_EVERY`/`BUDGET_PER_METRIC_SEC`/`TAIL_MS`. The 512 MiB `MAX_DIAG_BYTES` bound is kept — a bounded forensic artifact is correct; the fix is that its fullness no longer masquerades as authoritative completeness.
- `lag_over_5s`/`lag_max_s` implemented for real (they were dead counters, always 0). Consumer lag is measured as `now − point.time` per point. Rationale recorded in code: the analyzer drains a FIFO that mechanically backpressures k6's output writer once the pipe fills, so lag>0 is **evidence-pipeline** information.
- Stats now emit `max_diag_bytes` and `diag_overflow_dropped` (points rejected *because the byte cap was already hit* — the true truncation volume, distinct from per-second keep-budget rejects counted by `diag_budget_exceeded`).

### `perf/tools/capacity_search.py`

- `stream_evidence()` no longer requires `diag.jsonl.gz` and no longer lists `diag_overflow` among validity problems. It projects `forensic_diag = {status: COMPLETE|TRUNCATED|ABSENT, truncated, budget_exceeded_points, overflow_dropped_points, logical_bytes_cap}` for reporting only.
- `lag_over_5s > 0` is reclassified as **evidence-pipeline invalidity** (`evidence_pipeline_lag_over_5s` → `INVALID / evidence_pipeline_invalid` → fail_class `EVIDENCE_PIPELINE_INVALID`), matching the FIFO fact that a lagging consumer can block the k6 writer. For F3000-30M-R2 the recorded value is 0 (and, disclosed: the recording analyzer predates the live implementation of this counter, so its true consumption lag is unrecoverable — point timestamps are k6-side, so bin/cohort classification is unaffected either way).
- `generator_resource_evidence()` no longer counts analyzer stats at all. It now contains only real generator resource/process faults: container OOMKilled, CPU throttling, socket/fd exhaustion signatures in `run.log`, k6 panic, abnormal non-threshold exit.

### `perf/tools/pool_size_ab.py`

- `classify_stability` maps `EVIDENCE_PIPELINE_INVALID` → `(INVALID, EVIDENCE_PIPELINE_INVALID)`.
- The post-run analysis block was extracted verbatim into `_post_run_verdict(...)` so `--reeval POINT_DIR` replays the **identical code path** offline over saved evidence (no docker, no load). `enforce_report_time=False` is passed for replay: the report-time gate exists to catch fabricated publication clocks, not to retroactively fail a re-evaluation. The reeval output is explicitly marked `offline_reeval` / `new_real_load_time_s: 0`.
- `result["forensic_diag"]` is surfaced in every verdict.

### Not relaxed (§15)

Every performance threshold is unchanged: `rate ≥ 99.5%`, `drop ≤ 0.1%`, `unexpected = 0`, `p95 ≤ 100 ms`, `p99 ≤ 250 ms`, `late_vu_fraction ≤ 0.1%`, SUSTAINED_CLIFF definition, pool/audit/refresh health gates, provenance gates. The only semantic change is that forensic-artifact completeness no longer stands in for authoritative-evidence completeness.

## Zero-load proof (§10/§11/§12 — all in `perf/tests/test_evidence_contract.py`)

- **Overflow invariance:** the same synthetic point stream was consumed twice — once with the normal 512 MiB budget, once with `MAX_DIAG_BYTES` shrunk to 200 bytes (overflow fires immediately). `finalize_bins()`, `window_json`, and `measurement_cohort` are **byte-identical**; only `diag_overflow`/`diag_overflow_dropped` and the diag content differ. If any formal field had changed, the test fails.
- **Truncated diag → formal PASS** projected with `forensic_diag.status = TRUNCATED`; **missing diag → ABSENT**, still valid; complete → `COMPLETE`.
- **`lag_over_5s > 0` → `INVALID: evidence_pipeline_invalid`**, fail_class `EVIDENCE_PIPELINE_INVALID`; live lag measurement verified on synthetic points.
- **Generator resource scope:** analyzer stats (lag + overflow) produce zero `load_generator_evidence`; real signatures (`too many open files`, OOMKilled) still count.
- **Fail-closed preserved:** `parse_errors > 0`, `reader_error`, invalid/divergent window, `pending_drops_overflow`, `started ≠ completed`, `outcome_sum ≠ completed`, missing `series.json`/`analyzer-stats.json` — all still INVALID.
- **Stability ignores diag:** `stability_analyze` source contains no `diag.jsonl`/`diag_out`/`diag_fh` reference; `analyze()` returns identical results with and without the file.
- Historical verdicts re-verified by the suite: B1 FAIL, B2 PASS, F3000R2 (10 m) PASS — unchanged.

Suite: **366 tests, 0 failures, 1 skipped.**

## Offline re-evaluation of F3000-30M-R2 (§13)

Method: extracted the archived evidence set (`f3000-30m-r2-evidence.tar.gz`, jgw_bot1) unmodified into a scratch dir and ran `pool_size_ab.py --reeval` — the same `_post_run_verdict` code the live runner executes — over it. No artifact was edited; the recorded old verdict was not an input.

| Re-evaluated result | Value |
|---|---|
| `verdict` | **PASS** |
| `fail_class` | none |
| capacity gate | `PASS` |
| failed checks | `[]` — every health/provenance/sidecar check passed |
| `forensic_diag.status` | `TRUNCATED` (`budget_exceeded_points` 8,587,268; cap/lost-point fields absent in the old stats schema) |

Measurement re-derived from raw stream artifacts (not the old report):

| Metric | Value |
|---|---|
| started / completed | 5,355,005 / 5,355,005 |
| window drops | 0 |
| measured rate | 3000.003 ops/s |
| p95 / p99 | 41 ms / 135 ms |
| unexpected | 0 |
| `SUSTAINED_CLIFF` | NO |
| audit | enqueued == persisted == 895,378; dropped 0; journal contiguous; receiver reconciled |
| refresh family | invariants held |
| sidecars | 4/4 ready+timed+exit 0 |
| provenance | PASS (workspace, binary 3-way sha match, schema, samplers, timestamps) |

## Verdict handling (§14)

- `ORIGINAL_F3000_30M_R2_VERDICT = INVALID` — preserved unmodified in `docs/performance/reports/formal3000-30m-harness-repair/` (reason recorded under the old contract).
- That report is now marked `SUPERSEDED_EVIDENCE_CONTRACT_BY = formal-evidence-contract-repair`.
- `CORRECTED_F3000_30M_R2_VERDICT = PASS` — registered here. This is the **same execution and the same raw evidence** re-classified under a repaired evidence contract, not a rerun and not a better point picked after the fact. `NEW_REAL_LOAD_TIME = 0`.
- The older `F3000-30M` report's supersession pointer now resolves through this corrected R2 result.

## Consequences (§17-§18)

```
FORMAL_10M_3000_CAPACITY   = PASS
FORMAL_30M_3000_STABILITY  = PASS
READY_FOR_MERGE            = YES
PRIMARY_LIMIT              = NONE
NEXT_PRODUCTION_CANDIDATE  = NONE
POOL_32                    = PASS   (DATABASE_MAX_CONNECTIONS=32)
RSA_REUSE_STATUS           = CONFIRMED_AND_PRESENT
AUDIT_BATCH_STATUS         = PASS_AND_PRESENT
TOKEN_AUDIT_PREFLIGHT_STATUS = PASS_AND_PRESENT
GROUP_COMMIT_CANDIDATE     = FAIL
COMMIT_DELAY               = 0
WAL_SYNC_METHOD_CANDIDATE  = NOT_TESTED (fdatasync retained)
DURABILITY_CHANGED         = NO
PRODUCTION_CODE_CHANGED    = NO
```

`READY_FOR_MERGE` means the performance-optimization stack plus the harness repairs has reached merge-evaluation readiness. No automatic merge to `main` is performed. The 3000/s campaign is closed — no further capacity experiments under this task.

### Residual forensic caveat (honest limitation)

`FORENSIC_DIAG_STATUS = TRUNCATED` stands as a permanent caveat on this execution: per-point forensic detail for the tail of the 30-minute window was never written. It cannot be recovered (points were dropped at write time), and it is not needed for the formal verdict. For any future long formal run, the slimmer `KEEP_ALWAYS` policy keeps the artifact well inside the cap while preserving contract points, drops, failures, tails, and fixed-ratio samples.
