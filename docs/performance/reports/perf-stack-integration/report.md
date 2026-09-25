# Performance-stack clean integration

Clean reconstruction of the accepted performance stack on top of latest
`main`. This branch ports only the final net diff of the accepted source
branch — it does not merge, rebase, or cherry-pick the experimental chain.

- Integration base (`LATEST_MAIN_SHA`): `bb5f42c60d24c18bf71d279ad50aee4935f0cca0`
- Source branch: `perf/formal-evidence-contract-52fb25b3`
- Source final (`SOURCE_FINAL_SHA`): `c39e35dfbfc68cebaab62d61b88bf75d665555f9`
- `MAIN_DIVERGED`: NO (`origin/main` == `cnb/main` at integration base)
- `NEW_REAL_LOAD_TIME`: 0 s (no capacity/soak/formal run was executed)

## Production diff ledger

Exactly three accepted candidates; nothing else in `crates/**`, `migrations`,
or deployment configuration.

| # | Candidate | Files | Semantics preserved |
|---|---|---|---|
| 1 | Native RSA prepared-key reuse | `crates/crypto/src/signature.rs`, `crates/crypto/tests/contract.rs`, `crates/key-management/src/model.rs` | `PreparedSigningKey` caches the parsed `aws_lc_rs::rsa::KeyPair` for RS256/PS256; DER parsed once at construction; `RSA_PKCS1_SHA256`/`RSA_PSS_SHA256` + `SystemRandom` + modulus-sized output; EdDSA/ES256 keep the provider path. No global cache, mutex, pool, or runtime config added. |
| 2 | Best-effort audit batch persistence | `crates/persistence/src/lib.rs`, `crates/persistence-postgres/src/lib.rs`, `crates/persistence-postgres/src/repositories/audit_ledger.rs`, `crates/nazoauth/src/adapters/audit.rs`, `crates/nazoauth/src/http/perf_metrics.rs`, tests | `append_batch` port; batch>1 = one business-pool connection + one transaction + sequential `append_on_connection` + single commit; batch of 1 keeps the existing path; failed transactions do not return the connection to the pool; queue capacity 4096 / worker 1 / batch max 64 unchanged; required audit events keep the synchronous durable path. |
| 3 | Transactional token-audit preflight elision | `crates/authorization-server/src/ports/audit.rs`, `crates/authorization-server/src/token/issue_grant.rs`, tests | `ensure_transactional_ready()` default delegates to `ensure_storage()`; only the narrow commit-owned case (fresh issuance, no refresh, no authorization-code hash, no native SSO) uses it; dynamic anchor-health gate preserved; required `token_issued` append remains durable/transactional/fail-closed inside the same transaction. |

`Cargo.toml`/`Cargo.lock`: **no net change** vs `bb5f42c6`. `aws-lc-rs` was
already a `nazo-crypto` dependency on main; the source branch's only manifest
delta was the `[[example]]` entry for the one-shot `prepared_rsa_probe`
microbenchmark — dropped with the probe itself.

## Production tree equivalence (vs `c39e35df`)

| Result | Files |
|---|---|
| `EXACT_MATCH` (byte-identical) | `ports/audit.rs`, `issue_grant.rs`, `signature.rs`, `key-management/model.rs`, `nazoauth/adapters/audit.rs`*, `http/perf_metrics.rs`, `persistence/src/lib.rs`, `persistence-postgres/src/lib.rs`*, `repositories/audit_ledger.rs`*, all six ported test files* |
| `MERGED_WITH_NEW_MAIN_CHANGE` | none — latest main had no overlapping changes in these paths |
| `INTENTIONALLY_DIFFERS` | `crates/crypto/Cargo.toml` = main (source's only delta was the dropped `[[example]]` probe) |

\* Seven files carry rustfmt-1.9.0 whitespace normalization only; after
normalizing both sides through `rustfmt` they are byte-identical
(`EQUIV`), so no semantic drift exists. `mfa_profile.rs` has a pre-existing
fmt violation on `bb5f42c6` itself — left untouched (unrelated file).

## Harness reconstruction

Kept (final repaired form):

- `capacity_search.py` — stream-authoritative gates, evidence tiers,
  `lag_over_5s` fail-closed as `EVIDENCE_PIPELINE_INVALID`, forensic diag
  separated from formal accounting.
- `checkpoint_analyze.py`, `checkpoint_observer.py`, `measure_schedule.py`,
  `perf_state_ready.py`, `stability_analyze.py`, `residency_analyze.py`,
  `residency_observer.py`, `proc_detail_sampler.py`.
- `single_instance_scaling.py` — shared stack toolkit (compose management,
  pinning, provenance, samplers, pgss/wal, budget, run_load). Env-parametrized
  CLI; no baked-in experiment data. **Not** a one-shot driver.
- `pool_size_ab.py` — formal pool/capacity/stability runner incl. offline
  `--reeval`.
- **New `point_runner.py`** — shared point-runner core extracted from the
  one-shot A/B drivers (image hashing, receiver state, journal scan, audit
  reconciliation, pinned stack startup, point execution, sidecar evidence,
  health checks, audit-queue finalization). `PRE_APP_HOOK` and the dead
  duplicate `journal_event_counts` stub removed; dead import
  `runtime_session_show` removed.
- k6: `measurement_clock.js`, `checkpoint_clock_test.js`, `subject_state.js`,
  `subject_state_test.js`, updated `oauth.js`.
- Tests: 8 Python suites (stream cohort, capacity window, checkpoint
  measurement, evidence contract, pool A/B, residency analyze, scaling,
  stability).
- `perf/env.yaml`: `DATABASE_MAX_CONNECTIONS` 24→32 benchmark alignment only.

Dropped (one-shot drivers and helpers whose conclusions are frozen):
`prepared_rsa_ab.py`, `audit_batch_ab.py`, `token_audit_preflight_ab.py`,
`group_commit_ab.py`, `residency_run.py`, `prepared_rsa_probe.rs` example,
and their dedicated tests. Their shared helpers now live in
`point_runner.py`; formal runners no longer import experiment modules.

## Evidence keep/drop matrix

Kept canonical reports (all with manifest + report + minimal evidence):

| Report | Why canonical |
|---|---|
| `prepared-rsa-key-reuse` (+ `confirmation/`) | RSA candidate acceptance |
| `audit-batch-persistence` | Audit-batch candidate acceptance |
| `token-audit-preflight-elision` | Preflight candidate acceptance |
| `business-pool-24-vs-32` | POOL_32 evidence |
| `business-pool-residency` | Pool residency evidence |
| `single-instance-throughput-scaling` | Scaling-curve evidence |
| `formal3000-load-model-repair` | Formal 10 m capacity evidence chain |
| `formal3000-30m-stability` | ORIGINAL INVALID preserved (supersession chain) |
| `formal3000-30m-harness-repair` | ORIGINAL INVALID + R2 raw evidence |
| `formal-evidence-contract-repair` | Corrected PASS + reeval verdict |
| `capacity-window-accounting` | Window-accounting fix evidence |
| `checkpoint-jitter-remediation` | Measurement-contract fix evidence |
| `postgres-group-commit` | FAIL record — rejected candidate kept as report only |

Dropped: ~118 MB of redundant raw evidence inside the above trees
(duplicate unpacked point trees where a tarball preserves the full raw
set, oversized forensic `diag` streams, repeated PGSS/WAL snapshots).
The supersession chain `formal3000-30m-stability (INVALID)` →
`formal3000-30m-harness-repair (INVALID)` →
`formal-evidence-contract-repair (PASS)` is fully retained — that history
explains how the same execution moved from INVALID to PASS and must not
be silently flattened.

## Manifest metadata repair

`formal-evidence-contract-repair/manifest.json` previously recorded
`final_sha = efc2cb13` (an intermediate commit). Now records
`harness_fix_sha`, `harness_test_sha`, `report_source_sha = c39e35df…`,
`integration_base = bb5f42c6…`. No self-referential SHA is claimed.

## Rejected candidates — not ported

`GROUP_COMMIT_CANDIDATE = FAIL`, `commit_delay = 0`, `wal_sync_method`
candidate `NOT_TESTED`. No commit_delay/wal_sync_method production or
benchmark config was carried; `pool_size_ab` still asserts the baseline
GUC set (`fsync=on`, `synchronous_commit=on`, `full_page_writes=on`,
`commit_delay=0`, `commit_siblings=5`, `track_wal_io_timing=off`).

## Validation

- Baseline: `origin/main` re-fetched at final validation; still
  `bb5f42c6` — integration base remains current (`0 5` left-right count).
- `cargo fmt --check`: PASS on every file added or modified by this
  branch; `mfa_profile.rs:457` is a pre-existing violation on `bb5f42c6`
  itself (verified in a clean main worktree; untouched here).
- Targeted crates: `nazo-crypto`, `nazo-key-management`, `nazo-oauth-server`,
  `nazo-persistence` — all `test result: ok`, 0 failures.
- Real PostgreSQL: `audit_ledger` 9/9, `token_issuance_fresh` 12/12.
- Focused `nazoauth` unit tests (audit + token issue paths): 79/79.
- `cargo test --workspace` (131 test binaries): the only failing binary is
  `nazoauth` lib. Its failure set on this branch equals the failure set of
  unmodified `bb5f42c6` run in the same environment: two
  environment-sensitive tests
  (`authorization_code_marker_failure_revokes_the_issued_access_token`,
  `refresh_grant_rejects_wrong_client_family_or_sender_constrained_
  successors_without_compromising_family`) plus contention flakes that
  pass under `--test-threads=1`. `WORKSPACE_TESTS = BASELINE_EQUIVALENT`,
  `WORKSPACE_REGRESSION = NO`.
- Perf Python suite: 276 pass / 0 fail / 1 skip.
- JS harness (k6 2.2.0 pinned container): `subject_state_test` 10/10,
  `checkpoint_clock_test` `pass:true` (begin/end reconciled, late-VU
  coverage). Zero SUT traffic.
- One-shot driver runtime dependencies: 0 — only docstring provenance
  mentions remain in `point_runner.py`.
- Formal path fail-closed: `pool_size_ab` invokes
  `evaluate(..., require_stream=True)`; missing stream evidence →
  `INVALID: stream_evidence_missing`.
- Secret scan of the full `origin/main...HEAD` diff plus decompressed
  evidence archives: no private keys, tokens, cookies, or credentials —
  only fixed perf fixtures and parameterized query text.
- Evidence added: ~19.8 MB (largest single artifact 2.8 MB tarball);
  minimum-sufficient set per keep/drop matrix below.
- No performance workload executed: `NEW_REAL_LOAD_TIME = 0s`.
