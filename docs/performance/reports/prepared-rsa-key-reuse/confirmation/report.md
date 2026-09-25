# prepared-rsa-key-reuse — independent confirmation

Branch: `perf/prepared-rsa-confirm-a797b729`
Pre-registered plan: [plan.md](plan.md) (committed before any load run;
gates unchanged after execution).

## Verdict

| field | value |
| --- | --- |
| paired phase (3×A/B, cap_client_credentials) | **PASS** |
| mixed phase (cap_mixed 3000/s) | **FAIL — health gate `queue_full=0` violated on BOTH sides** |
| CC_THROUGHPUT_GAIN | CONFIRMED (geomean 1.444) |
| MIXED_REGRESSION_CHECK | FAIL (audit-sink `queue_full` > 0 on A and B) |
| CANDIDATE_RETAINED | NO — stays on this unmerged branch |
| READY_FOR_MERGE | NO |
| SYSTEM_MAX_CAPACITY | NOT_TESTED |
| STRICT_30M_CAPACITY | NOT_TESTED |

Per the registered outcomes, a mixed FAIL keeps the evidence and leaves
the candidate on this unmerged branch. No thresholds were adjusted, no
extra points were added, and no further experiment is started.

## Code identity

| item | value |
| --- | --- |
| BASE_SHA (A) | `b8e1aead20d4f875f64e55eb4bb3fb71d758cfd7` |
| RESTORED_CANDIDATE_SHA | `86c5907ab01873d596a55a84344d4c9a4b8f34bf` (revert-of-revert of `37a107a9`; restores `47f43178` production patch byte-identically) |
| HARNESS_SHA | `86c5907ab01873d596a55a84344d4c9a4b8f34bf` |
| A binary sha256 | `24d8067d395c624c7677e3d8c45d8e18c8be04182177bcb4d32ede17389fa0ae` |
| B binary sha256 | `4896749e163efce6dfedcc6bdec9f6ddf8ea84265798dd430632d251a7e9e966` |
| images | `prsa-base:b8e1aead`, `prsa-cand:47f43178` (preflight verified binaries differ; candidate image carries the same production code as the restored commit — identical to the original candidate build because the restore is byte-identical) |

Production delta is exactly the original RSA patch
(`crates/crypto/src/signature.rs` + the matching comment in
`crates/key-management/src/model.rs`). No Cargo.lock, dependency,
algorithm, pool, PG, or infrastructure changes.

## Tests (remote, `--locked`)

- crypto contract: 13/13 PASS — including restored strict
  construction-rejection and hot-path structural tests (RSA arm contains
  no `from_der`/`from_pkcs8`/`signer_factory`/`try_sign`).
- key-management: 73/73 PASS.
- driver offline unit tests: 38/38 PASS (journal scanner, same-window
  CPU/success, pair gates, mixed gates, env-arg filtering).

## Microbenchmark (single rerun, ≤180s, Instant-measured)

`evidence/microbench-confirm.jsonl` — corrected timing (real elapsed
≈5.0001s, completed counted post-sign, `in_flight_at_boundary=0`):

| case | A ns/sign | B ns/sign | Δ |
| --- | --- | --- | --- |
| RS256 1T | ~589,327 | ~239,314 | **−59.4%** |
| PS256 1T | ~593,777 | ~241,050 | **−59.4%** |
| RS256 8T signs/s | ~12,843 | ~31,696 | **+147%** |
| PS256 8T signs/s | ~12,801 | ~31,533 | **+146%** |

A discarded earlier run whose `in_flight` semantics were wrong is kept
at `evidence/microbench-confirm-superseded-timing.jsonl`
(`elapsed_ns=5000000000` hardcoded, no boundary accounting); it is not
used for any claim.

## Phase 1 — paired results

| pair | A ops/s | B ops/s | ratio | p99 A→B (ms) |
| --- | --- | --- | --- | --- |
| 1 (A3→B3) | 3862.5 | 5717.5 | 1.4803 | 36→29 |
| 2 (B4→A4) | 3986.1 | 5648.3 | 1.4170 | 31→30 |
| 3 (A5→B5) | 3975.0 | 5705.1 | 1.4353 | 33→29 |

Geometric mean **1.444** (≥1.15), all ratios ≥1.10, p99 improved in
every pair. Cross-pair A spread 3.2% (reported, not a veto). All six
points valid: pinset affinity verified, shared keyset fingerprints
identical (4 files, sha256 listed per point), `unexpected=0`,
`local_no_request=0`, `expected_rejection=0`, no OOM/restarts,
audit two-sided check PASS.

## Phase 2 — mixed results

Common window: 162.0s / 162.2s (contract windows + conservative
container bounds for the non-contract argon2 sidecar).

| metric | A | B |
| --- | --- | --- |
| successful_ops_per_s | 1797.7 | 2557.8 |
| drop_fraction | 0.3959 | 0.1368 |
| op p99 (ms) | 1596 | 1117 |
| local_no_request frac | 0.0068 | 0.0079 |
| expected_rejection frac | 0.0002 | 0.0002 |
| unexpected | 0 | 0 |
| OOM/restart | none | none |
| refresh invariants | scope≤10, spent≤64, backlog=0 | same |
| sidecars | 4/4 natural exit 0, terminal summaries, real HTTP req counts (6858/72000/26855/73347) | 4/4 same (8352/72002/26395/101195) |
| audit state check | PASS | PASS |
| **queue_full (audit-sink try_send failures)** | **51,838** | **71,242** |
| dropped_required | 0 | 0 |

Comparative gates all pass (B ≥ 0.97·A by a wide margin, drops and p99
improved, classification fractions within +0.5pp, unexpected=0). The
absolute health gate `queue_full=0` fails on **both** sides: under the
3000/s mixed profile the audit durable-sink mpsc saturates and sheds
best-effort events (`persistence_status=not_queued`); no required-class
event was dropped (`dropped_required=0`) and the durable chain +
receiver journal reconcile exactly (see below). All six paired CC
points had `queue_full=0`, so the saturation is specific to the mixed
profile, not the RSA change — B's larger count is proportional to its
42% higher event-generating throughput. This is a newly measured
shared audit-pipeline capacity limit; per the protocol an unhealthy A
cannot serve as baseline, so the mixed check is recorded as FAIL and
certifies nothing about system capacity.

Strict 99.5% arrival gate (reported separately): A achieved 60.4% of
scheduled iterations (~1977/s), B 86.3% (~2591/s) — neither sustains
the requested 3000/s under 1024 max VUs; noted as observation only.

## Audit / journal verification

Per point: receiver `/__state` + `/checkpoint` vs
`security_audit_chain_state` — sequence, head hash and deployment
equal; `pending=0`; `fault=none`; journal `accepted_events` delta equals
DB delta; journal range contiguous, no duplicate batches, deployment
bound, streamed (not fully loaded), input hash + path recorded.

- CC points: `token_issued` in checkpoint range == `iterations_completed`
  exactly (349756/513019/509875/357602/356839/511409).
- Mixed: no 1:1 claim (multi-grant + sidecars); journal event-type
  counts recorded in `MIXED*.point.json` (`token_issued`
  312915/437429, plus refresh/authorization/fapi types). Both sides
  show `refresh_reuse_detected=1` from the reuse-detection probes.

## CPU/success (same-window, auxiliary only)

Per-second proc-detail CPU ÷ same-interval completed successes:
A3 1.1498ms, B3 0.7591ms (status OK, boundary interpolation flagged as
estimate). Mixed = UNAVAILABLE (audit events are not a 1:1 completion
counter) — reported, not estimated. The old −37% figure remains a
misaligned-window observation and is not claimed here.

## Budget

Planned 900s; hard cap 1200s including failed attempts. Actual
`load_seconds` ledger (`evidence/budget.json`): two superseded A3
attempts 98.4+97.9s (killed for sampler/fingerprint environment fixes,
counted as failed attempts), six valid paired points 588.7s, two mixed
points 383.0s — **total 1168.0s ≤ 1200s**. Build/seed/setup time is not
counted as load.

## Corrections applied vs the first experiment (evidence in this run)

1. CPU/success uses the identical interval for numerator and
   denominator; UNAVAILABLE when no denominator exists.
2. Audit event counting reads the receiver `journal.jsonl` (the removed
   `security_audit_events.sequence` query is deleted; no drain-time DB
   join — ACKed rows are deleted by design).
3. Mixed gate is `B ≥ 0.97·A` (the `*1.03` error removed);
   no-request/expected-rejection are bounded fractions (≤+0.5pp), not
   forced to zero.
4. Probe timing: `Instant`-measured, post-sign completion counting,
   boundary in-flight recorded.
5. `planned` budget estimate mirrors the measured accounting (one shared
   elapsed window per point; sidecars run concurrently — they are not
   summed). The earlier additive estimate would have falsely reported
   budget exhaustion.
6. Sidecar env filtering removes orphaned `-e`; sidecar `started_ts`
   propagated into evidence so non-contract sidecars contribute a
   conservative container-bound window.
7. Keyset fingerprinting runs as root (runtime key files are
   root:0600); binary sha256 verified inside containers — tag equality
   is never trusted (the earlier build-cache collision is why).

## Evidence bundle

`evidence/` — per-point `point.json` (raw metrics, journal stats, audit
checks, CPU windows, keyset fingerprints, sidecar facts), `manifest.json`
(image/binary identity), `paired-eval.json`, `mixed-eval.json`,
`budget.json`, `microbench-confirm.jsonl`, superseded probe run.
Private keys never leave the remote fixture; only sha256 fingerprints
are recorded.

The first experiment's report, raw data, gates and INCONCLUSIVE verdict
are unchanged; this confirmation supersedes nothing — it is a new
paired protocol with its own evidence.
