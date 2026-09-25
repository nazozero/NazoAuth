# prepared-rsa-key-reuse — report

Date: 2026-09-24 · Host: authorized remote benchmark host (cnb workspace
`cnb-r49-1k38f54tm-001`) · All compile/test/microbench/load on remote; local
host used only for editing/sync.

## Identity

| field | value |
|---|---|
| BASE_SHA | `b8e1aead20d4f875f64e55eb4bb3fb71d758cfd7` |
| HARNESS_SHA | `47f431785dba9b2d510a01e262ef6c4ff44577b9` |
| BASELINE_APP_SHA | `b8e1aead20d4f875f64e55eb4bb3fb71d758cfd7` (image `prsa-base:b8e1aead`, binary sha256 `24d8067d395c…`) |
| CANDIDATE_APP_SHA | `47f431785dba9b2d510a01e262ef6c4ff44577b9` (image `prsa-cand:47f43178`, binary sha256 `4896749e163e…`) |
| jsonwebtoken | 11.0.0 (Cargo.lock, unchanged, `--locked` builds) |
| aws-lc-rs | 1.18.1 (Cargo.lock, unchanged) |

Binary-identity hygiene note: the first candidate image build produced a
binary byte-identical to baseline (buildkit cache hit on the shared cargo
target mount). It was rebuilt with `--no-cache-filter product-builder`;
the two shipped binaries now differ and each point's `provenance.json`
records the container binary sha256 actually measured.

## Call chain — before and after

Old (`b8e1aead`):

```
PreparedSigningKey::sign()
  → jsonwebtoken aws_lc DEFAULT_PROVIDER.signer_factory()   (per sign)
    → JwtSigner::try_sign()
      → RsaKeyPair::from_der(encoding_key.as_bytes())       (per sign)
        → KeyPair::new → validate_private_key
```

The old `PreparedSigningKey` cached only the byte-wrapping `EncodingKey`;
the factory call in `new()` probed family compatibility and discarded the
signer — for RSA it did **not** pre-parse the key pair.

New (candidate `47f43178`, later reverted — see verdict):

```
PreparedSigningKey::new()  → RsaKeyPair::from_der() once, stored
PreparedSigningKey::sign() → stored_pair.sign(RSA_PKCS1_SHA256 |
                              RSA_PSS_SHA256, SystemRandom, msg, buf)
```

RSA DER parse + private-key validation moved from per-signature to
per-generation construction. EdDSA/ES256 unchanged (provider path).
Padding constants, modulus-sized per-call output buffer, SystemRandom —
identical to the upstream `try_sign_rsa` shape. Error-discovery phase
change (documented, intended): malformed RSA DER now fails in `new()`
with `InvalidKey` instead of first `sign()`; an unusable generation can
no longer be published.

Resident-memory implication: `PreparedSigningKey` now holds one
`aws_lc_rs::rsa::KeyPair` (~RSA-2048 key material, a few KB) instead of
the DER byte vector — a fixed per-generation increase on the order of
single-digit KB. No second DER copy is retained for RSA (the
`EncodingKey` arm is not used for RSA algorithms).

## Correctness (remote, `--locked`)

- `nazo-crypto --features jose --test contract`: **13/13 pass** at the
  candidate commit (incl. RS256 byte-identical vs provider path, PS256
  verify+randomness, RS256↔PS256 cross-rejection, construction-time DER
  rejection, `Send + Sync` + shared `Arc` 8-thread sign/verify, Debug
  non-leakage, RSA sign arm contains no `from_der`/`signer_factory`).
  At branch tip (reverted): the construction-rejection and structural
  checks were relaxed to match the restored implementation (invalid DER
  still can never sign; the provider path re-parses per sign again);
  **12/12 pass** on the final tree.
- `nazo-key-management --all-features`: **73/73 pass** (rotation,
  generation lifecycle, signing paths unchanged).
- Python offline: `test_prepared_rsa_ab` 25/25, `test_single_instance_scaling` 77/77.

## Microbenchmark (remote, release, same build profile)

`crates/crypto/examples/prepared_rsa_probe.rs`, schedule A1→B1→B2→A2,
1s warmup + 5s timed per segment, 1024-byte message with mutated counter,
shared key across threads. Wall clock ≈ 100s (≤180s budget). Raw:
`evidence/microbench.jsonl`.

| cell | A ns/sign (mean of A1,A2) | B ns/sign (mean B1,B2) | change |
|---|---|---|---|
| RS256 1T | 597,683 | 236,721 | **−60.4%** |
| PS256 1T | 594,001 | 239,993 | **−59.6%** |
| RS256 8T | 12,153 sig/s | 28,976 sig/s | +138% (no regression) |
| PS256 8T | 12,553 sig/s | 31,538 sig/s | +151% (no regression) |

Gates: single-thread ≥10% improvement — PASS both algorithms;
8-thread regression ≤3% — PASS (improved). The duplicated work eliminated
is ~360µs of DER parse + key validation per signature.

## End-to-end A/B (real load, remote)

Phase 1: `cap_client_credentials`, constant-vus 64, 120s + 15s warmup,
app pinned **before** exec to 8 physical cores (one SMT sibling each;
verified `Cpus_allowed_list=24,26,132,134,136,138,140,142` on pid1; 18
threads all born inside the mask), PG/Valkey/k6/audit on disjoint infra
set `144-191`. `DATABASE_MAX_CONNECTIONS=24`, fsync/sync_commit/
full_page_writes on, no resource changes.

| point | successful ops/s | op p99 ms | app CPU ms/success | unexpected | local_no_request | restart/OOM |
|---|---|---|---|---|---|---|
| A1 (base) | 3191.14 | 39 | 1.1656 | 0 | 0 | none |
| B1 (cand) | 4582.48 | 35 | 0.7292 | 0 | 0 | none |
| B2 (cand) | 4518.44 | 34 | 0.7131 | 0 | 0 | none |
| A2 (base) | 3630.85 | 36 | 1.1297 | 0 | 0 | none |

A1/A2 spread = (3630.85−3191.14)/3630.85 = **12.1% > 5%** → baseline
unstable → **verdict INCONCLUSIVE** (`evidence/phase1-gates.json`). Per
the pre-declared rule no further performance phase was added; the mixed
A/B (Phase 2) was skipped by the driver and no extra points were run.

Observed but **not claimable**: B1/B2 sit 24–27% above `max(A1,A2)` and
app CPU/success fell ~37%. Because the A baseline itself moved 12.1%
between its two points, these deltas do not satisfy the stability
precondition and are reported as observations, not gains.

Real-load wall clock: **796 s elapsed** (4 points incl. stack
up/down + drain), **513 s of measured load** (4 × ~128 s), zero failed
attempts — inside the 20-minute hard cap.

## Audit state verification (per point, real two-sided check)

Existing receiver endpoints only (`GET /__state`, `GET /checkpoint`,
Bearer + per-run CA), compared with `security_audit_chain_state`
(pending / last / anchor seq+hash / anchor deployment). Pre-load
baseline captured post-seed so seed/startup events are excluded from the
measured increment.

All four points: pending=0, DB head == anchor == receiver checkpoint
(sequence **and** hash bytes), deployment_id identical on both sides,
receiver fault=none, checkpoint advanced — **PASS**.

CC issuance correlation: chain-sequence delta == receiver
`accepted_events` delta == `iterations_completed` exactly
(383547 / 547345 / 541763 / 429844) — the one-token_issued-per-successful-
issuance contract holds 1:1 over the whole point.

Caveat recorded: the in-run driver compared the event delta against the
105 s measure-window `outcome_success` (wrong denominator — the delta
spans warmup+measure). Raw pre/post snapshots are preserved in each
`point.json`; the verdicts above recompute the same checks against
`iterations_completed` (the correct whole-point denominator). No
evidence was regenerated; the run-time `audit_state_check` fields in the
saved point.json still show the stale `token_issued_eq_success` failure.

## Verdicts

| field | value |
|---|---|
| RSA_PARSE_REUSE | IMPLEMENTED (verified in microbench + point binaries), REVERTED at branch tip |
| RS256_SIGN_COST_CHANGE | −60.4% ns/sign (microbench) |
| PS256_SIGN_COST_CHANGE | −59.6% ns/sign (microbench) |
| END_TO_END_THROUGHPUT_CHANGE | INCONCLUSIVE (A1/A2 spread 12.1% > 5%) |
| APP_CPU_PER_SUCCESS_CHANGE | NOT_ESTABLISHED (baseline unstable; observed −37% is not evidence) |
| AUDIT_STATE_CHECK | PASS ×4 (two-sided seq/hash/deployment reconciliation) |
| CANDIDATE_RETAINED | **NO** — correctness+microbench gates passed, end-to-end gain gate INCONCLUSIVE; production change reverted by explicit revert commit |
| SYSTEM_CAPACITY_GAIN | NOT_ESTABLISHED |
| EFFICIENCY_GAIN | NOT_ESTABLISHED |
| MEASURED_SYSTEM_GAIN | NOT_ESTABLISHED |
| PRIMARY_SCALING_BOTTLENECK | UNRESOLVED |
| DURABILITY_CHANGED | NO |
| DB_POOL_CHANGED | NO |
| STRICT_30M_CAPACITY | NOT_TESTED |
| NEW_REAL_LOAD_TIME | 796 s elapsed / 513 s measured load, 0 failed attempts |
| PRODUCTION_CHANGES | NONE at branch tip (candidate committed as 47f43178, then reverted) |

Microbench-local acceleration is not an end-to-end improvement claim.
The retained artifacts are the test coverage, the probe, the focused A/B
driver, and this report — the production signing path is byte-identical
to the reviewed base at branch tip.

## Follow-up: independent confirmation (paired protocol)

A separate, pre-registered paired confirmation was run on branch
`perf/prepared-rsa-confirm-a797b729`:
[confirmation/report.md](confirmation/report.md). It restored the same
production patch, corrected the measurement defects found here
(misaligned CPU/success window, the removed `security_audit_events.sequence`
query, the `*1.03` mixed gate, and the probe's hardcoded elapsed time),
and evaluated three A/B pairs plus a mixed non-regression check.

Outcome there: paired phase PASS (geomean 1.444), mixed phase FAIL on
the pre-declared `queue_full=0` health gate — violated by BOTH baseline
and candidate under the 3000/s mixed profile (best-effort audit events
shed from a saturated durable-sink queue; `dropped_required=0`, audit
reconciliation still PASS). Per protocol the candidate stays unmerged.
This report's INCONCLUSIVE verdict and raw data stand unchanged.
