# Prepared-RSA confirmation — pre-registered plan

Status: **registered before any load run** (committed on branch
`perf/prepared-rsa-confirm-a797b729` prior to executing the experiment).
Gates below are fixed; they may not be edited after the run to make a
result pass.

## Subject

Restore the previously implemented candidate (commit `47f43178`, reverted
by `37a107a9`): `PreparedSigningKey` retains a parsed
`aws_lc_rs::rsa::KeyPair` for RS256/PS256 so request-time signing never
re-parses DER. Baseline app = `b8e1aead` production code; candidate app =
restored patch. The ONLY production-code delta between A and B is that
patch. Correctness tests are the strict (construction-rejection +
hot-path structural) versions, not the post-revert relaxed ones.

## Environment (identical for A and B)

- Same authorized host, same release profile, `--locked` deps
  (`jsonwebtoken 11.0.0`, `aws-lc-rs 1.18.1`).
- App: 8 physical cores, one hardware thread each; affinity applied via
  pinset `exec` wrapper BEFORE Tokio/Actix start. Infra pinned to a
  non-overlapping set (no SMT siblings of app cores).
- `DATABASE_MAX_CONNECTIONS=24`; PG params, fsync/synchronous_commit/
  full_page_writes, max_wal_size=8GB, checkpoint_timeout=5min unchanged.
- Audit exporter + receiver run for every point.
- One shared controlled keyset (external volume) across all points —
  per-point key fingerprints recorded and compared. Fresh postgres/
  valkey/audit volumes per point; same seed recipe.
- Preflight: `sha256` of `/usr/local/bin/nazoauth` inside both images
  must differ; equal binaries forbid the load.

## Measurement corrections applied since the first experiment

1. `cpu_per_success_ms` = app CPU between first/last proc-detail samples
   inside the window ÷ journal `occurred_at` completions in that SAME
   interval; UNAVAILABLE when no per-second denominator exists (incl.
   mixed). Auxiliary only — never a pass substitute. The old ~−37%
   figure stays a misaligned-window observation.
2. Audit event counts come from the receiver `journal.jsonl` (streamed,
   post-drain, hashed), filtered to (pre_seq, post_seq] — not from a
   removed DB column. Deployment binding, batch-chain contiguity,
   duplicates, `accepted_events` delta, DB↔receiver seq/hash equality
   are all checked. CC additionally requires `token_issued` delta ==
   whole-run `iterations_completed` (legitimate only on a fully clean
   run); mixed reports journal counts without a 1:1 claim.
3. Mixed non-regression: `B >= 0.97*A` (the erroneous `*1.03` is
   removed; A==B must pass). `local_no_request` and
   `expected_rejection` fractions (of measured attempts) may not grow
   by >0.5pp each vs A; `unexpected==0` stands.
4. Probe timing: `Instant`-measured interval, `completed` counted after
   each returned sign, message counter independent, boundary in-flight
   recorded. One rerun max (≤180s); the old microbench file is kept.

## Load plan (900s planned, 1200s hard cap including failures)

Phase 1 — three pairs, `cap_client_credentials`, constant-vus 64,
90s + 15s warmup, all pairs always executed once, adjacent within pair:

    Pair1: A3 -> B3   Pair2: B4 -> A4   Pair3: A5 -> B5

Phase 2 (only if paired PASS) — mixed A -> B, `cap_mixed`
constant-arrival-rate 3000/s, 180s + 15s warmup, main 256/1024 VU;
sidecars refresh 600/s(64/256), argon2 8/s(8/16), meta 200/s(16/32),
FAPI 30/s(32/64); common window >= 150s.

## Retention criteria (pre-declared engineering gate)

Every point must be valid: identity/affinity/window present, required
fields non-null, clean termination, unexpected=0, local_no_request=0,
expected_rejection=0, no OOM/restart, audit two-sided check PASS
(incl. CC token_issued==iterations).

Per pair `ratio_i = B_i.successful_ops_per_s / A_i.successful_ops_per_s`:
- all three ratios >= 1.10, AND
- geometric mean >= 1.15, AND
- per-pair B p99 not worse by both >10% and >2ms.

Cross-pair A variance is reported, never a veto. Per-second bins are not
independent samples.

Mixed: `B >= 0.97*A` successful rate, drop-fraction +<=0.1pp, p99 bound,
fractions bound, `queue_full=0`, refresh invariants (<=10 scope,
<=64 spent/family, 0 expired backlog), no OOM/restart, sidecars complete
with >0 HTTP requests, audit PASS on both sides — and A itself must be
healthy to serve as a baseline.

## Outcomes

- paired PASS + mixed PASS -> candidate retained on this branch
  (READY_FOR_MERGE for review; no merge performed here).
- paired GAIN_NOT_CONFIRMED or mixed FAIL -> keep evidence, candidate
  stays on the unmerged branch, report `GAIN_NOT_CONFIRMED`.
- Missing required evidence / infra failure -> `INVALID`/`PENDING`,
  branch kept unmerged; no automatic extra experiment.
- `SYSTEM_MAX_CAPACITY`, `STRICT_30M_CAPACITY` = NOT_TESTED regardless.
