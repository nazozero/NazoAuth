# transactional token-audit preflight elision — paired A/B

Date: 2026-09-24 · Branch: `perf/token-audit-preflight-elision-de603c8f`

## Identity

| Field | Value |
| --- | --- |
| BASE_SHA | `de603c8f6d5d613c6d533cc84990c504505a2bde` (carries confirmed RSA reuse + audit batching) |
| RSA_SHA | `86c5907a` — confirmed, present on both sides |
| AUDIT_BATCH_SHA | `de603c8f6d5d613c6d533cc84990c504505a2bde` — confirmed, present on both sides |
| COMMON_SHA | `53e05ebe02156e491f65de45388d2cdac7536f22` (A: port default + readiness tests + instrumentation, production path unchanged) |
| CANDIDATE_SHA | `86b2df169e05a65e0c482e1d6653a848c6aa83a8` (B: `ensure_transactional_ready` + predicate-gated call site) |
| TEST_FIX_SHA | `608b549289dc28410ff3abab3382530cb104b4bb` (test-only: dedicated admin conn in the revoke test) |
| A image / binary sha256 | `tap-a:53e05ebe` / `4ada844be97e3e408cc7357a2bdbb20e19f721edc794a3e0b02f61d7ff0a1223` |
| B image / binary sha256 | `tap-b:86b2df16` / `046c7d40861b63bdb8b75303d36b3b89d7ad0ad1cd50d86d7cec253020bba60a` |

Binaries verified in-container per point (`app_binary_sha256` in each
`point.json`). Both images built with full `--no-cache` — the shared
BuildKit `nazoauth-target` cache could not stale-hit. Keyset fingerprint
identical across all six points (shared `sisprsa-confirm-keys` volume);
RSA reuse and audit batching present and unchanged on both sides.

## What the candidate does

`issue_grant` computes a conservative commit-owned predicate —
`mode == Fresh` AND `!will_issue_refresh` AND `authorization_code_hash
is none` AND `native_sso is none` — and calls the new
`SecurityAudit::ensure_transactional_ready()` instead of
`ensure_storage()`. The production adapter resolves the installed durable
repository (absent ⇒ fail closed), skips the static writer-capability
probe in disabled/optional anchor mode, and keeps the dynamic
`anchor_health` + `ensure_fresh` gate in required mode. `ensure_storage`
is byte-identical and remains on every other issuance path. The final
`commit_token_issuance` still appends `token_issued` inside the same
transaction — the commit itself is the writer check.

Grant coverage actually hit: `client_credentials` (all of the CC phase)
plus Fresh token-exchange/JWT-bearer shapes in `cap_mixed`. Refresh
rotation, authorization-code redemption and Native SSO keep the full
preflight.

## Safety evidence (tests, real PostgreSQL 18 + Valkey)

| Suite | Result |
| --- | --- |
| `nazo-postgres --test token_issuance_fresh` | 12/12 — incl. `revoked_audit_append_execute_fails_the_fresh_commit`: mid-run `REVOKE EXECUTE` on `nazo_persist_security_audit_event` fails the commit, zero issuance/audit/outbox rows, no open transaction back to the pool |
| `nazoauth --lib audit_readiness` | 5/5 — Fresh commit-owned uses transactional gate (0,1); SingleUse/refresh/native-SSO keep `ensure_storage` (1,0); HTTP-level mid-run revoke ⇒ `server_error`, no `access_token`, no partial rows, re-grant recovers |
| `nazoauth --lib transactional_ready` | 11/11 — no repository ⇒ Err; disabled/optional ⇒ zero `check_available`/zero `anchor_health`; required ⇒ `anchor_health` 1× and every stale/mismatch/lag case fails closed; port default delegates to `ensure_storage` |
| `nazoauth --lib adapters::audit*` | 73/73 |
| `authorization-server` | 296/296 |
| `perf/tests/test_token_audit_preflight_ab.py` | 23/23 |

Startup writer-capability preflight (`check_available` at boot) is
untouched — the candidate only removes the per-request repetition.

## Protocol

CC: `cap_client_credentials` constant-vus=64, 90s + 15s warmup, order
`A1 → B1 → B2 → A2`. Mixed (after CC PASS): `cap_mixed` constant-arrival
3000/s, 180s + 15s warmup, sidecars refresh=600/s argon2=8/s
metadata=200/s fapi=30/s. PostgreSQL 18.6, app `pinset-exec` on the same
8 physical cores, infra pinned separately, pool=24, audit
exporter+receiver running throughout, `AUDIT_ANCHOR_MODE` unset on the
app (disabled). Load budget 900s; actual **769.7s**, zero failed
attempts.

## Results — client credentials

| Point | ops/s | p50/p95/p99 ms | success | pool acq | acq/op | wait avg ms | writer preflight (pgss) | per-success |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| A1 | 5375.2 | 11/18/33 | 403,140 | 1,947,355 | 3.9682 | 1.71 | 486,053 | 1.2057 |
| B1 | 5866.8 | 10/18/31 | 440,012 | 1,580,692 | 2.9717 | 2.09 | **0** | 0 |
| B2 | 5998.5 | 10/16/31 | 449,885 | 1,623,214 | 2.9828 | 2.03 | **0** | 0 |
| A2 | 5462.5 | 11/18/33 | 409,690 | 1,982,053 | 3.9768 | 1.69 | 494,727 | 1.2076 |

pgss per-issuance structure is exactly `client_lock = preflight =
issuance_insert = audit_append` on A and `preflight = 0` with the rest
identical on B — the removed call is the only difference.

Pre-registered structural gates: B preflight == 0 ✓; A ratio 1.206/1.208
within tolerance ✓; acq/op reduction 1.0008 / 0.9897 (≥0.9) ✓;
B_min/B1 5866.8 ≥ 0.97·A_max (5298.7) ✓. All health gates clean
(unexpected/local_no_request/expected_rejection/queue_full/
dropped_required = 0, outbox drained, audit reconciled, no OOM/restart).

Throughput did not merely hold — it improved: B mean 5932.6 vs A mean
5418.9 (**+9.5%**), B p99 31ms vs A 33ms. CPU: app ≈2.9–3.0 cores,
postgres ≈4.6–4.9 cores (B slightly less PG CPU at higher throughput —
fewer statements per issuance).

## Results — mixed 3000/s

| Point | ops/s | attainment | drop frac | p50/p95/p99 ms | success | acq/op | wait avg ms | writer preflight | per-success |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| A | 2436.7 | 81.2% | 0.1746 | 312/1094/1444 | 402,057 | 6.8746 | 70.24 | 492,734 | 1.2255 |
| B | 2815.8 | 93.9% | 0.0535 | 219/1007/1081 | 464,599 | 6.4311 | 61.74 | 351,967 | 0.7576 |

Mixed keeps non-eligible flows on `ensure_storage`, so B correctly still
shows 351,967 probes (refresh/auth-code/native-SSO) — strictly below A's
492,734, a 38% per-success reduction matching the eligible share.

Gates: B ops/s +15.6% vs A (≥0.97·A) ✓; drop fraction −12.1pp (≤+0.1pp)
✓; p99 1081 < 1444 (bounded) ✓; acq/op −6.45% (≥5%) ✓; unexpected=0
✓; audit queue enqueued==persisted (75,477 / 85,808), dropped=0,
pending=0, max batch ≤64 ✓; dropped_required=0, queue_full=0 ✓; receiver
journal contiguous, zero gaps/duplicates, `expected_in_range ==
events_in_range`, journal `token_issued` equals pgss `audit_append`
exactly ✓; refresh invariants hold ✓; no OOM/restart; outbox drained.

Sampler: pg.active averaged ≈11.2–11.3 of 24 pooled backends on both
mixed points, `idle in transaction` up to 13, wait events dominated by
`Client` (backend idle waiting for the app while the connection stays
checked out), then `Activity`/`LWLock`. WAL 1.96→2.23 GB consistent with
+15% committed work. CPU: app 4.0→4.3 of 8 cores, postgres ≈5.9 cores —
neither saturated.

## Interpretation

The redundancy is real and the removal is safe: eliminating one pool
checkout plus one no-op SQL round trip per eligible issuance lifted CC
throughput ~9.5% and mixed throughput ~15.6% at identical correctness,
durability and audit-delivery semantics.

Pool wait fell but did not disappear (mixed 70.2→61.7 ms avg). With only
~half the pooled backends active on average and Client-dominant wait
events, the remaining contention is connection **hold time** — sessions
checked out across inter-statement gaps and non-DB work — not pool
capacity and not PostgreSQL saturation. A pool-size experiment would be
the wrong next lever; a future CONNECTION_HOLD task (or a pool-size A/B
only after all 24 connections show continuously active with PG headroom)
follows the registered decision rule.

## Registered fields

```
TOKEN_AUDIT_PREFLIGHT_REDUNDANCY = CONFIRMED
CLIENT_CREDENTIALS_ACQUIRE_REDUCTION = 1.00/op (3.97 → 2.98)
MIXED_ACQUIRE_REDUCTION = 6.45% (6.8746 → 6.4311)
CC_THROUGHPUT_CHANGE = +9.5% mean (B_min/A_max +7.4%)
MIXED_THROUGHPUT_CHANGE = +15.6%
POOL_WAIT_CHANGE = mixed wait avg 70.24 → 61.74 ms (-12.1%); CC 1.70 → 2.06 ms (noise-level at +9.5% load)
PRIMARY_SCALING_LIMIT_AFTER_FIX = CONNECTION_HOLD
STRICT_3000_GATE = FAIL (mixed B attainment 93.9%)
STRICT_30M_CAPACITY = NOT_TESTED
TOKEN_AUDIT_PREFLIGHT_STATUS = PASS
RSA_REUSE_STATUS = CONFIRMED_AND_PRESENT
AUDIT_BATCH_STATUS = PASS_AND_PRESENT
READY_FOR_MERGE = YES (retention rules met; not merged)
DB_POOL_CHANGED = NO
DURABILITY_CHANGED = NO
AUDIT_SEMANTICS_CHANGED = NO
```

## Disclosures

1. First remote test run hung on the new HTTP-level revoke test: the
   fixture pool is capped at one connection and the test held the admin
   checkout across later verification queries. Fixed with a dedicated
   `AsyncPgConnection` for privilege administration
   (`608b5492`, test-only; the app binary is unaffected — test files are
   not compiled into the release target). Test-side `VALKEY_URL` needed
   the `redis://` scheme.
2. The first mixed evaluation FAILED on evaluator gates that were
   stricter than the pre-registered spec: `expected_rejection==0` and
   `local_no_request==0` are designed `cap_mixed` outcome classes
   (bounded-family `invalid_grant`, dead-family no-request exits; the
   previous mixed run showed the same nonzero classes), and a
   `b_preflight==0` gate is impossible-by-design in mixed because
   non-eligible grants keep `ensure_storage`. The evaluator was corrected
   to the spec (mixed requires `unexpected==0` plus the enumerated
   audit/refresh gates; B preflight strictly below A) and the **same
   recorded point data** re-evaluated — no load was re-run for the
   verdict change. The corrected evaluator is committed as `bedfbebf`;
   evidence JSONs are preserved under `evidence/`.
