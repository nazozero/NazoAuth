# Issuance maintenance acceptance evidence

`single_instance_scaling.py` phase 3 now requires explicit issuance-maintenance
acceptance evidence. The old refresh-family/spent-proof checks do not establish
that `oauth_token_issuances` is being reclaimed fast enough. Historical reports
retain their original verdict and measurement contract.

## Declare the test contract before running

Add these fields to the existing `SIS_POINT` JSON for the phase-3 candidate:

| Field | Meaning |
| --- | --- |
| `issuance_retention_seconds` | Maximum issuance-row retention horizon for the actual tested flows, including access-token clock skew and any longer single-use grant deadline. Confirm this from the test configuration and flow mix. |
| `issuance_max_expired_age_seconds` | Predeclared maximum allowed age of an expired row during the mature observation window. This is a test acceptance objective, not a cleanup scheduling guarantee. |

For example, **only when the tested configuration has a confirmed 360-second
maximum issuance retention**, a point may declare:

```json
{
  "issuance_retention_seconds": 360,
  "issuance_max_expired_age_seconds": 120
}
```

The example 120-second age objective allows two normal maintenance intervals.
It is not silently supplied by the harness. Neither field has a default. A run
without either field is `INVALID` for this gate. Do not derive retention solely
from an access-token TTL if the point also includes longer grant deadlines.

## Sampling and mature window

The existing `soak_sampler.py` records an indexed `ORDER BY retain_until LIMIT 1`
probe with a database clock from the same statement on each tick. No due row is
recorded as JSON `null`, which is different from a missing field. Exact due-row
counts run no more often than once per 60 seconds; their separate database
sample time and query duration are recorded. Existing `rel_bytes` cumulative
insertion/deletion counters supply the rate diagnostics.

The single-instance sampler normally ticks every 2 seconds. The collector also
records that interval in the point evidence. Acceptance requires sample gaps
and boundary gaps no larger than twice the configured sampler interval
(normally 4 seconds). Missing samples, database-clock regression, a due time
later than its sample clock, an observed database/host clock difference larger
than that coverage budget, query failure, or a detected issuance statistics
counter reset makes the evidence `INVALID`.

The mature window starts at **measurement start + declared retention horizon**,
conservatively excluding startup/warmup maturation. At least 180 seconds (three
normal 60-second maintenance intervals) must remain in the measurement window.
A shorter window is `INVALID`; it must not pass merely because nothing has yet
expired. Every sampled expiry age in that mature window must be within the
declared objective. A valid observation containing an age above the objective
is `FAIL`; a complete valid observation within it is `PASS`.

## Interpretation

- Due count, its slope, oldest-age slope and same-span insertion/deletion rates
  are reported. A nonzero or rising endpoint count alone does not fail the gate:
  periodic cleanup naturally produces a sawtooth queue and endpoint phases vary.
- Pre/post ledgers report total issuance rows, expired rows, oldest due time and
  age. Their ledger-start timestamp precedes the backlog statement, so that age
  is a diagnostic lower bound. The gate uses the sampler's same-statement clock.
- `PASS` establishes the **sampled issuance expiry-age objective in this run**.
  It does not establish an infinite steady state or prove retention of other
  categories. In particular, a fresh 30-minute test does not cross the one-hour
  refresh-contract grace.
- Phase 3 cannot retain a candidate with missing/invalid issuance evidence or a
  failed age objective. Prepare failures are also source-sensitive: local or
  unclassified preparation failures are `INVALID`; service preparation failures
  are `FAIL`. No failure is converted into successful throughput.

Pure regression coverage is in `perf/tests/test_issuance_maintenance.py` and
`perf/tests/test_single_instance_scaling.py`. Database integration and a fresh
same-environment load comparison remain required to claim a performance gain.
