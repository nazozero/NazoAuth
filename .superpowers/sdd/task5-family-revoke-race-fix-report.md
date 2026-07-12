# Task 5 Family Revocation Race Fix

## Scope and root cause

`GrantRepository::revoke` and
`AuthorizationRepository::revoke_issued_tokens` revoked a refresh family without
the transaction-scoped advisory lock used by `TokenRepository` rotation and
family compromise. Under PostgreSQL `READ COMMITTED`, a revoke `UPDATE` could
take its statement snapshot, block on the original token row while rotation
inserted a successor, and then resume without seeing that newly committed row.
Both operations could therefore return successfully while leaving the
successor active.

The fix exposes the existing lock only within the postgres repository module
and reuses it directly. Authorization-code replay compensation locks its known
family before either compensation write. Grant revocation loads the affected
family identifiers in UUID order and locks every family before revoking active
tokens and deleting the grant. The advisory-lock key derivation remains defined
in one function and is unchanged from refresh rotation/compromise.

## TDD evidence

Two real PostgreSQL tests install a family-specific insert gate, run an actual
`TokenRepository` rotation until it has revoked the original token and is
blocked before inserting its successor, and then start the relevant revoke
operation. `pg_stat_activity` plus unique connection application names provide
a deterministic barrier rather than timing sleeps.

Before the production change, both tests failed at the final family assertion:

- `grant_revoke_waits_for_concurrent_refresh_rotation_before_revoking_family`;
- `authorization_replay_waits_for_concurrent_refresh_rotation_before_compensation`.

In each RED run, the revoke returned but `family_active` reported the successor
still active. After the shared family lock was applied, both tests passed. The
tests also assert grant deletion and access-token revocation respectively, so
the surrounding transaction behavior remains covered.

## Verification

- Real PostgreSQL `auth_repositories`: 8/8 passed, including both concurrency
  regressions and the existing atomic grant/dual-token compensation tests.
- Focused concurrency filter: 2/2 passed.
- Real PostgreSQL full `nazo-postgres` suite: 58/58 passed across unit,
  integration, migration, concurrency, contract, and documentation suites.
- `cargo check -p nazo-postgres --all-targets --all-features --locked`: passed.
- `cargo clippy -p nazo-postgres --all-targets --all-features --locked -- -D
  warnings`: passed.
- Server refresh-related unit tests with real PostgreSQL and Valkey: 66/66
  passed.
- Focused source formatting and diff checks: passed.
