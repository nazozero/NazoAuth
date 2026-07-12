# Domain Task 5 Report — PostgreSQL Auth and Runtime Ownership

## Status

Domain Task 5 is complete. `nazo-postgres` owns the runtime-module desired,
instance, and audit tables; revision-bound desired/instance CAS; OAuth grant,
refresh-token, access-revocation, authorization-code compensation, SCIM-token
audit, and backchannel-logout outbox persistence. Migrated server handlers and
domain files no longer contain Diesel queries or persistence rows.

The already-completed OAuth-client/DCR/admin/profile/logout/introspection/
revocation/seed client work was reused rather than reimplemented. The later
refresh lost-response security fix at `4b58d1a` was preserved: unbound bearer
refresh tokens cannot use lost-response recovery, and the family advisory lock
and compromise transaction now exist only in `nazo-postgres`.

## Commits

- `1eac572` — `feat: add runtime module state migration`
- `6d4adfb` — `feat: persist runtime module state with CAS`
- `a2d76c1` — `refactor: route grants through postgres repository`
- `2a9e472` — `refactor: isolate postgres token repositories`
- `04be902` — `refactor: isolate postgres authorization and audit repositories`
- `9c19219` — `test: lock postgres auth ownership boundary`
- `0000078` — `refactor: remove auth repository forwarding helper`

No commit was pushed, and no deployment, PR, frontend, or refresh protocol
change was made by this task.

## Migration and runtime state

Migration `20260712000100_runtime_module_state` creates only:

- `runtime_module_desired_states`;
- `runtime_module_instance_states`;
- `runtime_module_state_events`.

It has database constraints for the three desired modes, five actual states,
thirteen closed module identifiers, seven closed audit event types, bounded
reason/error/outcome values, non-negative or positive revisions as applicable,
actor foreign keys, `(instance_id, module_id)` uniqueness, and operational time
indexes. Its down migration drops only the new indexes and tables. No historical
migration was edited. The migration checksum contract changed by exactly two
appended records, for the new `up.sql` and `down.sql`.

`RuntimeModuleRepository` implements `ModuleStateRepository` directly. Desired
CAS obtains a transaction-scoped key lock, row-locks existing state, verifies
the expected revision, advances by exactly one, and appends
`DesiredStateChanged` in the same transaction. Same-mode requests retain the
revision and append an identical before/after event with outcome `noop`. A stale
request returns `CasOutcome::Stale` without state or event mutation.

Instance CAS serializes the absent-row case, row-locks existing state, and uses
`WHERE transition_revision = expected` for conditional completion. A revision-7
completion cannot overwrite a revision-8 transition. Persistence rows remain
crate-private; callers receive runtime-domain records.

## Auth repositories and callers

- `GrantRepository` owns paging, authorization projection, upsert, authorized
  application counts, and the transaction that revokes active refresh tokens
  and deletes a user/client grant.
- `TokenRepository` returns `nazo-auth::RefreshToken`, never a Diesel row or
  stored verifier. It hashes raw refresh tokens inside the adapter and owns
  lookup, issuance, rotation, lost-response inspection, family compromise,
  active-family checks, refresh revocation, and access-JTI revocation checks.
- Refresh rotation and reuse retain the stable PostgreSQL family advisory lock.
  The lost-response path retains the fixed request-start timestamp, exact
  successor/sender/tenant/client checks, inclusive 60-second bound, and the
  unbound-token rejection introduced by `4b58d1a`.
- `AuthorizationRepository` commits authorization-code replay compensation in
  one PostgreSQL transaction: access-JTI revocation plus active refresh-family
  revocation.
- `AuditRepository` owns SCIM credential reads, atomic token-use timestamp plus
  audit insertion, and backchannel logout enqueue/claim/complete/fail updates.
  Network delivery remains outside the database transaction and preserves the
  existing retry/terminal-failure policy.
- `nazo_oauth_migrate` calls the postgres migration and cleanup APIs rather than
  embedding Diesel. Server production `schema.rs` now contains only the
  `#[cfg(test)]` fixture include.

The final ownership contract covers admin grants, prompt-none, authorization
decision, device approval, FAPI, introspection, revoke, userinfo, token
exchange, native SSO, refresh issue/rotation, authorization-code compensation,
SCIM auth, OIDC backchannel logout, profile counts, and support code. It rejects
Diesel and auth table paths in those production callers. The obsolete
`support::upsert_grant` forwarding helper was deleted after the pre-existing
OAuth-client facade contract correctly detected it.

The OIDF seed binary retains its previously reviewed direct user bootstrap SQL.
Its OAuth-client persistence already uses the focused repository and was
explicitly outside the remaining Task 5 inventory; it was not reworked.

## TDD evidence

- Migration RED ran against real PostgreSQL and found none of the three runtime
  tables. GREEN applied the new migration and found all three.
- Runtime repository RED failed because `RuntimeModuleRepository` did not
  exist. GREEN covers desired insert/stale/no-op audit, stale instance
  completion, and every closed event kind against PostgreSQL.
- Grants RED failed on missing `upsert`, `authorization`, and `revoke` methods.
  GREEN proves two upserts increment the authorization count and one revoke
  atomically removes the grant and revokes its refresh token.
- Tokens RED failed on missing auth token values and `TokenRepository`. GREEN
  proves issue, rotate, reuse classification, and whole-family compromise.
- Authorization/audit RED failed on missing `AuthorizationRepository` and
  `AuditRepository`. GREEN proves dual-token compensation, SCIM use audit, and
  backchannel outbox claim/completion.
- The full PostgreSQL suite first exposed the residual grant forwarding helper;
  direct caller migration made the unchanged facade contract GREEN.

## Verification

- Fresh disposable PostgreSQL database migration: exit 0; runtime tables 1/1.
- Migration compatibility suite: 3/3, including isolated baseline upgrade,
  closed state/event constraints, and new-migration down/up while preserving the
  baseline `users` table.
- `rtk python scripts/verify_static_contracts.py --append-migration
  20260712000100_runtime_module_state`: exit 0 at migration creation.
- `rtk python scripts/verify_static_contracts.py --check`: exit 0 after final
  implementation.
- Real PostgreSQL `nazo-postgres` suite: 52/52 across eight suites.
- Real PostgreSQL refresh suite: 39/39, including unbound fail-closed, mTLS
  lost-response recovery, fixed-window boundaries, concurrent rotation/reuse,
  and rollback injection cases.
- Focused server suites: introspection 24/24, revoke 15/15, userinfo 34/34,
  token exchange 5/5, native SSO 6/6, FAPI 40/40, authorization code 41/41,
  authorization compensation 7/7, SCIM auth 39/39, OIDC logout 38/38,
  authorization decision 18/18, and device authorization 8/8.
- `rtk cargo check --workspace --all-targets --all-features --locked`: exit 0.
- `rtk cargo clippy --workspace --all-targets --all-features --locked --
  -D warnings`: exit 0, no issues.
- `rtk cargo test --workspace --all-features --locked`: exit 0; 2,091 passed
  across 40 suites.
- `rtk cargo doc --workspace --no-deps --all-features --locked`: exit 0.
- `rtk cargo fmt --all -- --check`, `rtk git diff --check`, and the final static
  contract check: exit 0.

## Concerns

No known functional or migration concern remains in Task 5 scope. The local
instrumented refresh build artifact created by the preceding security work was
verified to resolve inside this worktree and removed before implementation; no
build output is tracked.
