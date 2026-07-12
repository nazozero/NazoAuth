# Domain Task 5 runtime audit and logout outbox fix

## Root causes

- Actual-state compare-and-set and transition audit append were separate repository calls, so an audit insert failure could leave durable state without its matching event, and a stale completion caller could append a misleading completion event.
- Backchannel logout completion/failure identified a delivery only by `id`; after an expired claim was reclaimed, the old worker could clear or overwrite the newer worker's claim or terminal state.

## Changes

- Added `InstanceStateMutation`, binding the CAS change to mutually exclusive applied/stale audit records.
- Removed the independently callable runtime `append_event` port. PostgreSQL now validates event/state identity and commits the conditional state write plus matching event in one transaction. A stale revision appends only `StaleTransitionDiscarded`; event insertion failure rolls the state write back.
- Bound logout outbox completion/failure to the claimed `attempts` generation and required `locked_at IS NOT NULL`, `delivered_at IS NULL`, and `failed_at IS NULL`. Zero updated rows return typed `RepositoryError::Consistency`.
- Propagated the claim generation through the logout delivery worker without schema or migration changes.

## Verification

- RED observed: focused PostgreSQL tests failed to compile because the atomic mutation type and expected-attempt APIs did not exist.
- `cargo test -p nazo-runtime-modules --test state_machine --locked`: 18 passed.
- Real PostgreSQL `cargo test -p nazo-postgres --test runtime_modules --locked`: 4 passed, including duplicate-event rollback and stale-completion audit assertions.
- Real PostgreSQL focused logout outbox tests: 2 passed, including expiry/reclaim barrier where attempt 1 cannot complete or fail attempt 2.
- Combined real PostgreSQL repository suite after sibling integration: 58 passed (reported by the family-lock fixer).
- `cargo check -p nazo-runtime-modules -p nazo-postgres -p nazo-oauth-server --all-targets --all-features --locked`: passed.
- `cargo clippy -p nazo-runtime-modules -p nazo-postgres -p nazo-oauth-server --all-targets --all-features --locked -- -D warnings`: passed.
- `cargo fmt --all -- --check`: passed.

## Commits

- `5cf79bd` `fix: atomically audit runtime transitions`
- `cbeb572` `fix: reject stale logout outbox workers`
- `5dbbdee` `style: format logout outbox race test`
- `9faac80` `style: normalize outbox test spacing`
