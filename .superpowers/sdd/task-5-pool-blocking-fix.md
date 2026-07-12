# Task 5 pool blocking fix

`run_pending_migrations` and `cleanup_expired_security_state` retain their
public async APIs and synchronous Diesel behavior, but now copy the database
URL before moving the complete synchronous connection and operation into
`tokio::task::spawn_blocking`. The outer future uses `.await??` so task join
failures and database-operation failures are both propagated without wrapping
one as the other. No shared abstraction was introduced.

## TDD and verification

- RED: `pool_async_contract` failed because the migration function did not own
  its URL before spawning and contained no blocking-worker boundary.
- GREEN: both structural and invalid-URL error-preservation tests pass (2/2).
- `cargo test -p nazo-postgres --lib --all-features --locked` passed (5/5).
- Workspace fmt, diff-check, all-target/all-feature check, and strict Clippy
  with `-D warnings` all exited successfully.
