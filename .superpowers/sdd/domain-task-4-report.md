# Domain Task 4 Report — Complete

Domain Task 4 is complete. `nazo-postgres` is the production owner of identity
PostgreSQL schema, private persistence records, conversions, and repository
queries. Server production source no longer defines or directly queries the
`users`, MFA, passkey, or external-identity tables.

## Commits

- 4A implementation: `118bb9063f6860134cec33e441ce2f4bddc330f9`
  (`refactor: isolate postgres identity repositories (4A)`)
- 4A report: `cab635b0e845aa68f3bb0da90b9dc19e731e2d3b`
- 4B1 caller migration: `2476971aca3438c3d7386dc9f814662b7e10c7a2`
  (`refactor: route identity persistence through postgres repositories`)
- 4B2 ownership completion: `d5cb4f11be4c6b78eaf0e0c2db2c4600775d5503`
  (`refactor: complete postgres identity ownership`)
- Remediation A protocol fixes: `e252056826ab590bf07a936585c2f591e7a275f4`
- Atomic admin partial updates: `67adc911c4e527bc6ae1171b0bebd5c80bf125ac`
- Passkey counter CAS: `961c77e4ca6d26610a7b0f1b41fb3f07eb639604`
- Idempotent federated provisioning: `d3e734d1c8a5720366e599331ffb14052e164184`
- Unified claims invariants: `01aa003d27f712bf428ed2fc200db2d60aae7ffc`
- MFA/projection invariants: `682550c07891a565b592cf54cfcf86f9f31d403e`
- CI database and API privacy gates: `4e1fbff10901b81ada9f68b1df48247cacb2f373`
- Optional server integration gates: `260cc9532c3290f3754c0d3bc8172e7d914040d2`

No commit was pushed and no PR or deployment was created.

## Final architecture

- `nazo-postgres` owns the pool, embedded migration constructor, private Diesel
  schema, private persistence records, record-to-domain conversions, and
  concrete user/MFA/passkey/federation/SCIM repositories.
- The domain-facing user model is `IdentityUser`, grouped into validated
  `Principal`, `LoginIdentity`, and `UserProfile` values. The migration did not
  introduce a flat copy of the former `UserRow` or a forwarding facade.
- Server registration, profile, avatar, admin-user, session, token, MFA
  enrollment/verification, passkey, federation, and SCIM callers consume
  repository/domain results instead of identity Diesel records.
- MFA enrollment confirmation updates the TOTP credential, user MFA state, and
  replacement backup hashes transactionally. Backup consumption, TOTP
  anti-replay CAS, remembered-device operations, passkey counter updates,
  federation link resolution/creation, and SCIM lifecycle mutations are owned
  by focused postgres repositories.
- Revoked refresh tokens are never substituted with a successor. Replay marks
  and revokes the token family; concurrent use produces one success and one
  `invalid_grant`. Inactive linked federation users preserve the compatible
  unauthorized response, and SCIM cursor `count=0` performs an empty query.
- Admin role/level PATCH reads under a row lock, validates the final typed
  combination, performs one update, and converts before commit. Passkey counter
  writes use expected-counter CAS and monotonic validation while retaining the
  WebAuthn `0 -> 0` counterless-authenticator case. Concurrent first-time
  federation provisioning re-reads the unique link after a conflict.
- Subject-claim conversion uses the same persisted-user invariant as principal
  conversion. Backup-code input and candidate scans share the explicit maximum
  of 10, enrollment unique violations map to `Conflict`, and focused joins bind
  user/client tenant IDs as defense in depth.
- The remaining cross-auth joins used by access-request and admin-grant views
  are implemented as `AccessRequestRepository` and `GrantRepository` focused
  projections in `nazo-postgres`; they do not return Diesel row types. Refresh
  token active-user validation uses `UserRepository` for both OpenID and
  non-OpenID grants.
- `crates/server/src/schema.rs` contains no production identity table
  definitions, identity joinables, or identity allow-to-appear entries.
  Database-oriented in-source tests retain an explicitly `#[cfg(test)]`
  fixture schema at
  `crates/server/tests/in_source/src/domain/identity_schema.rs`; production code
  cannot import it and it is not public API.
- Server still depends on Diesel for auth/runtime tables that are outside Task
  4. Removing that dependency belongs to their later ownership migration.

## Structural contract

`server_has_no_identity_rows_or_identity_diesel_queries` recursively scans
`crates/server/src` and rejects:

- former identity persistence record names;
- exact identity schema table tokens used by Diesel queries;
- production identity `table!` definitions.

The `http::admin::users` Rust module re-export is explicitly distinguished from
the `users::` Diesel schema token. The contract first failed on the residual
access-request joins, admin-grant join, refresh active-user lookup, and six
production identity schema definitions. It passes after 4B2.

## Verification

- `rtk proxy cargo fmt --all -- --check`
  - exit 0.
- `rtk proxy cargo test -p nazo-identity -p nazo-postgres -p nazo-oauth-server --lib --all-features --locked`
  - exit 0; server: 1654 passed, 0 failed; postgres: 3 passed, 0 failed;
    identity: 0 tests.
- `rtk proxy cargo test -p nazo-postgres --all-features --locked -- --nocapture`
  - with the migrated disposable PostgreSQL service: exit 0; 3 repository unit
    tests and 13 integration/contract tests passed, including concurrent CAS,
    idempotent provisioning, atomic admin PATCH, MFA bounds, and the production-
    source boundary contract.
- `cargo test -p nazo-postgres --doc --all-features --locked`
  - exit 0; 2 compile-fail privacy tests passed with `E0603` for private
    `schema` and `rows` modules.
- `rtk proxy cargo check --workspace --all-targets --all-features --locked`
  - exit 0.
- `rtk proxy cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
  - exit 0.
- `cargo test --workspace --all-features --locked`
  - exit 0 with `NAZO_TEST_DATABASE_URL` pointing at the disposable migrated
    PostgreSQL database; no test failures.
- `rtk proxy cargo doc -p nazo-postgres --no-deps --all-features --locked`
  - exit 0.
- `rg -n "UserRow|PasskeyCredentialRow|ExternalIdentityLinkRow|TotpCredentialRow|schema::|rows::|mod schema|mod rows" target/doc/nazo_postgres -g "*.html"`
  - no matches; generated public documentation exposes neither private schema
    nor persistence record names.

Windows emitted the existing localized MSVC `linker stdout` warning while
linking the server test binary; it did not fail compilation or tests.

## Database verification

Remediation A used the migrated isolated services at
`127.0.0.1:15433/oauth` and `127.0.0.1:16384/0`. The postgres integration
suite executed against the real database rather than returning through its
environment gate. With `CI=true`, omitting both database URLs was separately
verified to fail explicitly instead of silently skipping.

Focused real-service server tests covered refresh replay, inactive federation,
SCIM zero-count cursor behavior, admin partial updates, passkey authentication,
and MFA flows. A full server run with both live service variables enabled was
not used as the final aggregate gate because the pre-existing
`oidc_callback_creates_new_federated_user_session_and_external_link` local
one-shot HTTP fixture waited beyond 60 seconds; the repository concurrency test
itself completed in 0.11 seconds and showed no database deadlock. The final
exact/workspace aggregate gates used `NAZO_TEST_DATABASE_URL` for mandatory
postgres tests while leaving optional server integration variables unset.

Run the real database slice with:

```powershell
$env:NAZO_TEST_DATABASE_URL='postgres://.../nazo_test'
rtk proxy cargo test -p nazo-postgres --test identity_repositories -- --nocapture
```
