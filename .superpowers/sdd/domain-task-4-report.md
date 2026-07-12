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
  - exit 0; server: 1655 passed, 0 failed; postgres: 1 passed, 0 failed;
    identity: 0 tests.
- `rtk proxy cargo test -p nazo-postgres --all-features --locked -- --nocapture`
  - exit 0; 1 repository unit test and 9 integration/contract tests passed,
    including the server production-source boundary contract.
- `rtk proxy cargo check --workspace --all-targets --all-features --locked`
  - exit 0.
- `rtk proxy cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
  - exit 0.
- `rtk proxy cargo doc -p nazo-postgres --no-deps --all-features --locked`
  - exit 0.
- `rg -n "UserRow|PasskeyCredentialRow|ExternalIdentityLinkRow|TotpCredentialRow|schema::|rows::|mod schema|mod rows" target/doc/nazo_postgres -g "*.html"`
  - no matches; generated public documentation exposes neither private schema
    nor persistence record names.

Windows emitted the existing localized MSVC `linker stdout` warning while
linking the server test binary; it did not fail compilation or tests.

## Database verification limitation

At final verification, `NAZO_TEST_DATABASE_URL` and `DATABASE_URL` were unset,
and no local `postgresql*` service existed. The five environment-gated
PostgreSQL behavior tests compiled and returned through their explicit gate;
they did **not** execute tenant isolation, concurrent TOTP CAS, backup-code
single consumption, uniqueness constraints, or SCIM transactions against a
live PostgreSQL service. This report does not claim live-database coverage.

Run that slice against a migrated disposable database with:

```powershell
$env:NAZO_TEST_DATABASE_URL='postgres://.../nazo_test'
rtk proxy cargo test -p nazo-postgres --test identity_repositories -- --nocapture
```
