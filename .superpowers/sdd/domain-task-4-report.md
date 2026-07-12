# Domain Task 4 Report — 4A Intermediate Commit

This report covers only the accepted 4A atomic cut: private PostgreSQL adapter
boundary, pool ownership, and security-critical MFA transactions. Domain Task 4
is **not complete**. The remaining caller migration is explicitly assigned to
4B.

## Implementation commit

- `118bb9063f6860134cec33e441ce2f4bddc330f9`
- `refactor: isolate postgres identity repositories (4A)`
- Starting HEAD for this cut: `9ad77d1` (architecture baseline remains
  `2107535`).

## Changes

- Added the `nazo-postgres` workspace crate. It owns the PostgreSQL pool,
  embedded migration constructor, identity schema subset, private identity row
  types, explicit row conversions, and concrete user/MFA/passkey/federation/
  SCIM repositories.
- Kept `rows` and `schema` crate-private. The public API contains pool/migration
  functions and concrete repositories only; generated public docs contain no
  row or schema names.
- Added explicit `TryFrom<UserRow> for Principal` and a distinct
  `SubjectClaims` projection. Invalid persisted role/admin-level combinations
  and invalid identity IDs become consistency errors rather than coercions.
- Added only the identity repository ports needed by this cut: principal/claim
  projection and MFA load/CAS/consume/replace/clear operations. Added a minimal
  `FakeUserRepository` test substitute; no forwarding service or manager was
  introduced.
- Deleted `crates/server/src/db.rs`. Server production and test callers now use
  `nazo_postgres` pool APIs directly.
- Migrated server MFA verification from direct Diesel to `MfaRepository`:
  TOTP last-step acceptance is one conditional update; backup-code consumption
  uses `used_at IS NULL`; backup-code replacement and full MFA-state clearing
  use one Diesel connection transaction.
- Added repository APIs and contract/integration test cases for tenant-scoped
  user lookup, TOTP concurrent CAS, backup-code single consumption, passkey and
  federation uniqueness, SCIM replacement transaction, and public API row
  leakage.
- Existing migrations were not modified.

## TDD red/green evidence

RED:

- `rtk proxy cargo test -p nazo-postgres`
  - exit 1: package `nazo-postgres` did not exist.
- After adding the package manifest and desired API test:
  `rtk proxy cargo test -p nazo-postgres --test identity_repositories`
  - exit 1: unresolved crate/API because `src/lib.rs` did not exist.
- `rtk proxy cargo test -p nazo-identity --test repository_ports`
  - exit 1: `FakeUserRepository` did not exist.

GREEN:

- `rtk proxy cargo test -p nazo-identity --test repository_ports`
  - exit 0, 1 passed.
- `rtk proxy cargo test -p nazo-postgres -p nazo-identity`
  - exit 0; identity tests and 8 postgres tests passed.
- `rtk proxy cargo test -p nazo-oauth-server mfa --lib`
  - exit 0; 40 passed, 0 failed, 1616 filtered.

## Final verification

- `rtk proxy cargo fmt --all -- --check`
  - exit 0.
- `rtk proxy cargo check --workspace --all-targets --all-features --locked`
  - exit 0.
- `rtk proxy cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
  - first run found `too_many_arguments` in federation insertion and then a
    `collapsible_if` in the migrated MFA path; both were corrected.
  - fresh final run exit 0.
- `rtk proxy cargo test --workspace --all-features --locked`
  - fresh final run exit 0; no test failures. The existing Windows MSVC linker
    emitted localized `linker_messages` warnings during linked test binaries.
- `rtk proxy cargo doc -p nazo-postgres --no-deps`
  - exit 0; generated `target/doc/nazo_postgres/index.html`.
- `rtk rg -n 'UserRow|PasskeyCredentialRow|ExternalIdentityLinkRow|mod schema|mod rows' target/doc/nazo_postgres -g '*.html'`
  - exit 1 because there were no matches (the expected API-leak result).
- `rtk rg -n 'actix|fred' crates/postgres -g '*.rs' -g 'Cargo.toml'`
  - exit 1 because there were no matches.

## Database verification limitation

At verification time both `NAZO_TEST_DATABASE_URL` and `DATABASE_URL` were
unset, and `Get-Service -Name postgresql*` found no local PostgreSQL service.
Therefore the five tests that require a database returned at their explicit
environment gate. Their code compiled, but tenant isolation, concurrent CAS,
single-use consumption, uniqueness constraints, and SCIM transaction behavior
were **not executed against PostgreSQL** in this environment.

Run the real database slice with a migrated disposable test database:

```text
$env:NAZO_TEST_DATABASE_URL='postgres://.../nazo_test'
rtk proxy cargo test -p nazo-postgres --test identity_repositories -- --nocapture
```

## Remaining 4B scope / risks

- Server still owns the transitional schema definitions needed by Task 5 auth/
  runtime Diesel callers. It does not re-export `nazo-postgres` rows or schema.
- MFA enrollment/confirmation, remembered-device operations, passkey handlers,
  federation handlers, SCIM handlers, access-request identity effects, and the
  remaining `UserRow` consumers still require direct caller migration.
- Until 4B removes those uses, `nazo-postgres` is not yet the exclusive owner of
  all identity queries/rows and Domain Task 4 acceptance must not be claimed.
- The passkey/federation/SCIM adapters added here are compiled and API-tested,
  but are not production callers yet. 4B must migrate callers and add behavior-
  preserving response tests rather than introducing a full-user persistence DTO.
