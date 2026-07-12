# Domain Task 4 Report — Remediation B Completion

Domain Task 4 is **complete for its identity and access-request scope**.
`nazo-postgres` owns identity/access-request PostgreSQL schema, private
persistence records, conversions, repositories, and the atomic access-request
approval transaction. Server production source no longer defines or directly
queries identity or `client_access_requests` persistence. The auth-owned admin
grant repository remains explicitly bound to Task 5; access requests no longer
depend on `GrantProjection` or `GrantPage`.

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
- Inactive social session rejection and provider constraint: `fe1a142`
- Atomic refresh-family serialization: `2511f56`
- Admin empty-PATCH timestamp preservation: `01dab58`
- Non-conflicting social migration name: `79749e4`
- Social migration up/down compatibility contract: `b592fdd`
- PostgreSQL integration CI gates: `44d19ec`
- Deterministic no-email social callback completion test: `41eac28`
- Isolated refresh-family fixtures: `1a68e15`
- Remediation B password verifier boundary: `6faff27`
- Remediation B focused identity projections: `1225ca0`
- Remediation B access-request ownership: `db19755`
- Strict lint follow-up: `51e1a1d`

No commit was pushed and no PR or deployment was created.

## Final architecture

- `nazo-postgres` owns the pool, embedded migration constructor, private Diesel
  schema, private persistence records, record-to-domain conversions, and
  concrete user/MFA/passkey/federation/SCIM repositories.
- The catch-all `IdentityUser` API is deleted. Password authentication loads
  `AuthenticationIdentity`, composed from `Principal`, `LoginIdentity`,
  `AccountIdentity`, and `PasswordHash`. Session/profile/admin/SCIM callers load
  the password-free `PublicAccount`; OIDC userinfo and ID-token paths load
  `Principal` plus `SubjectClaims` directly. Focused Diesel selections prevent
  public-account and claims reads from retrieving `password_hash`.
- `PasswordHash` owns a private string, rejects blank persisted values, has a
  redacted custom `Debug`, implements neither `Serialize` nor `Deserialize`,
  and exposes verifier bytes only through `expose_for_verification()`. The
  exposure occurs inside the bounded blocking password verifier.
- Server registration, profile, avatar, admin-user, session, token, MFA
  enrollment/verification, passkey, federation, and SCIM callers consume
  repository/domain results instead of identity Diesel records.
- MFA enrollment confirmation updates the TOTP credential, user MFA state, and
  replacement backup hashes transactionally. Backup consumption, TOTP
  anti-replay CAS, remembered-device operations, passkey counter updates,
  federation link resolution/creation, and SCIM lifecycle mutations are owned
  by focused postgres repositories.
- Revoked refresh tokens are never substituted with a successor. Rotation and
  replay mutation acquire the same stable PostgreSQL advisory transaction lock
  for the token family. Replay marking and family revocation are one database
  transaction; concurrent use produces one HTTP 200 and one `invalid_grant`,
  after which the family has no active refresh token. The HTTP winner does not
  guarantee that its returned refresh token remains valid after family
  compromise. Inactive linked federation users, including social identities
  without email, receive the compatible `401 access_denied` response.
- Admin role/level PATCH reads under a row lock, validates the final typed
  combination, performs one update, and converts before commit. Passkey counter
  writes use expected-counter CAS and monotonic validation while retaining the
  WebAuthn `0 -> 0` counterless-authenticator case. Concurrent first-time
  federation provisioning re-reads the unique link after a conflict.
- An empty admin user PATCH is a baseline-compatible no-op: it returns the
  current representation without mutating `updated_at`.
- Migration `20260712000050_social_federation_provider_type` permits the
  production `oauth2_social` provider type while preserving existing OIDC/SAML
  rows. Its down migration fails while social links exist; operators must
  migrate or remove those links explicitly before rollback. Timestamp
  `20260712000100` remains available for the planned runtime desired-state
  migration.
- Subject-claim conversion uses the same persisted-user invariant as principal
  conversion. Backup-code input and candidate scans share the explicit maximum
  of 10, enrollment unique violations map to `Conflict`, and focused joins bind
  user/client tenant IDs as defense in depth.
- Access-request list/detail/create/cancel/reject/approve operations are
  tenant-scoped `AccessRequestRepository` methods returning identity-domain
  `AccessRequest` values, not adapter projections. Approval locks a pending
  request, creates the OAuth client, and performs the tenant/status/actor CAS in
  one PostgreSQL transaction. A losing concurrent approval rolls back its
  client insert. `server/src/support/access_requests.rs` and server access
  request row/status types are deleted.
- Valkey delivery retains the compatible fail-closed ordering: the one-time
  delivery record is written before the PostgreSQL approval transaction; a DB
  failure or CAS loss compensates by deleting that request-specific key. A
  delivery write failure does not call the repository and commits neither a
  client nor an approval. This is explicitly a compensated cross-system flow,
  not a distributed transaction.
- `GrantRepository`, `GrantProjection`, `GrantPage`, and admin grant revoke are
  auth-owned work deferred to Task 5. They are not used by access-request code.
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

Remediation B extends the contract to reject `client_access_requests::`,
`UserAccessRequestRow`, `PendingAccessRequestRow`, and
`AccessRequestProjection` in server production source. It also verifies that
both handlers contain no Diesel token, the forwarding support file is absent,
and fail-closed delivery precedes repository approval.

## Verification

- `rtk proxy cargo fmt --all -- --check`
  - exit 0.
- `rtk proxy cargo test -p nazo-identity -p nazo-postgres -p nazo-oauth-server --lib --all-features --locked`
  - exit 0; server: 1654 passed, 0 failed; postgres: 3 passed, 0 failed;
    identity: 0 tests.
- `rtk proxy cargo test -p nazo-postgres --all-features --locked -- --nocapture`
  - with the migrated PostgreSQL service: exit 0; 3 repository unit tests, 13
    identity integration/contract tests, 1 migration up/down test, and 2
    compile-fail privacy doctests passed.
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
- Public-item scan of `target/doc/nazo_postgres/all.html`
  - no private schema module or persistence record is listed. The crate index
    intentionally contains compile-fail examples naming private `schema` and
    `rows` paths; those examples prove the paths are inaccessible and are not
    API leaks.

Remediation B verification:

- Password-leak RED test first failed because derived `Debug` contained the
  complete Argon2 verifier; after encapsulation, identity/postgres focused tests
  passed and three identity compile-fail doctests proved the secret is not
  serializable/deserializable.
- `cargo test -p nazo-postgres --test access_requests --all-features --locked -- --nocapture`
  - exit 0 against `127.0.0.1:15433/oauth`; 3 tests passed, covering
    create/list/cancel, tenant and owner isolation, concurrent approve/reject
    CAS, and losing-client rollback.
- `cargo test -p nazo-oauth-server --lib access_requests::tests:: --all-features --locked -- --nocapture`
  - exit 0 with real PostgreSQL and Valkey; 29 tests passed, including rollback
    after client insert, duplicate transitions, and ACL-induced delivery write
    failure with the request left pending and no client committed.
- `cargo test -p nazo-identity -p nazo-postgres -p nazo-oauth-server --lib --all-features --locked`
  - exit 0 with mandatory PostgreSQL configured and optional server live-service
    variables unset; 1,660 tests passed.
- `cargo test --workspace --all-features --locked`
  - exit 0 with only `NAZO_TEST_DATABASE_URL` configured; 2,047 tests passed in
    37 suites.
- `cargo fmt --all -- --check`, workspace all-target/all-feature check, and
  strict workspace Clippy with `-D warnings` all exited 0.
- `cargo doc -p nazo-identity -p nazo-auth -p nazo-postgres --no-deps --all-features --locked`
  and identity doctests exited 0. Public postgres docs expose no access-request
  adapter projection or persistence record. The existing grant projections are
  recorded above as Task 5 scope.

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

The follow-up re-ran the no-email social completion regression and the three
refresh-family/admin exact tests against the real services. Each completed in
under 0.1 seconds. A broad `inactive_linked_user` filter was explicitly not
counted as passing: two unrelated one-shot HTTP fixtures ran concurrently and
waited indefinitely. The new no-email regression avoids that invalid signal by
testing the production callback-completion boundary with a resolved
`SocialIdentity`, a real PostgreSQL external link, a real Valkey client, and a
five-second deadline.

Run the real database slice with:

```powershell
$env:NAZO_TEST_DATABASE_URL='postgres://.../nazo_test'
rtk proxy cargo test -p nazo-postgres --test identity_repositories -- --nocapture
```

## Remediation B independent-review follow-up (2026-07-12)

All six Important and both Minor findings from
`domain-task-4-remediation-b-review.md` were remediated in production code and
regression tests. The follow-up also addressed the five Critical CodeQL
hard-coded-password annotations in the login tests and the SCIM formatting
notice. No Task 5 persistence migration, refresh/DPoP change, old migration
edit, push, deployment, or PR mutation was performed.

### Follow-up commits

- `856fac2` — separate authentication verifier reads from write-side password
  hash material; `PasswordHash` no longer has a public extraction API.
- `c464923` — generate unique per-test login passwords instead of hard-coded
  wrong-password fixtures flagged by CodeQL.
- `a1db5d3` — inline the SCIM boolean field format capture.
- `a08f864` — add true `PrincipalRow` and `SubjectClaimsRow` SQL projections,
  password-free mutation returning clauses, and a single active+claims query
  for ID-token and UserInfo boundaries.
- `1ce4ca0` — delete `server/support/repositories.rs`, call the focused user
  repository directly, and distinguish request-state CAS loss from OAuth
  client uniqueness conflicts (including a stable response classification).
- `4770af0` — enforce access-request user/tenant ownership on create and full
  tenant/realm/organization consistency for requester, actor, and inserted
  client during approval.
- `160a6ae` — replace auth core's 40+ field persistence-ready DTO with validated
  protocol metadata; plaintext remains server-private and PostgreSQL builds a
  crate-private `ClientInsertCommand` from metadata plus digests only.
- `4f1ed52` — implement staged/committed Valkey delivery, deterministic
  request-scoped recovery, PostgreSQL linkage validation before GETDEL, and
  one-time consumption. Staged or orphaned payloads are never claimable.
- `3ff89e6` — prove the double-failure case: Valkey SET succeeds, PostgreSQL
  rolls back, compensation DEL is denied, the staged key remains unclaimable,
  and the delivery endpoint returns 404 and removes it.

### TDD evidence

- Password verifier compile-fail RED: the new doctest failed because public
  `into_inner()` compiled; GREEN: identity doctests 4/4 pass.
- Login fixture RED: two generated password calls were equal; GREEN: UUID-based
  test passwords are unique and the five flagged login calls contain no
  hard-coded wrong password.
- Projection/snapshot RED: source contract found no `PrincipalRow` and two
  token-boundary reads; GREEN: narrow projection contract passes and a real
  disabled PostgreSQL account returns no issuable claims.
- Forwarder/conflict RED: `support/repositories.rs` existed and approval had no
  state-specific conflict; GREEN: the file is absent and repository/HTTP tests
  distinguish `AlreadyProcessed` from client uniqueness.
- Tenant RED: a valid second tenant plus a user owned by the default tenant
  reached the composite FK as an unexpected error; GREEN: repository precheck
  returns `NotFound`, and approval rejects mismatched actor/client contexts.
- DTO/plaintext RED: auth core exposed `PreparedClientRegistration` with
  plaintext and persistence digests; GREEN: boundary test proves those fields
  are absent from auth and issued plaintext is absent from PostgreSQL source.
- Delivery RED: staged/orphan payloads returned HTTP 200; GREEN: they return
  404, committed payloads require approved request/client linkage, recovery is
  idempotent, and replay returns 404 after one successful claim.

### Fresh verification results

- `rtk cargo fmt --all -- --check` — exit 0.
- `rtk cargo check --workspace --all-targets --all-features --locked` — exit 0.
- `rtk cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
  — exit 0, no issues.
- `rtk cargo test -p nazo-identity -p nazo-auth -p nazo-postgres -p nazo-oauth-server --lib --all-features --locked`
  — exit 0; 1,663 passed.
- `cargo test -p nazo-postgres --all-features --locked -- --nocapture` with the
  live container-derived PostgreSQL URL — exit 0: 4 unit, 6 access-request, 17
  identity repository, 1 migration, and 2 compile-fail doctests passed.
- Live PostgreSQL/Valkey focused server slices — 31 access-request tests and 3
  delivery tests passed. The approval recovery/one-time test returned one 200
  delivery then 404 on replay; the SET+PG rollback+DEL-denied test returned 404
  and removed the residual staged key.
- `rtk cargo test --workspace --all-features --locked` with mandatory live
  PostgreSQL and optional live server variables unset — exit 0 across the full
  workspace, including doctests.
- `rtk cargo doc -p nazo-identity -p nazo-auth -p nazo-postgres --no-deps --all-features --locked`
  — exit 0.

An intentional no-URL `nazo-postgres --all-features` probe failed explicitly
instead of skipping six live database tests; the immediately repeated gate
with the live container-derived URL passed completely. Windows emitted the
existing localized MSVC linker-stdout warning during server test linking; it
did not fail compilation or tests.

### Residual concerns

- The external CodeQL check-run was not locally re-executed; its five cited
  login locations were replaced with generated fixtures and the relevant
  source/test gates pass. CI must provide the final scanner readback.
- No known functional remediation concern remains within Domain Task 4. The
  separately owned DPoP lost-response failure and refresh implementation were
  intentionally untouched.

## Remediation B re-review completion (2026-07-13)

The three Important and one Minor findings in
`domain-task-4-remediation-b-rereview.md` were remediated without modifying the
refresh lost-response work, pushing, deploying, or changing PR state.

### Commits

- `bee6a60` — perform password candidate verification inside the identity
  domain; ordinary authentication callers receive only a boolean and cannot
  borrow or copy the encoded verifier.
- `7856d9a` — generate one live form-login password and reuse it for both the
  persisted fixture and encoded request.
- `985d380` — expose a still-live committed delivery capability only through
  the applicant's owner-scoped access-request response and prove production
  list-to-claim-to-replay behavior.
- `2638548` — replace server OAuth client query forwarding functions with the
  focused `OAuthClientRepository` and direct calls at each consumer.
- `62b649e` — satisfy the strict delivery-path Clippy gate.
- Sibling frontend, isolated worktree
  `D:\self\NazoAuthWeb-modular-workspace-architecture`, commit `0d69544` — show
  the applicant's one-time delivery action, correct the admin's false "sent"
  message and delivery page's false email instruction, and add an executable
  delivery-route test.

### TDD evidence

- Password RED failed with `E0599` because `PasswordHash::verify_password` did
  not exist. GREEN parses and verifies Argon2 inside `nazo-identity`; the
  former `expose_for_verification` API is absent and a compile-fail doctest
  locks that boundary.
- Live login RED used real PostgreSQL and Valkey and returned HTTP 401 instead
  of the expected 303 because setup and form encoding generated different
  passwords. GREEN reuses the same per-test value and the exact live test
  passes.
- Delivery RED used the production owner list and failed because the approved
  item had no `delivery_token`. GREEN derives a request/user-scoped HMAC token,
  looks up only exact approved-request keys in bounded 128-key `MGET` batches,
  returns a token/URL only for a present committed payload with matching
  request, user, and approved-client linkage, and fails the owner response with
  503 on Valkey errors. It never uses `KEYS` or `SCAN`. The real end-to-end test
  obtains the token from `GET /auth/me/access-requests`, claims it as the
  applicant, observes 404 on replay, and observes the token disappear after
  consumption. The admin response contains no token; another logged-in user
  sees no token and cannot claim it even when given the value.
- Frontend RED failed with `ERR_MODULE_NOT_FOUND` for the requested delivery
  path helper. GREEN has one Node test proving approved-only display and safe
  token encoding, followed by ESLint, TypeScript, and Vite build.
- Repository-boundary RED named all four forwarding definitions in
  `support/oauth.rs`. GREEN deletes them, calls `OAuthClientRepository`
  directly from the actual consumers, forbids those definitions recursively,
  forbids OAuth-client queries in every server support module, and requires
  direct focused-repository calls so moving the facade does not pass.

### Fresh verification

- `rtk cargo fmt --all -- --check` and `rtk git diff --check` — exit 0.
- `rtk cargo check --workspace --all-targets --all-features --locked` — exit 0.
- `rtk cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
  — exit 0, no issues.
- Real PostgreSQL `rtk cargo test -p nazo-postgres --all-features --locked -- --nocapture`
  — exit 0: 4 unit, 6 access-request, 18 identity/architecture, 1 migration,
  and 2 compile-fail privacy tests passed.
- Real PostgreSQL/Valkey server access-request slice — 31/31 passed. The
  production owner response supplied the token, applicant claim returned 200,
  replay returned 404, and post-claim owner response omitted the capability.
- Real PostgreSQL/Valkey
  `login_form_request_creates_session_and_redirects_to_safe_next` — 1/1 passed
  with HTTP 303.
- `rtk cargo test -p nazo-identity --doc --all-features --locked` — 5/5 passed,
  including non-serialization and non-extraction compile-fail contracts.
- `rtk cargo doc -p nazo-identity -p nazo-postgres --no-deps --all-features --locked`
  — exit 0.
- `rtk cargo test --workspace --all-features --locked` with the live mandatory
  PostgreSQL URL and optional server live-service variables unset — exit 0
  across all workspace suites and doctests; server lib reported 1,658 passed.
- Sibling frontend `rtk npm test` — exit 0: Node delivery-path test 1/1,
  ESLint, TypeScript, and Vite production build all passed.

The existing localized MSVC linker-stdout warning was emitted during Rust test
linking and did not fail any gate. No external CI/CodeQL check was rerun
locally.

## Final OAuth client row-boundary remediation (2026-07-13)

The final Important finding is remediated. `nazo-postgres` now keeps its
`OAuthClientRecord` private and returns the auth-owned, storage-independent
`OAuthClient`. The runtime type composes validated registration metadata with
tenant identity and active/sender-constraint state; it is not Diesel-enabled,
contains no client-secret digest, and is not re-exported by the PostgreSQL
adapter. The server's `ClientRow` name is now only a compatibility alias to
that domain type. Remaining Task 5 server writes use the explicitly private
`ClientRecord` and convert to the domain type while rejecting malformed JSON
arrays.

Secret-basic/post authentication uses
`OAuthClientRepository::client_secret_matches`, which selects only the digest,
applies the unchanged `client-secret-v1` HMAC-SHA256 peppered verification in
constant time, and returns only a boolean. Missing clients, missing digests,
malformed digests, and wrong candidates fail closed. Repository errors retain
the existing service-unavailable behavior; invalid credentials retain the
existing `invalid_client` behavior. No public lookup returns a digest.

### TDD and focused evidence

- The new architecture contract first failed because the public Diesel result
  row still existed. It now rejects a public OAuth client row, public digest
  field, PostgreSQL re-export, and adapter-to-server `From` reconstruction,
  while requiring the auth-owned client result.
- The client-secret verifier test first failed with `E0425`; it now covers a
  matching candidate, wrong candidate, and malformed digest. A PostgreSQL unit
  test rejects non-array persisted client metadata.
- Auth, PAR, dispatch, introspection, revocation, and admin-client focused
  suites passed respectively: 14, 31, 56, 24, 15, and 39 tests.
- Real PostgreSQL/Valkey exact tests passed for wrong token-endpoint secret,
  wrong introspection secret, and successful authenticated refresh-token
  introspection. The real PostgreSQL identity/architecture suite passed 19/19.
- Server all-feature test compilation completed with zero errors and warnings;
  `nazo-auth` passed 70 tests and `nazo-postgres` passed 5 unit tests.

No refresh behavior, frontend, push, deployment, or PR state was changed.

### Commit and full verification

- Implementation: `beffc74` — `refactor: isolate OAuth client persistence rows`.
- `rtk cargo fmt --all -- --check` — exit 0.
- `rtk cargo check --workspace --all-targets --all-features --locked` — exit 0.
- `rtk cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
  — exit 0, no issues.
- `rtk cargo test --workspace --all-features --locked` with the mandatory
  isolated PostgreSQL URL and optional server live-service variables unset —
  exit 0 across all workspace tests and doctests.
- `rtk cargo doc --workspace --no-deps --all-features --locked` — exit 0.
  The `nazo-postgres` public item index lists `OAuthClientRepository` but no
  OAuth client result row, `OAuthClientRecord`, or client-secret digest field.

The workspace test emitted only the existing localized MSVC linker stdout
warnings; strict Clippy remained warning-free.

## Client persistence regression follow-up (2026-07-13)

The four Important and one Minor findings from
`client-persistence-review-regressions.md` are remediated. Stored client-secret
verifiers are never selected into Rust: PostgreSQL returns only the non-secret
salt, the server security boundary derives the exact compatible
`client-secret-v1:<salt>:<HMAC-SHA256>` candidate, and PostgreSQL returns only
an equality/`EXISTS` boolean. The auth crate's public stored-verifier API is
deleted. Invalid credentials remain `401 invalid_client`; repository failures
remain `503 server_error`.

DCR replacement is an active-row CAS. Its single parameterized `UPDATE` has
`WHERE tenant_id = $1 AND id = $2 AND is_active = TRUE` and does not assign
`is_active`, so a stale PUT snapshot cannot resurrect a concurrently deleted
client. The admin lifecycle mutation remains separate. The OIDF seed operation
is again one PostgreSQL `INSERT ... ON CONFLICT DO UPDATE`, using exactly the
managed columns from the pre-migration SQL. It preserves
`registration_access_token_blake3` and all fields the former seed did not
manage, while atomically updating the former managed fields and reactivating
the seed client.

Profile application projection again retains mixed JSON scope arrays through
the repository and filters non-string elements at the response boundary. The
original mixed-scope regression is restored. Production server schema no
longer declares, joins, or allow-lists `oauth_clients`; its declaration exists
only in the in-source test fixture. Architecture contracts now detect support
forwarding wrappers by function body rather than exact function names and scan
raw SQL case-insensitively.

### TDD evidence and commits

- Secret-boundary RED failed because `clients.rs` selected
  `oauth_clients::client_secret_hash`; the live equality test and default
  correct/wrong tests are GREEN.
- DCR RED ran against PostgreSQL and returned an active client from the stale
  PUT after DELETE; GREEN returns typed `NotFound` and leaves the row inactive.
- Seed RED showed an unmanaged `subject_type` overwritten from `pairwise` to
  `public`; GREEN preserves the registration token and every unmanaged sentinel,
  updates managed fields, and permits two concurrent missing-row upserts.
- Mixed-scope RED returned `RepositoryError::Unexpected` for integer `42`;
  GREEN returns `openid` and `profile` and does not turn the malformed elements
  into a 503.
- `41aff0b` — keep client-secret digest material inside PostgreSQL/server
  security boundaries and restore mixed-scope response filtering.
- `0073380` — make DCR replacement an active-client CAS with a real concurrent
  PostgreSQL regression.
- `cd0b385` — restore the atomic, old-SQL-compatible seed upsert.
- `eeec3ec` — remove the production server OAuth-client schema and strengthen
  persistence contracts.
- `031b7f8` — make forwarding-wrapper detection semantic and independent of
  exact helper names.

### Fresh verification

- Real PostgreSQL `cargo test -p nazo-postgres --all-features --locked` — exit
  0; 37 passed across 6 suites, including DCR concurrency, seed compatibility,
  digest equality, mixed scopes, and architecture contracts.
- Server focused all-feature tests — DCR 25/25, profile applications 1/1, and
  client authentication 16/16 passed.
- `cargo fmt --all -- --check` and `git diff --check` — exit 0.
- `cargo check --workspace --all-targets --all-features --locked` — exit 0.
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
  — exit 0, no issues.
- `cargo test --workspace --all-features --locked` with mandatory live
  PostgreSQL and optional server live-service variables unset — exit 0; 2,068
  passed across 38 suites.
- `cargo doc --workspace --no-deps --all-features --locked` — exit 0.

No refresh behavior, frontend, push, deployment, or PR state was changed.

## OAuth client persistence final completion (2026-07-13)

All remaining server OAuth-client persistence is now owned by the focused
`nazo-postgres::OAuthClientRepository`. The server `ClientRow` is only an alias
of the auth-owned `OAuthClient`; the complete Diesel `ClientRecord`, its
field-copy conversion, and direct server `oauth_clients` Diesel/raw-SQL reads
and writes are deleted. Admin create/list/update/detail, DCR authentication and
credential rotation/replacement/deactivation, PAR/token client authentication,
introspection, revocation, profile applications, OIDC logout, and the OIDF seed
binary call focused repository operations directly. No facade, trait object,
`block_on`, refresh behavior, frontend, push, deployment, or PR state was
introduced or changed.

Client-secret verification preserves the existing
`client-secret-v1:<salt>:<HMAC-SHA256>` format, pepper input, salt/candidate
input ordering, and compatibility. The adapter keeps stored verifiers private
and exposes only boolean `has_client_secret`/`client_secret_matches` results;
no digest is returned by a public lookup or result type. Default non-live tests
again cover correct and incorrect candidates. Repository/query failures remain
`503 server_error`, while a valid lookup with mismatched credentials remains
`401 invalid_client`. The review suggestion to collapse both cases to 401 was
explicitly rejected because it would break the established public error
taxonomy and obscure infrastructure failures.

### TDD evidence and commits

- The strengthened recursive architecture contract first failed with twelve
  semantic violations: seed raw SQL/persistence shape, the server record and
  field-copy conversion, admin create/list/update, DCR, profile applications
  and logout, introspection, and revocation. It does not depend on the former
  record name: it detects Diesel schema use, raw CRUD/JOIN SQL, a
  persistence-shaped client struct by field sentinels, and field-copy
  conversions. It now passes with no violation.
- `7af9ac4` — `refactor: move OAuth client writes into postgres repository`.
- `651e892` — `refactor: route OAuth client profile reads through postgres`.
- `c2d6a8f` — `refactor: complete OAuth client persistence ownership`.
- Default correct/wrong/store-unavailable secret tests pass 3/3. Focused DCR,
  admin clients, client auth, PAR, dispatch, introspection, and revocation
  suites pass 25, 39, 16, 31, 56, 24, and 15 tests respectively.

### Real-service and workspace verification

- Real PostgreSQL `rtk cargo test -p nazo-postgres --all-features --locked --
  --nocapture` — 33/33 passed across five suites.
- Real PostgreSQL/Valkey exact tests passed for wrong token-endpoint,
  introspection, and revocation secrets, plus successful authenticated refresh
  token introspection: 1/1 each. Live-enabled focused DCR/admin/PAR suites
  passed 25/25, 39/39, and 31/31.
- `rtk cargo fmt --all -- --check` and `rtk git diff --check` — exit 0.
- `rtk cargo check --workspace --all-targets --all-features --locked` — exit 0.
- `rtk cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
  — exit 0, no issues.
- `rtk cargo test --workspace --all-features --locked` with the mandatory live
  PostgreSQL URL and optional server live-service variables unset — 2,065
  passed in 37 suites.
- `rtk cargo doc --workspace --no-deps --all-features --locked` — exit 0.
`nazo-postgres` public docs contain no `OAuthClientRecord`, `ClientRecord`, or
`client_secret_hash` item.

## OAuth client schema-alias contract completion (2026-07-13)

The server OAuth-client ownership contract now rejects the physical table name
as a case-insensitive identifier token instead of relying on the literal
`oauth_clients::` Diesel module path. This closes local Diesel declaration and
alias bypasses such as `#[sql_name = "oauth_clients"] clients` followed by
`clients::table`, as well as direct declarations, schema import aliases, and
quoted/case-varied raw SQL. The existing visitor recursively scans every Rust
file under `crates/server/src`, including nested `schema.rs` files. The
separate `crates/server/tests/in_source` fixture tree remains outside that
production root, and documentation comments plus the existing directly gated
`#[cfg(test)]` schema import are not reported.

### TDD evidence and commit

- RED: the in-memory local-alias mutation produced no violation and failed
  `oauth_client_persistence_contract_rejects_a_locally_aliased_table_declaration`.
- GREEN: the consolidated mutation contract detects local SQL-name aliases,
  direct Diesel declarations, schema import aliases, and case-insensitive
  quoted raw SQL. A separate negative fixture proves documentation and the
  existing `#[cfg(test)]` schema import do not become false positives.
- `ef51c6e` — `test: close OAuth client schema alias loopholes`.

### Fresh verification

- Live PostgreSQL `rtk cargo test -p nazo-postgres --test identity_repositories
  --all-features --locked` — exit 0; 24/24 passed, including the mutation and
  recursive production-source ownership contracts.
- `rtk cargo fmt --all -- --check` — exit 0.
- `rtk cargo check --workspace --all-targets --all-features --locked` — exit 0.
- `rtk cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
  — exit 0, no issues.
- `rtk cargo test --workspace --all-features --locked` with the mandatory
  isolated PostgreSQL URL and optional server live-service variables unset —
  exit 0; 2,070 passed across 38 suites.
- `rtk cargo doc --workspace --no-deps --all-features --locked` — exit 0.

No production behavior, refresh implementation, frontend, push, deployment,
or PR state was changed.

## OAuth client contract cfg(test) scope correction (2026-07-13)

The OAuth-client table-name contract now removes complete directly
`#[cfg(test)]`-gated Rust items before looking for production references. The
bounded scrubber follows stacked item attributes and balances item braces while
ignoring braces in line/block comments, normal strings, raw strings, byte
strings, and character literals. It is local to the architecture test and does
not parse or change production code. Production string contents remain visible
to the table-name detector so direct raw SQL is still rejected.

### TDD evidence and commit

- RED: a `#[cfg(test)] mod tests { ... }` fixture containing an OAuth-client
  raw SQL string and Diesel schema reference failed because the old detector
  inspected only the token's current and preceding line.
- GREEN: the contract ignores the entire gated module and a gated item with an
  additional stacked attribute. Two positive mutations prove that a schema
  import and Diesel declaration after gated items remain detectable, including
  when comments and strings contain misleading closing braces.
- `fe0b3a6` — `test: scope OAuth contract cfg exclusions`.

### Fresh verification

- Focused OAuth-client contract tests — exit 0; 3/3 passed.
- Live PostgreSQL `rtk cargo test -p nazo-postgres --test
  identity_repositories --all-features --locked -- --nocapture` — exit 0;
  25/25 passed.
- `rtk cargo fmt --all -- --check` and `rtk git diff --check` — exit 0.
- `rtk cargo check --workspace --all-targets --all-features --locked` — exit 0.
- `rtk cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
  — exit 0, no issues.
- `rtk cargo test --workspace --all-features --locked` with the mandatory
  isolated PostgreSQL URL and optional server live-service variables unset —
  exit 0; 2,071 passed across 38 suites.
- `rtk cargo doc --workspace --no-deps --all-features --locked` — exit 0.

No production behavior, refresh implementation, frontend, push, deployment,
PR, or review-package state was changed.

## Refresh lost-response compatibility remediation (2026-07-13)

The 60-second lost-response retry behavior is restored without reinstating the
pre-`e252056` race. A revoked refresh token is eligible only when its
`revoked_at` is at or before the request-start timestamp and no more than 60
seconds old, its family has no reuse marker, and PostgreSQL contains exactly
one unexpired active child linked by `rotated_from_id` with the same tenant,
family, client, DPoP JKT, and mTLS thumbprint. Nullable sender constraints use
PostgreSQL `IS NOT DISTINCT FROM`, so both bound and unbound families are
matched exactly.

The request-start timestamp is fixed before token lookup. This is security
significant: a request that began while the token was active cannot become a
lost-response retry merely because another concurrent request rotates the
token before its lookup completes. The first real HTTP E2E run exposed that
boundary by producing two successes in the existing refresh-reuse race. After
carrying the request-start timestamp through the lost-response rotation policy
and locked persistence revalidation, the race again produces one success and
one `invalid_grant`, while a genuinely later retry remains compatible.

Both preliminary inspect-or-compromise and the authoritative final decision
use the existing stable PostgreSQL family advisory transaction lock. The
refresh persistence transaction reloads the original row, repeats the window,
reuse, unique-child, tenant/family/client, sender-constraint, active, and
expiry checks using the same request-start timestamp, then revokes that exact
successor and inserts a new child in the same transaction. A changed or
non-eligible state marks reuse and revokes the family atomically. Insert
failure rolls back successor revocation; family-revoke failure rolls back the
reuse marker. The response contains only the newly generated refresh token
whose BLAKE3 hash was inserted, never plaintext from the stored successor
(plaintext successors are not stored).

### TDD and commits

- RED: against the migrated PostgreSQL service, the restored compatibility
  assertion expected HTTP 200 for a token revoked 35 seconds earlier with one
  exact active successor, but received HTTP 400 `invalid_grant`. The run took
  0.07 seconds and failed at the response assertion, not compilation or
  fixture setup.
- The first implementation remained RED at the explicit successor-inspection
  assertion because nullable sender equality did not match SQL `NULL`; the
  null-safe PostgreSQL comparison made the exact test GREEN.
- The first full real-request E2E then failed
  `refresh_token_reuse_race_single_success` with two HTTP 200 responses. This
  identified request-start time, rather than post-lookup wall time, as the
  required future-revocation boundary. The timestamp-carrying implementation
  made both that race and the lost-response retry pass in the same unmodified
  E2E script.
- `918b5e3` — `fix: restore safe refresh lost-response retries`.

### Regression coverage

Real PostgreSQL tests cover the inclusive zero/60-second boundary plus
out-of-window and future revocations, no successor, two successors, expired or
inactive state, existing reuse markers, wrong tenant/family/client/DPoP/mTLS
constraints, newly persisted plaintext/hash linkage, concurrent ordinary
replay, concurrent lost-response retry, family compromise, reuse rollback, and
successor-revocation rollback after an injected child-insert failure. The live
test pool uses four connections so concurrency exercises the advisory lock
rather than a single pool connection queue.

### Fresh verification

- Real PostgreSQL focused refresh suite:
  `cargo test -p nazo-oauth-server --lib http::token::refresh::tests::
  --all-features --locked -- --nocapture` — exit 0; 36/36 passed.
- A current release service image was built from the implementation commit; a fresh migrated
  PostgreSQL 18 database, Valkey 8 instance, ordinary server, and signed server
  ran the unmodified `scripts/full_real_request_e2e.py` — exit 0 with
  `{"ok": true}`. Evidence includes
  `refresh_token_reuse_race_single_success`,
  `dpop_nonce_error_/token_425`,
  `POST /token previous refresh_token inside lost response window`, and
  `refresh_token_lost_response_rotates_successor`.
- `rtk cargo fmt --all -- --check` and `rtk git diff --check` — exit 0.
- `rtk cargo check --workspace --all-targets --all-features --locked` — exit 0.
- `rtk cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
  — exit 0, no issues.
- `rtk cargo test --workspace --all-features --locked` with the mandatory
  isolated PostgreSQL URL and optional server live-service variables unset —
  exit 0 across all unit, integration, and doctest suites.
- `rtk cargo doc --workspace --no-deps --all-features --locked` — exit 0.

Only the existing localized MSVC linker-stdout notices appeared during test
linking; strict Clippy was warning-free. No frontend file, migration, E2E
assertion, push, deployment, or PR state was changed.

## OAuth client contract parser correction (2026-07-13)

The OAuth-client ownership contract now parses every server production Rust
source with `syn` 2 (`full` and `visit`) instead of maintaining a test-local
Rust lexer and item-brace scrubber. The bounded AST visitor skips complete
items carrying an exact `#[cfg(test)]`, including inline modules and associated
items, while continuing recursively through production inline modules,
functions, and statements. Documentation attributes and comments are not
scanned. Production identifiers and paths, macro token streams such as Diesel
table declarations and `sql_name`, and normal or raw string literals retain
case-insensitive `oauth_clients` identifier-boundary detection. No `quote`
dependency was added.

### TDD evidence and commit

- RED: the reviewer lifetime/character-literal fixture and const-generic
  fixture produced 3 passing and 2 failing focused contract tests. The former
  exposed the hand-written lexer hiding an exact `cfg(test)` gate on the same
  line; the latter exposed a const-generic expression brace being mistaken for
  the gated function body.
- GREEN: the focused OAuth-client contract slice passes 5/5, retaining local
  alias, direct declaration, schema import, case-varied raw SQL,
  documentation/comment, whole cfg module, stacked-attribute, and continued
  production traversal coverage. An associated-item fixture also failed before
  the visitor was extended to skip exact cfg-gated impl, trait, and foreign
  items, then passed.
- `5e3b9c0` — `test: parse OAuth contract sources with syn`.

### Fresh verification

- Isolated live PostgreSQL `rtk cargo test -p nazo-postgres --test
  identity_repositories --all-features --locked -- --nocapture` — exit 0;
  27/27 passed.
- `rtk cargo fmt --all -- --check` and `rtk git diff --check` — exit 0.
- `rtk cargo check --workspace --all-targets --all-features --locked` — exit 0.
- `rtk cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
  — exit 0, no issues.
- `rtk cargo test --workspace --all-features --locked` with the mandatory
  isolated PostgreSQL URL and optional server live-service variables unset —
  exit 0; 2,073 passed across 38 suites.
- `rtk cargo doc --workspace --no-deps --all-features --locked` — exit 0.

No production behavior, refresh implementation, frontend, push, deployment,
PR, or review-package state was changed.

## Refresh PostgreSQL fixed-window coverage correction (2026-07-13)

The refresh remediation report previously overstated the live boundary
coverage. Before this follow-up, the exact zero/60-second/60-second-plus-1-ms/
future cases were asserted only by the pure
`within_lost_refresh_token_retry_window` unit test. The real PostgreSQL tests
called `lost_response_successor` for an approximate 35-second case, but did not
hold one `now` value fixed while exercising the exact window boundaries.

Commit `a14378e` (`test: exercise refresh retry window in postgres`) adds that
missing coverage without changing production code. The test creates a unique
schema and token family, uses the fixed timestamp
`2026-07-13T12:00:00Z`, and calls the real `lost_response_successor` query four
times on one PostgreSQL connection inside one transaction. It proves that
zero seconds and exactly 60 seconds return the unique active successor, while
60 seconds plus 1 millisecond and a 1-millisecond future revocation return
none. The schema is dropped before result assertions; no sleep or wall-clock
timing tolerance is involved.

### TDD evidence

- RED: with a temporary local boundary mutation from `<= 60 seconds` to
  `< 60 seconds`, the new live test failed in 0.09 seconds at the exact
  60-second assertion: PostgreSQL lookup returned `None` instead of the
  inserted successor UUID. The test compiled, connected, created its fixture,
  executed the query, and cleaned the schema before the assertion failed.
- GREEN: after restoring the existing inclusive production expression, the
  exact live test passed 1/1 in 0.08 seconds. The temporary mutation is not in
  any commit or final diff.

### Fresh verification

- Real PostgreSQL exact fixed-window test — exit 0; 1/1 passed.
- Real PostgreSQL focused refresh suite — exit 0; 37/37 passed.
- `rtk cargo fmt --all -- --check` and `rtk git diff --check` — exit 0.
- `rtk cargo check --workspace --all-targets --all-features --locked` — exit 0.
- `rtk cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
  — exit 0, no issues.
- `rtk cargo test --workspace --all-features --locked` with the mandatory
  isolated PostgreSQL URL and optional server live-service variables unset —
  exit 0; 2,081 passed across 38 suites.
- `rtk cargo doc --workspace --no-deps --all-features --locked` — exit 0.

No production behavior, frontend, E2E assertion, push, deployment, or PR state
was changed.

## Refresh unbound lost-response hardening (2026-07-13)

Lost-response recovery is now restricted to refresh-token families whose
presented revoked token has a stable non-null sender constraint: a DPoP JKT or
an mTLS `x5t#S256` thumbprint. The existing null-safe exact successor checks
remain authoritative for both constraints. A revoked unbound bearer token is
therefore never recoverable, even within 60 seconds with exactly one active
child; presentation marks reuse and revokes the family atomically under the
existing family advisory lock.

This closes the coverage-instrumentation race without treating request start
time as proof of concurrency. A deterministic real PostgreSQL regression first
obtained HTTP 200 from an unbound refresh token, waited for that call to return
and its rotation transaction to commit, then presented the same token again.
Before the fix the second sequential request also returned HTTP 200; after the
fix it returns `400 invalid_grant` and every family row has a reuse marker and
revocation timestamp. The prior unbound lost-response success test now asserts
the same fail-closed compromise behavior.

Bound compatibility remains intact. Real PostgreSQL tests preserve the
inclusive 60-second DPoP-bound window and exact nullable sender matching. An
mTLS-bound lost-response retry with a matching verified certificate rotates
the stored successor, returns a newly generated token distinct from both
presented plaintext values, and persists only its hash. Concurrent mTLS-bound
retries still yield one success and one `invalid_grant`, followed by family
compromise; injected child-insert failure still rolls back successor
revocation. The ordinary active-token concurrent replay test remains unchanged.

### TDD and verification evidence

- RED: real PostgreSQL
  `sequential_unbound_replay_after_first_commit_fails_closed` failed in 0.08
  seconds because the post-commit second request returned HTTP 200 instead of
  400. The rewritten prior unbound-success test also failed because the
  successor query returned the unbound child.
- GREEN: real PostgreSQL refresh focused suite passed 39/39, covering unbound
  fail-closed behavior, DPoP/mTLS bound recovery, concurrency, fixed-window
  boundaries, constraint mismatch, family compromise, and transaction faults.
- The same 39/39 focused suite passed with native Rust
  `-C instrument-coverage`; `.profraw` files were produced in the isolated
  instrumentation target directory. `cargo-llvm-cov` itself was not installed
  locally.
- A fresh release image built from the hardened source ran against a newly
  migrated PostgreSQL 18 database and Valkey 8 instance. The unmodified full
  real-request E2E returned `{"ok": true}`, including
  `refresh_token_reuse_race_single_success`, family revocation after the race,
  DPoP nonce 425, and DPoP-bound lost-response successor rotation.

No E2E assertion, token plaintext storage, nonce behavior, frontend, migration,
push, deployment, or PR state was changed.
