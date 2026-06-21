# Security Coverage Checkpoint

Date: 2026-06-14

This checkpoint records the current security-coverage and refactor work after the
test files were moved under `tests/` and the token-management boundary tests were
expanded.

## Target

The target is effective 100% coverage for real business and security behavior, not cosmetic global line coverage. Tests must make insecure or incorrect implementations fail.

Coverage is treated as a signal. The actual objective is to prove security invariants across valid, invalid, malicious, malformed, replayed, expired, and boundary-condition inputs.

## First-Principles Rules

- Start from assets, trust boundaries, protocol invariants, state transitions, and attacker behavior.
- Do not add tests merely to execute lines.
- Do not use weak assertions that only check success or failure.
- Every important test must assert exact observable behavior: OAuth/OIDC error code, HTTP status, response shape, state transition, absence of issued credentials, and absence of sensitive leakage where relevant.
- Prefer endpoint/service boundaries. Use unit tests only for validators, parsers, claim builders, policy functions, and error mappers.
- Do not expose private production APIs just for tests unless it preserves the architecture better than weakening boundaries.
- Do not weaken validation, loosen protocol behavior, add broad exclusions, or mock away security logic.
- Failed exchanges must fail closed and must not issue credentials or leave inconsistent state.

## File Responsibility Rules

- A file should carry one clear module responsibility.
- Files over 600 lines require self-review for overly broad responsibility.
- Files over 1000 lines require an explicit reason if not split.
- Files over 1500 lines should be split unless there is a specific exceptional reason.
- File names should express a security semantic boundary.
- Tests should live under the `tests/` tree. Source-mounted tests that need private or `pub(crate)` implementation access are stored under `tests/in_source/src/**` and mounted from the owning module with `#[cfg(test)]`. Top-level `tests/*.rs` files are reserved for integration tests that exercise the public crate or process boundary.

Current length check: no Rust file under `src/` or `tests/` exceeds 600 lines.

## Completed In This Batch

Token endpoint security-boundary coverage was expanded:

- `tests/in_source/src/http/token/tests/introspect.rs`
  - malformed content type returns `400 invalid_request`
  - invalid UTF-8 returns `400 invalid_request`
  - duplicate `token` returns `400 invalid_request`
  - missing `token` returns `400 invalid_request`
  - conflicting client authentication returns `400 invalid_request`
  - missing client authentication returns `401 invalid_client`
  - assertions verify no `active`, `client_id`, or `sub` metadata is leaked on failures

- `tests/in_source/src/http/token/tests/revoke.rs`
  - malformed content type returns `400 invalid_request`
  - invalid UTF-8 returns `400 invalid_request`
  - duplicate `token` returns `400 invalid_request`
  - missing `token` returns `400 invalid_request`
  - conflicting client authentication returns `400 invalid_request`
  - missing client authentication returns `401 invalid_client`
  - assertions verify no access token, refresh token, or internal reason is exposed

Authorization-code tests were split by semantic boundary:

- `authorization_code/consumption.rs`
- `authorization_code/error_mapping.rs`
- `authorization_code/pkce.rs`
- `authorization_code/redirect_uri.rs`

Authorization request stored-grant and `prompt=none` tests were split into:

- `request/prompt_none.rs`

The split keeps each file aligned to a specific security responsibility while preserving behavior.

Production testability changes were minimal and scoped:

- `introspect_after_rate_limit(...)` allows tests to exercise token introspection parsing and client-authentication boundaries without Valkey rate-limiter setup.
- `revoke_after_rate_limit(...)` does the same for revocation.

These helpers do not remove validation, bypass protocol logic, or widen public API surface beyond crate-internal testing boundaries.

Coverage tooling was corrected:

- `.github/workflows/codecov.yml` now exports llvm-cov instrumentation environment before `cargo clean`.
- `README.md` local coverage instructions now match the verified working order.

The old order could reuse non-instrumented binaries and produce invalid near-zero coverage despite tests passing.

## Validation Results

Commands already completed before this checkpoint:

```sh
CARGO_BUILD_JOBS=1 CARGO_TERM_COLOR=never rtk cargo fmt --all -- --check
CARGO_BUILD_JOBS=1 CARGO_TERM_COLOR=never rtk cargo test --workspace --all-features
CARGO_BUILD_JOBS=1 CARGO_TERM_COLOR=never rtk cargo clippy --workspace --all-features --all-targets -- -D warnings
```

Observed result:

- formatting passed
- full workspace tests passed: 582 tests passed
- clippy passed with `-D warnings`

Reliable local coverage command:

```sh
CARGO_BUILD_JOBS=1 CARGO_TERM_COLOR=never rtk bash -lc '
  cargo llvm-cov clean --workspace
  eval "$(cargo llvm-cov show-env --sh)"
  cargo clean
  cargo test --locked --workspace --all-features --lib
  cargo llvm-cov report --lcov --output-path lcov.info \
    --ignore-filename-regex '"'"'(^|/)(tests?|benches|examples|migrations)(/|\.rs$)|src/(schema|db)\.rs$|src/domain/rows\.rs$|src/bootstrap/routes\.rs$|src/support/valkey\.rs$|src/main\.rs$|src/bin/nazo_oauth_(keyctl|migrate|seed_oidf)\.rs$'"'"'
'
```

Coverage result from the valid `lcov.info`:

```text
TOTAL LH=7132 LF=15514 45.97%
```

The earlier `0.65%` result is invalid because tests reused non-instrumented binaries.

## Continued Coverage Batch

Additional security-invariant tests were added after the initial checkpoint:

- `tests/in_source/src/http/token/tests/client_auth.rs`
  - confidential `client_secret_basic` succeeds only when the client is confidential, uses the registered method, and supplies the correct secret
  - wrong secret is rejected as `InvalidClient`
  - wrong authentication method is rejected as `InvalidClient`
  - public clients are rejected even if they present a valid secret
  - unsupported registered authentication methods fail closed

- `tests/in_source/src/http/token/tests/dispatch.rs`
  - FAPI2 rejects `client_secret_basic` with `401 invalid_client`
  - FAPI2 rejects bearer-only clients with `400 invalid_request`
  - FAPI2 rejects public clients with `400 unauthorized_client`
  - FAPI2 accepts confidential mTLS clients when tokens are sender constrained
  - malformed `grant_types` registration fails closed as `400 unauthorized_client` without panicking or dispatching a grant

- `tests/in_source/src/http/token/tests/issue.rs`
  - access-token signing failure returns `500 server_error`
  - signing failure does not return `access_token`, `refresh_token`, or `id_token`
  - invalid persisted `authorization_details` state fails before token signing
  - invalid authorization details failure does not issue any credentials

Validation after this continuation:

```sh
CARGO_BUILD_JOBS=1 CARGO_TERM_COLOR=never rtk cargo test --workspace --all-features
```

Observed result:

- full workspace tests passed: 582 tests passed

Coverage after this continuation, using the corrected llvm-cov flow:

```text
TOTAL LH=7132 LF=15514 45.97%
```

Delta from the initial valid checkpoint baseline:

```text
45.31% -> 45.97%
```

## Local OIDF Full Matrix

After this refactor batch, the local OIDF conformance containers were rebuilt from
the current working tree and the full local matrix was executed.

Result directory:

```text
runtime/oidf/results-local-full-20260614T150352Z
```

Exported result packages:

```text
16
```

OIDF API audit of exported module IDs:

```text
module_ids=562
FINISHED/PASSED=559
FINISHED/REVIEW=3
bad_count=0
```

`bad_count=0` means the bounded API audit found no `FAILED`, `WARNING`,
`SKIPPED`, or `INTERRUPTED` module result in the exported full matrix.

## Current Exclusions And Justification

The coverage report excludes:

- `tests/**`, `benches/**`, `examples/**`: non-production test or demonstration code
- `migrations/**`: generated or database migration artifacts
- `src/schema.rs`: generated Diesel table declarations
- `src/domain/rows.rs`: Diesel row projection DTOs
- `src/db.rs`: connection-pool glue
- `src/bootstrap/routes.rs`: mechanical route wiring
- `src/support/valkey.rs`: thin Valkey command wrappers
- `src/main.rs`: binary entry wrapper
- `src/bin/nazo_oauth_keyctl.rs`, `src/bin/nazo_oauth_migrate.rs`, `src/bin/nazo_oauth_seed_oidf.rs`: command wrappers and seed side-effect entrypoints

Do not exclude:

- token issuing logic
- authorization logic
- client authentication
- PKCE
- DPoP
- mTLS
- JWT/JWK/JWS validation
- refresh-token rotation
- error mapping
- repository state transitions
- protocol metadata
- resource-server verification
- settings and security policy validation

## Next Work

Continue from the valid low-coverage list, but keep deriving tests from invariants first.

Priority modules from the current `lcov.info`:

- `src/support/repositories.rs`
  - persistence and transaction boundaries
  - stale state and replay behavior
  - failed writes must not create partial credentials

- `src/http/token/issue.rs`
  - issued access/ID/refresh token claims
  - no credentials on failed authorization-code or refresh-token exchanges
  - signing and claim construction fail closed

- `src/http/token/issue/authorization_code_state.rs`
  - single-use authorization code consumption
  - client and redirect URI binding
  - invalid attempts must follow project policy consistently

- `src/http/token/issue/refresh_persistence.rs`
  - refresh-token rotation atomicity
  - reuse detection
  - old token invalidation
  - no replacement token after failed refresh

- `src/http/token/client_auth.rs`
  - exact behavior for missing, unknown, wrong, conflicting, and public/confidential client authentication
  - no token issuance after failed authentication

- `src/http/token/refresh.rs`
  - refresh grant validity, scope narrowing, client binding, expiration, and replay

- `src/http/token/dispatch.rs`
  - grant type routing
  - malformed form behavior
  - unsupported grant type exact error mapping

- `src/http/authorization/request.rs`
  - redirect URI integrity
  - open redirect prevention
  - state and nonce propagation
  - unsupported response type and scope errors

- `src/http/authorization/jar.rs` and `src/http/authorization/par.rs`
  - signed request validation
  - request URI expiration and client binding
  - downgrade rejection
  - exact FAPI-required errors

- `src/http/auth/federation.rs` and `src/http/auth/federation/oidc.rs`
  - upstream issuer/audience/signature validation
  - nonce/state binding
  - fail-closed behavior on malformed or unsigned upstream tokens

- `src/resource_server.rs`, `src/support/dpop.rs`, `src/support/mtls.rs`
  - proof binding
  - wrong `htu`/`htm`
  - replayed `jti`
  - wrong key binding
  - expired/future proof timestamps

For every added test, record the invariant implicitly in the test name and assert:

- precondition
- action
- expected state change
- forbidden state change
- externally visible response

## OIDF Status To Document Later

The user reported that the official full OIDF matrix has passed. Before writing final public proof text, verify the current official run URL, run id, tested commit, plan list, and artifact/API result, then update README and conformance docs with exact evidence.

## Resume Continuation

The session fail-closed batch was resumed and completed.

Additional tests:

- `tests/in_source/src/support/tests/sessions.rs`
  - missing session cookies return anonymous state without touching Valkey or Postgres
  - missing session cookies cannot complete MFA or perform MFA step-up
  - anonymous requests receive exact `401 login_required` for user-only paths
  - anonymous requests receive exact `403 access_denied` for admin-only paths
  - stale session cookies are cleared on login-required responses
  - session lookup backend failures return `503 server_error`
  - session lookup backend failures do not become Basic or Bearer challenges

Validation for this continuation:

```sh
rtk cargo fmt --all -- --check
rtk cargo test --workspace --all-features support::sessions::tests
CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=target/codex-coverage rtk proxy bash -lc 'cargo llvm-cov clean --workspace && eval "$(cargo llvm-cov show-env --sh)" && cargo test --locked --workspace --all-features --lib && cargo llvm-cov report --lcov --output-path lcov.info --ignore-filename-regex ...'
```

Observed result:

- `support::sessions::tests`: 10 passed
- coverage test target set: source-mounted lib tests include the OIDF seed and resource-server coverage; the former duplicate top-level integration test targets are no longer part of the command

Coverage after this continuation:

```text
TOTAL LH=7234 LF=15514 46.63%
src/support/sessions.rs LH=102 LF=186 54.84%
```

Delta from the previous reliable checkpoint:

```text
45.97% -> 46.63%
```

Continue from the low-coverage map in this document, with
`src/http/token/issue/refresh_persistence.rs`, `src/support/repositories.rs`,
`src/http/token/refresh.rs`, `src/http/auth/federation.rs`, and DB-backed
handler paths as high-value next targets. Those need storage-aware integration
tests or carefully bounded service-boundary tests, not mocked validation.
