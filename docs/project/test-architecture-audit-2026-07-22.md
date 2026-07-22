# Test Architecture Audit — 2026-07-22

## Decision

The canonical Rust layout is `src/<module>.rs` plus a mirrored
`tests/unit/<module>.rs` private-unit child, ordinary `tests/support` fixtures,
and public-API integration targets directly under `tests/`.
`tests/source_mounted/src/.../tests` is rejected: it repeats implementation
mechanics, obscures ownership, and made copied implementations look like tests
of production behavior.

Tests must execute production policies, parsers, key derivation, cryptography,
and state transitions. A test may construct input or fake an external port; it
must not carry a second implementation of the behavior being asserted.

## Inventory and screening

The repository-wide declaration inventory found 2,296 Rust and Python test
declarations. Automated screening classified the dominant methods as behavior,
HTTP transport, PostgreSQL, Valkey, concurrency, script orchestration, and
source-contract checks. It produced 580 unique review candidates; that number
is a triage queue, not 580 confirmed defects. The main signals were test-only
seam calls, source-text assertions, missing explicit assertions, and production
source recompiled into a test target.

Source-contract tests are permitted only as supplemental architecture
guardrails. They are not evidence that OAuth/OIDC behavior is conformant. Count
thresholds and string copies of production source are specifically rejected.

## Confirmed defects corrected

- Removed the integration target that recompiled
  `http-actix/src/authorization_decision.rs`; it now imports the public
  production API.
- Removed the copied PostgreSQL subject-claims converter; tests now call
  `active_subject_claims`.
- Removed the test-only OIDC front-channel logout boolean and made tests use the
  same runtime capability registry as production.
- Deleted the obsolete authorization-parameter implementation retained under
  `cfg(test)` after the core architecture rewrite. Its focused replacements call
  production normalization and decision functions.
- Made S256 PKCE mandatory for authorization code requests and PAR. A
  confidential client no longer bypasses both PKCE and an equivalent
  transaction-bound protection.
- Re-homed random-code, password-verification, JWT-algorithm, replay-key, and
  authorization-code storage-reply tests with the crates that own those real
  implementations.
- Replaced raw PAR key reconstruction with `AuthorizationService::load_par`;
  corruption tests use one centralized state-store test harness function.
- Made service-backed PostgreSQL targets skip cleanly when their declared test
  database is absent instead of reporting infrastructure absence as a product
  failure.

The PKCE decisions are aligned with the project-wide stronger policy and the
security direction in RFC 9700. The FAPI-specific PAR assertions additionally
cover authenticated PAR, confidential/strong client authentication,
sender-constrained tokens, explicit redirect URI, and S256 PKCE as required by
the FAPI 2.0 Security Profile. Logout tests use actual runtime capability state,
which is necessary for meaningful RP-Initiated and Front-Channel Logout
behavior. OpenID4VC and CIBA coverage remains attached to their production
endpoints and orchestration rather than copied protocol models.

Primary specifications:

- <https://www.rfc-editor.org/rfc/rfc9700.html>
- <https://openid.net/specs/fapi-security-profile-2_0-final.html>
- <https://openid.net/specs/openid-connect-core-1_0-35.html>
- <https://openid.net/specs/openid-connect-rpinitiated-1_0.html>
- <https://openid.net/specs/openid-connect-frontchannel-1_0.html>
- <https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html>
- <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html>
- <https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html>

## Enforcement

`scripts/verify_static_contracts.py --check` now rejects executable tests under
`src`, legacy or repeated test/source layouts, missing mounts, and a test that
uses `#[path]` or `include!` to recompile a production source file.
`docs/project/testing.md` defines the ownership and method rules.

## Remaining migration debt

Forty-two `tests/support/seams` includes remain. They are not the target
architecture and are not treated as completed work. Thin composition adapters
are lower risk, but copied session, rate-limit, token-dispatch, CIBA, and state
key behavior must still be replaced by calls to owned production APIs and then
removed. The structure verifier prevents a return to `source_mounted` and
source recompilation now; the seam count should only decrease.

## Verification snapshot

- `cargo fmt --all -- --check`: passed.
- `python scripts/verify_static_contracts.py --check`: passed.
- `cargo test --workspace`: 1,946 passed across 100 suites.
- Explicit Python `unittest` module run: 222 passed. The deploy contract module
  accounts for about 213 seconds and needs its own CI timeout budget.
- Live PostgreSQL/Valkey behavior remains environment-dependent; absence is now
  reported as an unexecuted service-backed case rather than a false product
  failure.
