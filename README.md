# Nazo Auth Server

[![OpenID Certified](https://openid.net/wordpress-content/uploads/2016/04/oid-l-certification-mark-l-rgb-150dpi-90mm-300x157.png)](https://openid.net/mark/)

[![code-quality](https://github.com/bymoye/NazoAuth/actions/workflows/code-quality.yml/badge.svg?branch=main)](https://github.com/bymoye/NazoAuth/actions/workflows/code-quality.yml)
[![codeql](https://github.com/bymoye/NazoAuth/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/bymoye/NazoAuth/actions/workflows/codeql.yml)
[![dependency-review](https://github.com/bymoye/NazoAuth/actions/workflows/dependency-review.yml/badge.svg?branch=main)](https://github.com/bymoye/NazoAuth/actions/workflows/dependency-review.yml)
[![conformance-security](https://github.com/bymoye/NazoAuth/actions/workflows/conformance-security.yml/badge.svg?branch=main)](https://github.com/bymoye/NazoAuth/actions/workflows/conformance-security.yml)
[![oidf-conformance-full](https://github.com/bymoye/NazoAuth/actions/workflows/oidf-conformance-full.yml/badge.svg?branch=main)](https://github.com/bymoye/NazoAuth/actions/workflows/oidf-conformance-full.yml)
[![codecov](https://codecov.io/gh/bymoye/NazoAuth/branch/main/graph/badge.svg)](https://app.codecov.io/gh/bymoye/NazoAuth)

[中文文档](README.zh-CN.md)

Nazo Auth Server is a Rust-native OAuth 2.1 and OpenID Connect authorization
server for self-hosted deployments. The implementation favors explicit profile
boundaries, sender-constrained token support, and repeatable conformance
evidence.

The current implementation covers the authorization-server surface: authorization code with
PKCE, token issuance, refresh tokens, PAR, signed request objects, DPoP, mTLS
sender constraints, JWKS, discovery, UserInfo, token management, and a compact
identity/admin data plane.

## Project Map

- Package: `nazo-oauth-server`
- Language: Rust 2024
- License: Apache-2.0
- Runtime dependencies: PostgreSQL and Valkey
- Main branch policy: work happens on `main`
- Chinese documentation: see [README.zh-CN.md](README.zh-CN.md)
- Conformance evidence: see [docs/conformance](docs/conformance)
- Deployment guide: see [docs/deployment.md](docs/deployment.md) and
  [docs/deployment.zh-CN.md](docs/deployment.zh-CN.md)
- Ecosystem onboarding decisions: see [docs/ecosystem-onboarding.md](docs/ecosystem-onboarding.md)
- PostgreSQL and Valkey operations: see [docs/ha-operations.md](docs/ha-operations.md)
- Resource server verifier: see [docs/resource-server-verifier.md](docs/resource-server-verifier.md)
- Current scope: see [docs/roadmap.md](docs/roadmap.md)
- Security policy: see [SECURITY.md](SECURITY.md)
- Release security: see [docs/release-security.md](docs/release-security.md)
- Change history: see [CHANGELOG.md](CHANGELOG.md)

## Capabilities

- OAuth authorization code flow with S256 PKCE.
- Refresh-token rotation, token-family reuse detection, and atomic authorization code consumption.
- Client credentials, refresh token, revocation, and introspection endpoints.
- OpenID Connect discovery, OAuth Authorization Server Metadata, JWKS, ID Token, and UserInfo.
- PAR and JAR support, including signed request objects with `EdDSA`, `RS256`, `ES256`, and `PS256`.
- `client_secret_basic`, compatibility `client_secret_post`, `private_key_jwt`, public clients, and mTLS client authentication. High-security clients use `private_key_jwt` or mTLS rather than `client_secret_post`.
- DPoP proof validation, nonce handling, sender-constrained access tokens, and DPoP-bound UserInfo.
- mTLS sender-constrained access tokens through a trusted reverse-proxy certificate forwarding boundary.
- Server signing key rotation with active and previous JWKS publication.
- Pairwise subject identifiers.
- Cookie sessions, CSRF protection, security response headers, and structured audit events.
- HTTPOnly session cookie flow; login responses do not expose session identifiers in JSON.
- PostgreSQL persistence with Rust-native migrations.
- Valkey-backed sessions, security state, replay prevention, PAR handles, and rate limiting.
- User, profile, avatar, OAuth client, grant, and access-request management APIs.
- RFC 8707 `resource` parameter support for token requests, including repeated resource indicators mapped to JWT access-token `aud` arrays. The older `audience` parameter remains as a single-audience project extension.
- RFC 9396-style Rich Authorization Requests through `authorization_details` on authorization, PAR, and signed request object inputs. Supported detail types are advertised in OAuth metadata and bound into consent, authorization codes, refresh tokens, and JWT access-token claims.
- Resource-server JWT access-token verifier core for Rust integrations. It
  validates `typ=at+jwt`, issuer, audience, expiry, scopes, algorithm/key
  selection, and optional DPoP or mTLS `cnf` sender constraints before
  application policy hooks run.

## Certification And Conformance

Nazo Auth Server is published in the OpenID Foundation certification listings.
The certified deployment is `Nazo Auth Server 0.1.0`, dated `09-Jun-2026`:

- [Certified OpenID Provider profiles](https://openid.net/certification/certified-openid-providers-profiles/)
- [Certified FAPI 2.0 OP Security Profile Final and Message Signing Final](https://openid.net/certification/certified-fapi-2-0-op-security-profile-final-message-signing-final/)

Durable conformance records live in Git because GitHub Actions artifacts
expire. The certified deployment is backed by the 2026-06-09 OpenID Foundation
16-plan matrix against `https://auth.nazo.run` across OIDC Basic, OIDC Config,
FAPI2 Security Profile Final, FAPI2 Message Signing Final, mTLS, DPoP,
`private_key_jwt`, and client credentials variants. The latest official full
matrix reran the same public issuer through the real `/ui/` frontend after the
OIDF-only interaction pages were removed and after JSON-only backend
authorization errors were enabled:

- [2026-06-09 OIDF full matrix](docs/conformance/2026-06-09-oidf-full-matrix.md)
- [2026-06-13 real public UI OIDF regression](docs/conformance/2026-06-13-real-public-ui-regression.md)
- [2026-06-14 local refactor OIDF full matrix](docs/conformance/2026-06-14-local-refactor-full-matrix.md)

The latest recorded official workflow conclusion was `success` on run
`27491182262` for commit
`31c3d0665ec72ffb4babedfea519ed175ef403ad`. The official runner reported 71
test modules, 6375 successes, `0 failures`, and `0 warnings`. The records
include commit SHA, run environment, plan IDs, exported artifact filenames,
profile combinations, artifact digest, and pass counts.

## Architecture

```text
.
├── Cargo.toml
├── Containerfile
├── compose.yml
├── docs/
│   ├── conformance/
│   └── deployment.md
├── migrations/
├── scripts/
└── src/
    ├── bootstrap/       # application assembly and route registration
    ├── bin/             # operational commands
    ├── domain/          # domain rows, OAuth payloads, and settings types
    ├── http/            # endpoint handlers
    ├── support/         # shared security, storage, response, and protocol helpers
    └── main.rs          # HTTP service entry point
```

Key binaries:

| Binary | Purpose |
| --- | --- |
| `nazo-oauth-server` | HTTP authorization server |
| `nazo-oauth-migrate` | Database migration command |
| `nazo-oauth-keyctl` | JWT signing key lifecycle command |

## Local Requirements

- Rust toolchain compatible with edition 2024
- PostgreSQL 18 or compatible PostgreSQL server
- Valkey 8 or compatible Redis protocol server
- Docker or Podman for containerized local integration

## Local Start

Create a local configuration file:

```sh
cp .env.yaml.example .env.yaml
```

Start the local integration stack:

```sh
docker compose up -d nazo_oauth_server
```

Check the service:

```sh
curl -fsS http://127.0.0.1:8000/health
curl -fsS http://127.0.0.1:8000/.well-known/openid-configuration
```

For a direct host run, point `DATABASE_URL` and `VALKEY_URL` in `.env.yaml` at host-reachable services, then run:

```sh
cargo run --bin nazo-oauth-migrate
cargo run --bin nazo-oauth-server
```

## Runtime Configuration

Configuration precedence is:

```text
defaults < .env.yaml < process environment variables
```

Only explicitly allowlisted environment variables are accepted. A `.env` file is deliberately unsupported; if `.env` exists, the service refuses to start. Use `.env.yaml` for local or deployment configuration and do not commit real secrets.

Common settings:

| Setting | Default | Notes |
| --- | --- | --- |
| `BIND` | `0.0.0.0:8000` | HTTP listener |
| `DATABASE_URL` | `postgresql://postgres:postgres@127.0.0.1:5432/oauth` | PostgreSQL connection string |
| `VALKEY_URL` | `redis://127.0.0.1:6379/0` | Valkey connection string |
| `ISSUER` | `http://127.0.0.1:8000` | Must match discovery and token issuer exactly; production must use HTTPS |
| `FRONTEND_BASE_URL` | `http://127.0.0.1:3000` | Login and consent frontend base URL |
| `CORS_ALLOWED_ORIGINS` | `http://127.0.0.1:3000` | Comma list or YAML array |
| `DEFAULT_AUDIENCE` | `resource://default` | Default access-token audience |
| `AUTHORIZATION_SERVER_PROFILE` | `oauth2-baseline` | `oauth2-baseline`, `fapi2-security`, or `fapi2-message-signing-authz-request` |
| `COOKIE_SECURE` | derived from issuer | Must be `true` in HTTPS production |
| `TRUSTED_PROXY_CIDRS` | empty | Required before trusting forwarded IP or mTLS headers |
| `CLIENT_IP_HEADER_MODE` | `none` | `none`, `forwarded`, or `x-forwarded-for` |
| `SUBJECT_TYPE` | `public` | `public` or `pairwise` |
| `PAIRWISE_SUBJECT_SECRET` | empty | Required when `SUBJECT_TYPE=pairwise` |
| `EMAIL_DELIVERY` | `disabled` | `smtp` enables registration email delivery |
| `AVATAR_STORAGE_DIR` | `runtime/avatars` | Avatar storage path |
| `JWK_KEYS_DIR` | `runtime/keys` | Signing key storage path |
| `SIGNING_EXTERNAL_COMMAND` | empty | Optional comma-separated argv for a KMS/HSM signing command or sidecar |
| `SIGNING_EXTERNAL_TIMEOUT_MS` | `2000` | External signer timeout in milliseconds |

See [.env.yaml.example](.env.yaml.example) for the complete field list.

`AUTHORIZATION_SERVER_PROFILE=fapi2-security` requires PAR, confidential
clients, `private_key_jwt` or mTLS client authentication, sender-constrained
access tokens, and authorization code lifetimes of 60 seconds or less.
`fapi2-message-signing-authz-request` adds signed request objects at PAR.
Discovery metadata is generated from the active profile and mTLS proxy
configuration. mTLS capabilities are not advertised unless
`TRUSTED_PROXY_CIDRS` is configured.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Health check |
| `GET` | `/authorize` | Authorization endpoint |
| `GET` | `/authorize/consent` | Consent page data |
| `POST` | `/authorize/decision` | Consent decision |
| `POST` | `/par` | Pushed Authorization Request |
| `POST` | `/token` | Token endpoint |
| `GET`/`POST` | `/logout` | OIDC RP-Initiated Logout |
| `POST` | `/revoke` | Token revocation |
| `POST` | `/introspect` | Token introspection |
| `GET` | `/.well-known/openid-configuration` | OIDC discovery |
| `GET` | `/.well-known/oauth-authorization-server` | OAuth server metadata |
| `GET` | `/jwks.json` | JWKS |
| `GET` | `/userinfo` | OIDC UserInfo |

The token endpoint accepts the RFC 8707 `resource` parameter as an absolute URI
without a fragment. A request may repeat `resource` to request multiple
audiences; single-resource access tokens keep a string `aud`, and
multi-resource access tokens use a JWT `aud` array. The legacy `audience`
parameter remains available as a single-audience project extension. A request
must not send both.

The authorization endpoint, PAR endpoint, and signed request objects accept RFC
9396-style `authorization_details` arrays. Each item must be an object with a
supported `type`; the server advertises `account_information` and
`payment_initiation` in `authorization_details_types_supported`. High-risk
details such as payments or write actions require fresh transaction binding and
are not silently covered by a previous broad consent.

OIDC logout is available at `/logout` and advertised as `end_session_endpoint`.
RP-Initiated Logout accepts `id_token_hint`, `client_id`,
`post_logout_redirect_uri`, and `state`; post-logout redirects require exact
registration in `post_logout_redirect_uris`. Registered clients with
`backchannel_logout_uri` receive best-effort back-channel logout notifications
signed as `logout+jwt` tokens.

## Key Management

Generate keys:

```sh
nazo-oauth-keyctl generate
nazo-oauth-keyctl generate --alg RS256
nazo-oauth-keyctl generate --alg ES256
nazo-oauth-keyctl generate --alg PS256
```

Activate a new key after it has been deployed and published in JWKS:

```sh
nazo-oauth-keyctl activate <kid>
```

Retire an old key after the maximum token TTL has elapsed:

```sh
nazo-oauth-keyctl retire <old-kid> --at 2026-06-01T00:00:00Z
```

Validate the keyset:

```sh
nazo-oauth-keyctl validate
```

Register a non-exportable KMS/HSM key by storing only its public JWK and provider reference:

```sh
nazo-oauth-keyctl register-external \
  --kid rs256-kms-2026-06 \
  --alg RS256 \
  --key-ref kms://prod/oauth/rs256-kms-2026-06 \
  --public-jwk /secure/exported-public-jwk.json
nazo-oauth-keyctl validate
nazo-oauth-keyctl activate rs256-kms-2026-06
```

When the active key uses `backend: external-command`, configure `SIGNING_EXTERNAL_COMMAND` to the signer argv. The signer receives JSON on stdin with `kid`, `alg`, `key_ref`, and the compact-JWS `signing_input`, and returns `{"signature":"<base64url-signature>"}` on stdout. Signing failures return protocol `server_error`; the server does not fall back to unsigned tokens or plain query responses.

The keyset uses atomic file replacement. On Unix platforms, private key PEM files are written with `0600` permissions. Retired keys are not published in JWKS, and the active key cannot be retired.

## Local Checks

Run the standard local gates:

```sh
cargo fmt --check
cargo check
cargo clippy -- -D warnings
cargo test --locked
```

Run local Rust coverage with `cargo-llvm-cov`:

```sh
cargo install cargo-llvm-cov
cargo test --workspace --all-features
cargo llvm-cov --workspace --all-features --all-targets --no-rustc-wrapper --no-report
cargo llvm-cov report --html \
  --ignore-filename-regex '(^|/)(tests?|benches|examples|migrations)(/|\.rs$)|src/(schema|db)\.rs$|src/domain/rows\.rs$|src/bootstrap/routes\.rs$|src/main\.rs$|src/bin/nazo_oauth_(keyctl|migrate|seed_oidf)\.rs$'
cargo llvm-cov report --lcov --output-path lcov.info \
  --ignore-filename-regex '(^|/)(tests?|benches|examples|migrations)(/|\.rs$)|src/(schema|db)\.rs$|src/domain/rows\.rs$|src/bootstrap/routes\.rs$|src/main\.rs$|src/bin/nazo_oauth_(keyctl|migrate|seed_oidf)\.rs$'
```

Coverage is used as a security signal, not a cosmetic target. Codecov is
configured for an 80% project target and a 90% patch target so changes improve
meaningful coverage without forcing artificial tests for generated schema,
migrations, examples, benches, test sources, Diesel row projection structs,
connection-pool glue, route table wiring, binary entry wrappers, or local OIDF
seed tooling. Protocol handlers, token issuance/validation, client
authentication, PKCE, DPoP, mTLS, PAR/JAR/JARM, resource-server verification,
repository state transitions, settings validation, and OAuth/OIDC error mapping
must not be excluded.
Test files are excluded from coverage accounting so split-out tests measure
production-code coverage rather than inflating totals with test implementation
lines.
Integration tests live directly under `tests/*.rs`. Unit tests that must access
private or `pub(crate)` implementation boundaries live under `tests/unit/src/**`
and are mounted from the owning module with `#[cfg(test)]`; this keeps test
source out of `src/` without widening production APIs just for tests.
Security-critical protocol logic such as authorization-code exchange, PKCE,
client authentication, DPoP, mTLS, JWT/JWK validation, refresh-token rotation,
and OAuth error mapping should use behavior-oriented tests with exact error and
state assertions.

Run deterministic HTTP and race-condition checks:

```sh
python scripts/full_real_request_e2e.py
python scripts/full_real_request_load.py
```

The `conformance-security` GitHub Actions workflow runs format, check, clippy,
tests, a real HTTP matrix, load/race checks, and a Valkey outage injection
check for implementation-affecting changes.

It also runs the supply-chain gate: `cargo audit`, `cargo deny`, CycloneDX SBOM
generation, container build, and Trivy image scanning. Tagged `v*` releases run
the separate `release-security` workflow for release binaries, SBOM artifact
upload, keyless artifact signing, and GitHub provenance attestations.

## OpenID Foundation Suite

The full OIDF workflow is
[.github/workflows/oidf-conformance-full.yml](.github/workflows/oidf-conformance-full.yml).
It runs the official OpenID Foundation Conformance Suite runner against a public
HTTPS deployment and exports per-plan result archives.

Required GitHub secret:

- `OIDF_CONFORMANCE_TOKEN`

Plan configuration can be provided either as `OIDF_PLAN_CONFIG_JSON` or chunked gzip+base64 secrets named `OIDF_PLAN_CONFIG_JSON_GZ_B64_01` through `OIDF_PLAN_CONFIG_JSON_GZ_B64_10`.

Common variables:

| Variable | Default |
| --- | --- |
| `OIDF_CONFORMANCE_SERVER` | `https://www.certification.openid.net/` |
| `OIDF_CONFORMANCE_SUITE_REF` | `master` |
| `OIDF_EXPORT_RESULTS` | `true` |
| `OIDF_VERBOSE` | `true` |
| `OIDF_DISABLE_SSL_VERIFY` | `false` |
| `OIDF_RUN_TIMEOUT_SECONDS` | `14400` |
| `OIDF_MONITOR_INTERVAL_SECONDS` | `60` |

The pass condition is stricter than a triggered workflow: GitHub Actions must conclude `success`, all suite plans must finish with `0 failures` and `0 warnings`, and the durable record under `docs/conformance` must be updated before the artifact expires.

## Deployment

Production deployment requires HTTPS, stable issuer metadata, PostgreSQL backups, Valkey availability, key rotation, strict trusted-proxy configuration, and live endpoint verification. See [docs/deployment.md](docs/deployment.md).

## Security Boundaries

The implementation enforces these boundaries:

- Exact issuer, redirect URI, PKCE, client, and token binding checks.
- Refresh token rotation and token-family reuse detection.
- DPoP and mTLS sender-constrained token paths.
- Replay prevention for authorization codes, DPoP proofs, client assertions, and request objects.
- ASCII-safe OAuth protocol error descriptions.
- No-store token and protocol error responses.
- Explicit trusted proxy configuration before forwarded headers are trusted.

Refresh-token rotation for non-FAPI compatibility profiles is documented in [docs/refresh-token-rotation.md](docs/refresh-token-rotation.md). FAPI2 Security deployments do not use routine rotation by default; refresh grants still require confidential client authentication and the configured DPoP or mTLS proof, and newly issued access tokens remain sender-constrained.

The default deployment is single-tenant with tenant-aware schema boundaries. TOTP MFA, WebAuthn/passkeys, external OIDC/SAML federation, SCIM provisioning with hashed/scoped/audited database tokens, and Rust resource-server middleware are implemented. Dynamic Client Registration, Client Configuration Management, Device Authorization Grant, Token Exchange, and request-level multi-issuer tenant routing are outside the default scope; see [docs/ecosystem-onboarding.md](docs/ecosystem-onboarding.md), [docs/tenancy.md](docs/tenancy.md), and [docs/oauth2-1-self-audit.md](docs/oauth2-1-self-audit.md).
