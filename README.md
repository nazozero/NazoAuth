# Nazo Auth Server

<p align="right">
  <a href="https://openid.net/certification/#OPs">
    <img src="https://openid.net/wordpress-content/uploads/2016/04/oid-l-certification-mark-l-rgb-150dpi-90mm-300x157.png" alt="OpenID Certified" width="140">
  </a>
</p>

[![code-quality](https://github.com/bymoye/NazoAuth/actions/workflows/code-quality.yml/badge.svg?branch=main)](https://github.com/bymoye/NazoAuth/actions/workflows/code-quality.yml)
[![codeql](https://github.com/bymoye/NazoAuth/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/bymoye/NazoAuth/actions/workflows/codeql.yml)
[![dependency-review](https://github.com/bymoye/NazoAuth/actions/workflows/dependency-review.yml/badge.svg?branch=main)](https://github.com/bymoye/NazoAuth/actions/workflows/dependency-review.yml)
[![conformance-security](https://github.com/bymoye/NazoAuth/actions/workflows/conformance-security.yml/badge.svg?branch=main)](https://github.com/bymoye/NazoAuth/actions/workflows/conformance-security.yml)
[![oidf-conformance-full](https://github.com/bymoye/NazoAuth/actions/workflows/oidf-conformance-full.yml/badge.svg?branch=main)](https://github.com/bymoye/NazoAuth/actions/workflows/oidf-conformance-full.yml)
[![codecov](https://codecov.io/gh/bymoye/NazoAuth/branch/main/graph/badge.svg)](https://app.codecov.io/gh/bymoye/NazoAuth)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/bymoye/NazoAuth/badge)](https://scorecard.dev/viewer/?uri=github.com/bymoye/NazoAuth)

[中文文档](README.zh-CN.md)

**Links:** [Documentation](#documentation) · [Quick start](#quick-start) ·
[Configuration](#configuration) · [Conformance](#conformance) ·
[Deployment](docs/deployment.md) · [Security](SECURITY.md)

Nazo Auth Server is a self-hosted OAuth 2.1 and OpenID Connect authorization
server written in Rust. It runs the authorization, token, discovery, JWKS,
UserInfo, session, and admin surfaces needed for a small production identity
service.

The project is built around explicit protocol profiles. Baseline OAuth/OIDC can
run in compatibility mode, while FAPI2 profiles require PAR, PKCE, confidential
clients, signed request objects where configured, and DPoP or mTLS sender
constraints.

## Contents

- [At a glance](#at-a-glance)
- [What it includes](#what-it-includes)
- [What is out of scope by default](#what-is-out-of-scope-by-default)
- [Standards and profiles](#standards-and-profiles)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Endpoints](#endpoints)
- [Keys](#keys)
- [Conformance](#conformance)
- [Development checks](#development-checks)
- [OpenID Foundation suite](#openid-foundation-suite)
- [Deployment](#deployment)
- [Documentation](#documentation)
- [License](#license)

## At a glance

| Item | Value |
| --- | --- |
| Package | `nazo-oauth-server` |
| Language | Rust 2024 |
| License | AGPL-3.0-or-later |
| State | Authorization server with local identity/admin APIs |
| Runtime services | PostgreSQL, Valkey |
| Public certified issuer | `https://auth.nazo.run` |
| Main branch | `main` |

## What it includes

- Authorization code flow with S256 PKCE.
- Token, refresh, revocation, introspection, UserInfo, JWKS, and discovery endpoints.
- PAR and signed request object support.
- `client_secret_basic`, compatibility `client_secret_post`, `private_key_jwt`, public clients, and mTLS client authentication.
- DPoP and mTLS sender-constrained access tokens.
- Refresh-token rotation for compatibility profiles, with token-family reuse detection.
- OIDC RP-Initiated Logout and back-channel logout notifications.
- Pairwise subject identifiers.
- RFC 8707 `resource` parameter support.
- RFC 9396-style `authorization_details` behind an explicit feature flag.
- Cookie sessions, CSRF protection, security headers, rate limiting, and structured audit events.
- User, profile, avatar, OAuth client, grant, MFA, passkey, federation, SCIM, and access-request APIs.
- Rust resource-server verifier core with Actix Web, Axum/Tower, and tonic adapters.
- Local signing key lifecycle plus optional external-command signing for KMS/HSM integration.

## What is out of scope by default

These features are not advertised by default and need a separate threat model
before being enabled:

- Dynamic Client Registration / RFC 7591.
- Client Configuration Management / RFC 7592.
- Device Authorization Grant.
- Token Exchange / RFC 8693.
- Request-level multi-issuer tenant routing.
- Signed introspection responses.

See [docs/roadmap.md](docs/roadmap.md) and
[docs/ecosystem-onboarding.md](docs/ecosystem-onboarding.md) for the current
scope record.

## Standards and profiles

The active authorization-server profile is selected with
`AUTHORIZATION_SERVER_PROFILE`. Discovery metadata is generated from the active
profile and deployment settings instead of being a static document.

IETF and RFC-aligned protocol support:

| Standard | Status |
| --- | --- |
| OAuth 2.0 Authorization Framework / [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) | authorization code, refresh token, and client credentials grants |
| Bearer Token Usage / [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) | bearer access-token handling |
| PKCE / [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) | S256 PKCE for authorization code clients |
| Token Revocation / [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009) | `/revoke` endpoint |
| Token Introspection / [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662) | `/introspect` endpoint |
| OAuth 2.0 Authorization Server Metadata / [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) | `/.well-known/oauth-authorization-server` |
| JWT Profile for Client Authentication / [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523) | `private_key_jwt` client authentication |
| OAuth 2.0 mTLS / [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705) | mTLS client auth and sender-constrained access tokens |
| Resource Indicators / [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) | `resource` request parameter and JWT `aud` binding |
| JWT-Secured Authorization Request / [RFC 9101](https://www.rfc-editor.org/rfc/rfc9101) | signed request objects where enabled |
| Pushed Authorization Requests / [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126) | `/par` endpoint |
| JWT Profile for Access Tokens / [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) | JWT access-token shape for resource servers |
| DPoP / [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) | DPoP proof validation and sender-constrained tokens |
| Rich Authorization Requests / [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396) | behind `ENABLE_AUTHORIZATION_DETAILS` |
| OAuth 2.1 draft direction | OAuth 2.1-style defaults, with compatibility exceptions documented explicitly |

OpenID Foundation protocol support:

| Specification | Status |
| --- | --- |
| [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) | ID Token, UserInfo, claims, and standard OIDC authorization flows |
| [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) | `/.well-known/openid-configuration` |
| [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) | `/logout` endpoint |
| [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html) | best-effort back-channel logout notifications |
| [JWT Secured Authorization Response Mode](https://openid.net/specs/oauth-v2-jarm.html) | JARM where advertised by the active profile |
| [FAPI 2.0 Security Profile Final](https://openid.net/specs/fapi-2_0-security-profile-final.html) | enforced profile for FAPI2 deployments |
| [FAPI 2.0 Message Signing Final](https://openid.net/specs/fapi-2_0-message-signing-final.html) | signed authorization request and JARM profile support |

Certification:

| Program | Evidence |
| --- | --- |
| [OpenID Connect Certified](https://openid.net/certification/#OPs) | listed as `Nazo Auth Server 0.1.0`, dated `09-Jun-2026` |
| OpenID Provider certification plans | OIDC Basic OP and OIDC Config OP records under [docs/conformance](docs/conformance) |
| FAPI 2.0 certification plans | FAPI2 Security Profile Final and FAPI2 Message Signing Final records under [docs/conformance](docs/conformance) |

Other implemented protocol surfaces:

| Standard | Status |
| --- | --- |
| SCIM 2.0 / [RFC 7643](https://www.rfc-editor.org/rfc/rfc7643), [RFC 7644](https://www.rfc-editor.org/rfc/rfc7644) | default-tenant user provisioning APIs |
| WebAuthn | passkey registration and login flows |

## Quick start

Requirements:

- Rust toolchain compatible with edition 2024
- PostgreSQL 18 or a compatible PostgreSQL server
- Valkey 8 or a compatible Redis protocol server
- Docker or Podman for the local integration stack

Create local configuration:

```sh
cp .env.yaml.example .env.yaml
```

Start the service with Docker Compose:

```sh
docker compose up -d nazo_oauth_server
```

Check the service:

```sh
curl -fsS http://127.0.0.1:8000/health
curl -fsS http://127.0.0.1:8000/.well-known/openid-configuration
```

For a direct host run, point `DATABASE_URL` and `VALKEY_URL` in `.env.yaml` at
host-reachable services, then run:

```sh
cargo run --bin nazo-oauth-migrate
cargo run --bin nazo-oauth-server
```

## Configuration

Configuration is loaded in this order:

```text
defaults < .env.yaml < process environment variables
```

Only allowlisted environment variables are accepted. A `.env` file is not
supported; if one exists, the server refuses to start.

The default deployment is same-origin. Configure `PUBLIC_BASE_URL` once; the
server derives the issuer, UI URL, passkey origin, CORS origin, and persistent
subdirectories from it.

Minimal settings:

| Setting | Default | Notes |
| --- | --- | --- |
| `BIND` | `0.0.0.0:8000` | HTTP listener |
| `PUBLIC_BASE_URL` | `http://127.0.0.1:8000` | Public same-origin base URL |
| `DATABASE_URL` | `postgresql://postgres:postgres@127.0.0.1:5432/oauth` | PostgreSQL connection string |
| `VALKEY_URL` | `redis://127.0.0.1:6379/0` | Valkey connection string |
| `DATA_DIR` | `runtime` | Base directory for persistent files |
| `AUTHORIZATION_SERVER_PROFILE` | `oauth2-baseline` | `oauth2-baseline`, `fapi2-security`, or `fapi2-message-signing-authz-request` |
| `RUST_LOG` | `info` | Tracing filter |

Derived defaults:

| Value | Rule |
| --- | --- |
| `ISSUER` | `PUBLIC_BASE_URL` |
| `FRONTEND_BASE_URL` | `PUBLIC_BASE_URL + "/ui/"` |
| `CORS_ALLOWED_ORIGINS` | origin of `PUBLIC_BASE_URL` |
| `PASSKEY_ORIGIN` / `PASSKEY_RP_ID` | derived from issuer |
| `JWK_KEYS_DIR` | `DATA_DIR + "/keys"` |
| `AVATAR_STORAGE_DIR` | `DATA_DIR + "/avatars"` |

See [.env.yaml.example](.env.yaml.example) and
[docs/configuration.md](docs/configuration.md).

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

The token endpoint accepts RFC 8707 `resource` as the standard audience input.
The legacy `audience` parameter is rejected unless
`ENABLE_LEGACY_AUDIENCE_PARAM=true`.

## Keys

Startup creates a local RS256 signing key if `keyset.json` does not exist. The
key lifecycle supports prepublished, active, grace, and retired states. Retired
keys are removed from JWKS after the longest relevant token lifetime has passed.

Validate the keyset:

```sh
nazo-oauth-keyctl validate
```

Register an external key by storing its public JWK and provider reference:

```sh
nazo-oauth-keyctl register-external \
  --kid rs256-kms-2026-06 \
  --alg RS256 \
  --key-ref kms://prod/oauth/rs256-kms-2026-06 \
  --public-jwk /secure/exported-public-jwk.json
nazo-oauth-keyctl validate
```

When `SIGNING_EXTERNAL_COMMAND` is configured, the server sends signing input to
the command over stdin and verifies the returned signature against the active
public JWK before returning a token.

## Conformance

Nazo Auth Server is listed by the OpenID Foundation as `Nazo Auth Server 0.1.0`,
dated `09-Jun-2026`:

- [Certified OpenID Provider profiles](https://openid.net/certification/certified-openid-providers-profiles/)
- [Certified FAPI 2.0 OP Security Profile Final and Message Signing Final](https://openid.net/certification/certified-fapi-2-0-op-security-profile-final-message-signing-final/)

Durable suite records are kept under [docs/conformance](docs/conformance)
because GitHub Actions artifacts expire. The retained records are:

- [2026-06-09 OIDF full matrix](docs/conformance/2026-06-09-oidf-full-matrix.md)
- [2026-06-26 security findings OIDF full matrix](docs/conformance/2026-06-26-security-findings-full-matrix.md)
- [2026-06-27 PR 15 official OIDF full matrix](docs/conformance/2026-06-27-pr15-official-oidf-full-matrix.md)

The latest official full matrix tested runtime commit
`be7ef9f6a9197520235a59d42866a0918a293014` against `https://auth.nazo.run`.
It exported all 16 plan archives and reported `0 failures` and `0 warnings`.

Baseline OIDC metadata advertises `none` for unsigned Request Object
compatibility. FAPI2, PAR request-object, signed-authorization-request, and
holder-bound-token paths still reject unsigned Request Objects.

## Development checks

Run the normal local checks:

```sh
cargo fmt --check
cargo check
cargo clippy -- -D warnings
cargo test --locked
```

Run HTTP and race-condition checks:

```sh
python scripts/full_real_request_e2e.py
python scripts/full_real_request_load.py
```

Run local Rust coverage with `cargo-llvm-cov`:

```sh
cargo install cargo-llvm-cov
python -m pip install requests "psycopg[binary]" redis argon2-cffi pyjwt cryptography aiosmtpd
bash scripts/generate_codecov_lcov.sh
```

On Windows, use [docs/coverage/codecov-docker-runbook.md](docs/coverage/codecov-docker-runbook.md)
so PostgreSQL, Valkey, Python, and llvm-cov run in one repeatable environment.

## OpenID Foundation suite

The full suite workflow is
[.github/workflows/oidf-conformance-full.yml](.github/workflows/oidf-conformance-full.yml).
It runs the official OpenID Foundation Conformance Suite against a public HTTPS
deployment and exports per-plan archives.

Required GitHub secret:

- `OIDF_CONFORMANCE_TOKEN`

Plan configuration can be provided as `OIDF_PLAN_CONFIG_JSON` or as chunked
gzip+base64 secrets named `OIDF_PLAN_CONFIG_JSON_GZ_B64_01` through
`OIDF_PLAN_CONFIG_JSON_GZ_B64_10`.

## Deployment

Production deployments need:

- `PUBLIC_BASE_URL` set to the exact public HTTPS origin.
- PostgreSQL backups and migration rollback planning.
- Valkey availability for short-lived protocol state.
- Signing key rotation and JWKS prepublication.
- Secure cookies. This is derived from HTTPS by default.
- `TRUSTED_PROXY_CIDRS` before trusting forwarded IP or mTLS headers.
- Live endpoint checks after every deploy.

See [docs/deployment.md](docs/deployment.md) and
[docs/deployment.zh-CN.md](docs/deployment.zh-CN.md).

## Documentation

- [Security policy](SECURITY.md)
- [Configuration](docs/configuration.md)
- [Release security](docs/release-security.md)
- [Profile matrix](docs/profile-matrix.md)
- [Threat model](docs/threat-model.md)
- [Refresh-token rotation](docs/refresh-token-rotation.md)
- [Tenant, realm, and organization boundaries](docs/tenancy.md)
- [PostgreSQL and Valkey operations](docs/ha-operations.md)
- [Resource server verifier](docs/resource-server-verifier.md)
- [SCIM provisioning](docs/scim.md)
- [External identity federation](docs/federation.md)
- [WebAuthn passkeys](docs/passkeys.md)
- [MFA and step-up authentication](docs/mfa.md)
- [Change history](CHANGELOG.md)

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
