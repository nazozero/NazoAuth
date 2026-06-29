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

[中文文档](README.zh-CN.md) · [Documentation](#documentation) · [Quick start](#quick-start) · [Security](SECURITY.md)

Nazo Auth Server is a self-hosted OAuth 2.1 and OpenID Connect authorization
server written in Rust. It is built for same-origin deployments where the
issuer, browser UI, passkeys, CORS, cookies, and protocol endpoints share one
public origin.

The project includes the authorization server, a compact identity/admin surface,
local signing key management, WebAuthn/passkeys, MFA, external federation, SCIM,
and Rust resource-server verification libraries. It uses PostgreSQL for durable
state and Valkey for short-lived protocol state.

## Status

| Item | Value |
| --- | --- |
| Package | `nazo-oauth-server` |
| Version | `0.1.0` |
| License | AGPL-3.0-or-later |
| Language | Rust 2024 |
| Runtime services | PostgreSQL, Valkey |
| Certified public issuer | `https://auth.nazo.run` |
| Default deployment model | same-origin |

## Standards

Nazo Auth Server implements and tests the core standards expected from a modern
authorization server. Compatibility exceptions are documented instead of hidden
behind discovery metadata.

IETF and RFCs:

| Standard | Implementation |
| --- | --- |
| [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749), OAuth 2.0 | authorization code, refresh token, and client credentials grants |
| [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750), Bearer Token Usage | bearer access-token handling |
| [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009), Token Revocation | `/revoke` |
| [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523), JWT Client Authentication | `private_key_jwt` |
| [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636), PKCE | S256 PKCE |
| [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662), Token Introspection | `/introspect` |
| [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414), Authorization Server Metadata | `/.well-known/oauth-authorization-server` |
| [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705), OAuth 2.0 mTLS | mTLS client auth and sender-constrained tokens |
| [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707), Resource Indicators | `resource` and JWT `aud` binding |
| [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068), JWT Access Tokens | JWT access-token shape for resource servers |
| [RFC 9101](https://www.rfc-editor.org/rfc/rfc9101), JAR | signed request objects where enabled |
| [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126), PAR | `/par` |
| [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396), Rich Authorization Requests | behind `ENABLE_AUTHORIZATION_DETAILS` |
| [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449), DPoP | proof validation and sender-constrained tokens |
| OAuth 2.1 draft direction | OAuth 2.1-style defaults with explicit compatibility switches |

OpenID Foundation:

| Specification | Implementation |
| --- | --- |
| [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) | ID Token, UserInfo, claims, authorization code flow |
| [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) | `/.well-known/openid-configuration` |
| [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) | `/logout` |
| [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html) | best-effort logout notifications |
| [JWT Secured Authorization Response Mode](https://openid.net/specs/oauth-v2-jarm.html) | JARM where advertised by the active profile |
| [FAPI 2.0 Security Profile Final](https://openid.net/specs/fapi-2_0-security-profile-final.html) | `fapi2-security` profile |
| [FAPI 2.0 Message Signing Final](https://openid.net/specs/fapi-2_0-message-signing-final.html) | signed authorization request and JARM profile support |

Other protocol surfaces:

| Standard | Implementation |
| --- | --- |
| SCIM 2.0, [RFC 7643](https://www.rfc-editor.org/rfc/rfc7643) and [RFC 7644](https://www.rfc-editor.org/rfc/rfc7644) | default-tenant user provisioning |
| WebAuthn | passkey registration and login |

## Certification

Nazo Auth Server is listed by the OpenID Foundation as
`Nazo Auth Server 0.1.0`, dated `09-Jun-2026`.

- [OpenID Connect Certified providers](https://openid.net/certification/#OPs)
- [Certified OpenID Provider profiles](https://openid.net/certification/certified-openid-providers-profiles/)
- [Certified FAPI 2.0 OP Security Profile Final and Message Signing Final](https://openid.net/certification/certified-fapi-2-0-op-security-profile-final-message-signing-final/)

Durable records are kept in [docs/conformance](docs/conformance). The latest
official full matrix tested `https://auth.nazo.run` at runtime commit
`be7ef9f6a9197520235a59d42866a0918a293014`, exported all 16 plan archives, and
reported `0 failures` and `0 warnings`.

## Features

- Authorization code + PKCE, refresh tokens, client credentials, revocation,
  introspection, discovery, JWKS, UserInfo, PAR, JAR, DPoP, and mTLS.
- Runtime profiles: `oauth2-baseline`, `fapi2-security`, and
  `fapi2-message-signing-authz-request`.
- Local users, profiles, OAuth clients, grants, access requests, TOTP MFA,
  backup codes, remembered MFA, WebAuthn/passkeys, external OIDC/SAML
  federation, and SCIM provisioning.
- Local signing key lifecycle with prepublish, active, grace, and retired
  states. External-command signing is available for KMS/HSM integrations.
- Rust resource-server verifier with Actix Web, Axum/Tower, and tonic adapters.
- Release security workflows for CodeQL, dependency review, cargo audit,
  cargo deny, SBOM generation, Trivy image scanning, OpenSSF Scorecard,
  keyless signing, and provenance attestations.

## Quick start

Requirements:

- Rust toolchain compatible with edition 2024
- PostgreSQL 18 or a compatible PostgreSQL server
- Valkey 8 or a compatible Redis protocol server
- Docker or Podman for the local integration stack

Run with Docker Compose:

```sh
cp .env.yaml.example .env.yaml
docker compose up -d nazo_oauth_server
curl -fsS http://127.0.0.1:8000/health
curl -fsS http://127.0.0.1:8000/.well-known/openid-configuration
```

Run directly on the host after pointing `.env.yaml` at reachable PostgreSQL and
Valkey services:

```sh
cargo run --bin nazo-oauth-migrate
cargo run --bin nazo-oauth-server
```

## Configuration

Configuration is intentionally small for new deployments:

```yaml
BIND: "0.0.0.0:8000"
PUBLIC_BASE_URL: "https://auth.example.com"
DATABASE_URL: "postgresql://nazo_oauth:<password>@postgres:5432/oauth"
VALKEY_URL: "redis://valkey:6379/0"
DATA_DIR: "/var/lib/nazo_oauth"
AUTHORIZATION_SERVER_PROFILE: "oauth2-baseline"
RUST_LOG: "info"
```

`PUBLIC_BASE_URL` drives the same-origin defaults:

| Value | Default rule |
| --- | --- |
| `ISSUER` | `PUBLIC_BASE_URL` |
| `FRONTEND_BASE_URL` | `PUBLIC_BASE_URL + "/ui/"` |
| `CORS_ALLOWED_ORIGINS` | origin of `PUBLIC_BASE_URL` |
| `COOKIE_SECURE` | `true` for HTTPS issuers |
| `PASSKEY_ORIGIN` and `PASSKEY_RP_ID` | derived from issuer |

`DATA_DIR` drives persistent local file paths:

| Value | Default rule |
| --- | --- |
| `JWK_KEYS_DIR` | `DATA_DIR + "/keys"` |
| `AVATAR_STORAGE_DIR` | `DATA_DIR + "/avatars"` |

Advanced settings still exist for compatibility and specialized deployments.
They are documented in [docs/configuration.md](docs/configuration.md).

## Default boundaries

The following capabilities are outside the default authorization-server surface
and are not advertised unless implemented, tested, and explicitly enabled:

- Dynamic Client Registration / RFC 7591.
- Client Configuration Management / RFC 7592.
- Device Authorization Grant.
- Token Exchange / RFC 8693.
- Request-level dynamic tenant or issuer routing.
- Signed introspection responses.

See [docs/roadmap.md](docs/roadmap.md) for the current scope record.

## Documentation

| Topic | Link |
| --- | --- |
| Configuration | [docs/configuration.md](docs/configuration.md) |
| Deployment | [docs/deployment.md](docs/deployment.md) |
| Chinese deployment guide | [docs/deployment.zh-CN.md](docs/deployment.zh-CN.md) |
| Conformance records | [docs/conformance](docs/conformance) |
| Profile matrix | [docs/profile-matrix.md](docs/profile-matrix.md) |
| Threat model | [docs/threat-model.md](docs/threat-model.md) |
| Release security | [docs/release-security.md](docs/release-security.md) |
| PostgreSQL and Valkey operations | [docs/ha-operations.md](docs/ha-operations.md) |
| Resource server verifier | [docs/resource-server-verifier.md](docs/resource-server-verifier.md) |
| SCIM | [docs/scim.md](docs/scim.md) |
| Federation | [docs/federation.md](docs/federation.md) |
| Passkeys | [docs/passkeys.md](docs/passkeys.md) |
| MFA | [docs/mfa.md](docs/mfa.md) |
| Security policy | [SECURITY.md](SECURITY.md) |
| Changelog | [CHANGELOG.md](CHANGELOG.md) |

## Development

```sh
cargo fmt --check
cargo check
cargo clippy -- -D warnings
cargo test --locked
```

HTTP and concurrency checks:

```sh
python scripts/full_real_request_e2e.py
python scripts/full_real_request_load.py
```

Windows coverage runs are documented in
[docs/coverage/codecov-docker-runbook.md](docs/coverage/codecov-docker-runbook.md).

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
