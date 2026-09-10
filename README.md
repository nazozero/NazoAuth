<div align="center">
  <h1>NazoAuth</h1>
  <p>OAuth 2.0 and OpenID Connect, written in Rust.</p>
  <p>
    <a href="https://github.com/nazozero/NazoAuth/actions/workflows/code-quality.yml"><img src="https://github.com/nazozero/NazoAuth/actions/workflows/code-quality.yml/badge.svg?branch=main" alt="Code quality"></a>
    <a href="https://github.com/nazozero/NazoAuth/releases"><img src="https://img.shields.io/github/v/release/nazozero/NazoAuth?label=release" alt="Latest release"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0--or--later-2563eb" alt="AGPL-3.0-or-later"></a>
  </p>
  <p>
    <a href="docs/operations/one-click-update.md">Deploy</a> ·
    <a href="#openid-certified">Certifications</a> ·
    <a href="docs/integration/openid-connect.md">Connect an application</a> ·
    <a href="docs/protocol/rfc-compliance-matrix.md">Protocol status</a> ·
    <a href="README.zh-CN.md">简体中文</a>
  </p>
</div>

NazoAuth runs sign-in, token issuance, and client access under your own issuer.
It includes passkeys, MFA, tenant routing, and external identity providers.
Its protocol and business cores access persistent and transient state through
storage interfaces. Concrete adapters provide the storage implementation.

> [!WARNING]
> **Before 0.5.0, this project iterates rapidly. Version updates do not preserve
> compatibility with historical releases.** Configuration, stored state,
> administrative interfaces, and control messages follow the current format.
> Back up a deployment before upgrading and follow the target release's setup
> requirements. Historical format readers and conversion layers are not maintained.

## OpenID Certified

<p align="center">
  <a href="https://openid.net/certification/"><img src="https://openid.net/wordpress-content/uploads/2016/04/oid-l-certification-mark-l-rgb-150dpi-90mm-300x157.png" width="180" alt="OpenID Certified — Nazo Auth Server 0.2.0"></a>
</p>

The OpenID Foundation's public certification directory lists **NazoAuth / Nazo
Auth Server 0.2.0** for the following **29 conformance profiles**. Each link
opens the official register, including the certification and test-result records.

| Certification | Certified profiles | Registered |
| --- | --- | --- |
| [OpenID Provider](https://openid.net/certification/certified-openid-providers-profiles/) | `Basic OP` · `Config OP` · `Form Post OP` · `3rd Party-Init OP` | 2026-07-29 |
| [OpenID Connect Logout](https://openid.net/certification/certified-openid-providers-for-logout-profiles/) | `RP-Initiated OP` · `Session OP` · `Front-Channel OP` · `Back-Channel OP` | 2026-07-29 |
| [FAPI 2.0 Security Profile Final](https://openid.net/certification/certified-fapi-2-0-op-security-profile-final-message-signing-final/) | `FAPI2SP OP MTLS + MTLS`<br>`FAPI2SP OP MTLS + DPoP`<br>`FAPI2SP OP private key + MTLS`<br>`FAPI2SP OP private key + DPoP`<br>`FAPI2SP OP OpenID Connect` | 2026-07-29 |
| [FAPI 2.0 Message Signing Final](https://openid.net/certification/certified-fapi-2-0-op-security-profile-final-message-signing-final/) | `FAPI2MS OP JAR` · `FAPI2MS OP JARM` | 2026-07-29 |
| [FAPI 2.0 Client Credentials](https://openid.net/certification/certified-fapi-2-0-op-security-profile-final-message-signing-final/) | `FAPI2SP OP Client Credentials MTLS + MTLS`<br>`FAPI2SP OP Client Credentials MTLS + DPoP`<br>`FAPI2SP OP Client Credentials private key + MTLS`<br>`FAPI2SP OP Client Credentials private key + DPoP` | 2026-07-29 |
| [FAPI-CIBA](https://openid.net/certification/certified-fapi-ciba-openid-providers-profiles/) | `FAPI-CIBA OP Poll w/ MTLS`<br>`FAPI-CIBA OP Poll w/ Private Key`<br>`FAPI-CIBA OP Ping w/ MTLS`<br>`FAPI-CIBA OP Ping w/ Private Key` | 2026-07-29 |
| [**OID4VCI 1.0 + HAIP 1.0**](https://openid.net/certification/certified-oid4vci-haip-final/) | `OID4VCI-1.0+HAIP-1.0 Issuer sd_jwt_vc issuer_initiated`<br>`OID4VCI-1.0+HAIP-1.0 Issuer sd_jwt_vc wallet_initiated`<br>`OID4VCI-1.0+HAIP-1.0 Issuer mdoc issuer_initiated`<br>`OID4VCI-1.0+HAIP-1.0 Issuer mdoc wallet_initiated` | 2026-08-21 |
| [**OID4VP 1.0 + HAIP 1.0**](https://openid.net/certification/certified-oid4vp-haip-final/) | `OID4VP-1.0+HAIP-1.0 Verifier sd_jwt_vc direct_post.jwt`<br>`OID4VP-1.0+HAIP-1.0 Verifier iso_mdl direct_post.jwt` | 2026-08-23 |

The OID4VCI and OID4VP registers spell the implementation version `v0.2.0`.
The certification mark and scope above refer to these registered deployments.

## What it handles

| Area | Capabilities |
| --- | --- |
| Application access | Authorization Code with PKCE, client credentials, rotating refresh tokens, token introspection and revocation, device authorization, CIBA poll/ping |
| Request and token protection | PAR, JAR, JARM, DPoP, mTLS, per-client security policy, FAPI 2.0 controls |
| Sign-in | Passwords, passkeys, TOTP MFA, external OIDC providers, QQ/WeChat adapters, a trusted SAML gateway |
| Tenants | Host-based issuer routing, tenant-scoped service graphs, signing keys, clients, sessions, and storage |
| Identity administration | Account profiles, client and grant management, SCIM provisioning, security events |
| Digital credentials | OpenID4VCI issuance and OpenID4VP presentation, with configured credential profiles and trust material |

A published capability still needs client authorization. The
[capability policy](docs/protocol/composable-capability-policy.md) describes
defaults, prerequisites, and per-client controls. Implicit, hybrid, password
grants, unsigned Request Objects, and CIBA push are not supported.

## Deploy

Use [NazoAuthCtl](https://github.com/nazozero/NazoAuthCtl) to install and operate a
release on a local or SSH host. Choose Docker, Podman, or a host binary. The
current distribution uses the PostgreSQL and Valkey adapters. Prepare a public
HTTPS issuer, PostgreSQL with separate runtime and lifecycle roles, and Valkey.

<details>
<summary><strong>Install on an SSH host</strong></summary>

Install NazoAuthCtl on both ends first; the remote helper must match the
controller build. Use an existing OpenSSH alias and replace the release-tag
placeholder with the signed release you intend to deploy.

~~~sh
nazoauthctl host add production-host --ssh production --privilege sudo

nazoauthctl install \
  --host production-host --name production \
  --to '<nazoauth-release-tag>' \
  --runtime podman --public-url https://auth.example.com \
  --database-host db.internal --database-port 5432 \
  --database-name nazoauth \
  --database-runtime-user nazo_runtime \
  --database-runtime-password-file ./database-runtime-password \
  --database-lifecycle-user nazo_lifecycle \
  --database-lifecycle-password-file ./database-lifecycle-password \
  --valkey-host valkey.internal --valkey-port 6379 \
  --valkey-password-file ./valkey-password

nazoauthctl admin create --instance production
~~~

Sign in at https://auth.example.com/ui/auth and enroll MFA. Then bind the
controller using that administrator account:

~~~sh
nazoauthctl bind --instance production --label operations \
  --output-secret-file ./production-recovery-secret
nazoauthctl verify --instance production
~~~

Keep the recovery secret offline. The first administrator is created through
the target's local deployment authority; controller binding requires that
administrator and fresh MFA approval.

</details>

The [installation guide](docs/operations/one-click-update.md) covers the full
sequence, backup verification, updates, and recovery.
[Deployment](docs/operations/deployment.md) covers TLS, reverse proxies, and
health checks. External databases and Valkey remain under your administration.

## Connect an application

Start with the issuer's discovery document:

~~~text
https://auth.example.com/.well-known/openid-configuration
~~~

Register a client and its exact redirect URIs, then use Authorization Code
with S256 PKCE. The [OIDC integration guide](docs/integration/openid-connect.md)
covers registration, discovery, authorization, tokens, and logout.

Each client has an explicit security policy. Enable the grants and token
protection that the application needs; enabling a server module does not grant
every client access to it.

## Inside the server

One executable composes the protocol cores, identity services, and adapters.
The cores depend on semantic persistence and state interfaces; adapters
implement those contracts and own driver calls, transactions, and storage
mechanics.

~~~mermaid
flowchart TB
    Core["Protocol and identity cores"] --> Ports["Persistence and state interfaces"]
    PG["PostgreSQL adapter"] -. persistence .-> Ports
    VK["Valkey adapter"] -. transient state .-> Ports
~~~

PostgreSQL and Valkey are the currently implemented adapters, not requirements
of the core architecture. The composition root selects them; the protocol and
business crates do not depend on their drivers. Avatar storage has separate
local and S3-compatible adapters.

Tenant selection happens before request handlers run. Each active tenant has
its own service graph and signing-key lifecycle. Host routing uses an
immutable in-process index; unknown hosts are rejected. See
[architecture](docs/project/architecture.md) and
[tenant boundaries](docs/features/tenancy.md) for the ownership rules.

## Development and verification

Use the repository's pinned Rust toolchain. Tests that exercise PostgreSQL,
Valkey, and object storage need the isolated services and fixture configuration
defined in the [quality workflow](.github/workflows/code-quality.yml).

~~~sh
cargo build --release --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
~~~

[Testing](docs/project/testing.md) explains the checks and external test setup.
[Conformance records](docs/conformance/README.md) identify the artifacts and
conditions covered by project regression runs. Official certification profiles
and registration dates are listed in [OpenID Certified](#openid-certified).

## Documentation

| Build an integration | Operate a deployment |
| --- | --- |
| [OIDC integration](docs/integration/openid-connect.md) | [Configuration](docs/operations/configuration.md) |
| [Passkeys](docs/features/passkeys.md) · [MFA](docs/features/mfa.md) | [Deployment and TLS](docs/operations/deployment.md) |
| [Identity federation](docs/features/federation.md) | [High availability](docs/operations/ha-operations.md) |
| [SCIM](docs/features/scim.md) | [Security model](docs/security/threat-model.md) |
| [Protocol coverage](docs/protocol/rfc-compliance-matrix.md) | [Performance measurements](docs/performance/README.md) |

Report vulnerabilities through [SECURITY.md](SECURITY.md). Contribution rules
are in [CONTRIBUTING.md](CONTRIBUTING.md).

Licensed under [AGPL-3.0-or-later](LICENSE).
[Commercial licensing](COMMERCIAL-LICENSE.md) requires a separate agreement.
