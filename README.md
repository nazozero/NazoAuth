# Nazo OAuth Server

Nazo OAuth Server is a Rust-native OAuth 2.1 / OpenID Connect authorization server for self-hosted deployments that need a compact codebase, explicit security boundaries, and repeatable conformance evidence.

The project is intentionally focused on the authorization server surface: authorization code + PKCE, token issuance, refresh-token rotation, PAR, signed request objects, DPoP, mTLS sender constraints, JWKS, discovery, userinfo, token management, and a small built-in identity/admin data plane.

## Status

- Package: `nazo-oauth-server`
- Language: Rust 2024
- Runtime dependencies: PostgreSQL and Valkey
- Main branch policy: work happens on `main`
- Conformance evidence: see [docs/conformance](docs/conformance)
- Deployment guide: see [docs/deployment.md](docs/deployment.md)
- PostgreSQL and Valkey operations: see [docs/ha-operations.md](docs/ha-operations.md)
- Roadmap: see [docs/roadmap.md](docs/roadmap.md)
- Security policy: see [SECURITY.md](SECURITY.md)
- Release security: see [docs/release-security.md](docs/release-security.md)
- Change history: see [CHANGELOG.md](CHANGELOG.md)

This repository is not yet a full IAM suite like Keycloak, ZITADEL, authentik, or Ory Hydra. The current goal is narrower and stricter: become one of the most trustworthy and standards-compatible OAuth2 / OpenID Connect authorization server implementations in the Rust ecosystem.

## Features

- OAuth authorization code flow with S256 PKCE.
- Refresh token rotation, token family reuse detection, and atomic authorization code consumption.
- Client credentials, refresh token, revocation, and introspection endpoints.
- OpenID Connect discovery, OAuth Authorization Server Metadata, JWKS, ID Token, and UserInfo.
- PAR and JAR support, including signed request objects with `EdDSA`, `RS256`, `ES256`, and `PS256`.
- `client_secret_basic`, compatibility `client_secret_post`, `private_key_jwt`, public clients, and mTLS client authentication. High-security clients should use `private_key_jwt` or mTLS rather than `client_secret_post`.
- DPoP proof validation, nonce handling, sender-constrained access tokens, and DPoP-bound UserInfo.
- mTLS sender-constrained access tokens through a trusted reverse-proxy certificate forwarding boundary.
- Server signing key rotation with active and previous JWKS publication.
- Pairwise subject support.
- Cookie sessions, CSRF protection, security response headers, and structured audit events.
- HTTPOnly session cookie flow; login responses do not expose session identifiers in JSON.
- PostgreSQL persistence with Rust-native migrations.
- Valkey-backed sessions, security state, replay prevention, PAR handles, and rate limiting.
- User, profile, avatar, OAuth client, grant, and access-request management APIs.
- RFC 8707 `resource` parameter support for token requests, mapped to the current single-audience access-token model. The older `audience` parameter remains as a project extension.

## Conformance

The project maintains durable conformance records in Git instead of relying only on GitHub Actions artifacts, which expire. The latest recorded OpenID Foundation run covers a 16-plan matrix across OIDC Basic, OIDC Config, FAPI2 Security Profile Final, FAPI2 Message Signing Final, mTLS, DPoP, `private_key_jwt`, and client credentials variants:

- [2026-06-06 OIDF full matrix](docs/conformance/2026-06-06-oidf-full-matrix.md)

The recorded workflow conclusion was `success`, with every matrix plan completing with `0 failures` and `0 warnings`. The record includes commit SHA, workflow run URL, job URL, artifact name, artifact digest, artifact expiry, plan IDs, exported artifact filenames, profile combinations, and pass counts.

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

## Requirements

- Rust toolchain compatible with edition 2024
- PostgreSQL 18 or compatible PostgreSQL server
- Valkey 8 or compatible Redis protocol server
- Docker or Podman for containerized local integration

## Quick Start

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

## Configuration

Configuration precedence is:

```text
defaults < .env.yaml < process environment variables
```

Only explicitly allowlisted environment variables are accepted. A `.env` file is deliberately unsupported; if `.env` exists, the service refuses to start. Use `.env.yaml` for local or deployment configuration and do not commit real secrets.

Important settings:

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

See [.env.yaml.example](.env.yaml.example) for the complete field list.

When `AUTHORIZATION_SERVER_PROFILE` is set to `fapi2-security`, the server requires PAR, confidential clients, `private_key_jwt` or mTLS client authentication, sender-constrained access tokens, and authorization code lifetimes of 60 seconds or less. `fapi2-message-signing-authz-request` adds signed request objects at PAR. Discovery metadata is generated from the active profile and mTLS proxy configuration; mTLS capabilities are not advertised unless `TRUSTED_PROXY_CIDRS` is configured.

## Protocol Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Health check |
| `GET` | `/authorize` | Authorization endpoint |
| `GET` | `/authorize/consent` | Consent page data |
| `POST` | `/authorize/decision` | Consent decision |
| `POST` | `/par` | Pushed Authorization Request |
| `POST` | `/token` | Token endpoint |
| `POST` | `/revoke` | Token revocation |
| `POST` | `/introspect` | Token introspection |
| `GET` | `/.well-known/openid-configuration` | OIDC discovery |
| `GET` | `/.well-known/oauth-authorization-server` | OAuth server metadata |
| `GET` | `/jwks.json` | JWKS |
| `GET` | `/userinfo` | OIDC UserInfo |

The token endpoint accepts the standard RFC 8707 `resource` parameter for a single absolute URI without a fragment and maps it to the access-token audience. The legacy `audience` parameter is still accepted as a project extension, but a request must not send both.

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

The keyset uses atomic file replacement. On Unix platforms, private key PEM files are written with `0600` permissions. Retired keys are not published in JWKS, and the active key cannot be retired.

## Development

Run the standard local gates:

```sh
cargo fmt --check
cargo check
cargo clippy -- -D warnings
cargo test --locked
```

Run deterministic HTTP and race-condition checks:

```sh
python scripts/full_real_request_e2e.py
python scripts/full_real_request_load.py
```

The `conformance-security` GitHub Actions workflow runs format, check, clippy, tests, a real HTTP matrix, load/race checks, and a Valkey outage injection check.

It also runs the supply-chain gate: `cargo audit`, `cargo deny`, CycloneDX SBOM generation, container build, and Trivy image scanning. Tagged `v*` releases run the separate `release-security` workflow for release binaries, SBOM artifact upload, keyless artifact signing, and GitHub provenance attestations.

## OpenID Foundation Suite

The full OIDF workflow is [.github/workflows/oidf-conformance-full.yml](.github/workflows/oidf-conformance-full.yml). It runs the official OpenID Foundation Conformance Suite runner against a public HTTPS deployment and exports per-plan result archives.

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

## Security Posture

Current high-priority boundaries:

- Exact issuer, redirect URI, PKCE, client, and token binding checks.
- Refresh token rotation and token-family reuse detection.
- DPoP and mTLS sender-constrained token paths.
- Replay prevention for authorization codes, DPoP proofs, client assertions, and request objects.
- ASCII-safe OAuth protocol error descriptions.
- No-store token and protocol error responses.
- Explicit trusted proxy configuration before forwarded headers are trusted.

Refresh-token rotation for non-FAPI compatibility profiles is documented in [docs/refresh-token-rotation.md](docs/refresh-token-rotation.md). FAPI2 Security deployments should prefer sender-constrained refresh/access tokens and should not use routine rotation by default.

Known roadmap items are tracked in [docs/roadmap.md](docs/roadmap.md), [CHANGELOG.md](CHANGELOG.md), and future conformance records. Priority areas include fuller OIDC claims request semantics, ACR/AMR policy, WebAuthn/passkeys, Dynamic Client Registration, RAR, broader RFC 8707 multi-resource support, release signing, SBOM/provenance, and deeper supply-chain verification.
