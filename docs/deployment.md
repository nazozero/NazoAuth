# Deployment Guide

This guide describes a production-shaped deployment for Nazo OAuth Server. It assumes the service runs behind a TLS-terminating reverse proxy, with PostgreSQL and Valkey managed as persistent infrastructure.

## Deployment Model

Required components:

- `nazo-oauth-server` HTTP process
- `nazo-oauth-migrate` migration command
- PostgreSQL database
- Valkey instance
- persistent JWT key directory
- persistent avatar directory
- HTTPS reverse proxy

The service itself listens on HTTP, typically `0.0.0.0:8000`, and the reverse proxy exposes the public HTTPS issuer.

## Preflight

Before first deployment:

1. Create PostgreSQL database and user.
2. Create Valkey instance and decide persistence / HA policy.
3. Allocate persistent directories for keys and avatars.
4. Create `.env.yaml` outside the repository.
5. Set `ISSUER` to the exact public HTTPS issuer, without a trailing slash.
6. Set `FRONTEND_BASE_URL` and `CORS_ALLOWED_ORIGINS` to real HTTPS origins.
7. Set `COOKIE_SECURE=true`.
8. Configure `TRUSTED_PROXY_CIDRS` only for reverse proxies that you control.
9. Keep `CLIENT_IP_HEADER_MODE=none` until forwarded headers are correctly sanitized by the proxy.
10. Run migrations before serving traffic.

## Minimal Production Configuration

```yaml
BIND: "0.0.0.0:8000"
DATABASE_URL: "postgresql://nazo_oauth:<password>@postgres.example.internal:5432/oauth"
VALKEY_URL: "redis://valkey.example.internal:6379/0"
ISSUER: "https://oauth.example.com"
FRONTEND_BASE_URL: "https://accounts.example.com"
CORS_ALLOWED_ORIGINS:
  - "https://accounts.example.com"
DEFAULT_AUDIENCE: "resource://default"
AUTHORIZATION_SERVER_PROFILE: "oauth2-baseline"
COOKIE_SECURE: true
TRUSTED_PROXY_CIDRS: "10.0.0.0/24"
CLIENT_IP_HEADER_MODE: "forwarded"
SUBJECT_TYPE: "pairwise"
PAIRWISE_SUBJECT_SECRET: "<high-entropy-secret>"
EMAIL_DELIVERY: "smtp"
EMAIL_SMTP_HOST: "smtp.example.com"
EMAIL_SMTP_PORT: 587
EMAIL_SMTP_TLS: "starttls"
EMAIL_SMTP_USERNAME: "<smtp-user>"
EMAIL_SMTP_PASSWORD: "<smtp-password>"
EMAIL_FROM: "Nazo OAuth <no-reply@example.com>"
AVATAR_STORAGE_DIR: "/var/lib/nazo_oauth/avatars"
JWK_KEYS_DIR: "/var/lib/nazo_oauth/keys"
SIGNING_EXTERNAL_COMMAND: ""
SIGNING_EXTERNAL_TIMEOUT_MS: 2000
RUST_LOG: "info"
OTEL_ENABLED: false
OTEL_EXPORTER_OTLP_ENDPOINT: ""
OTEL_EXPORTER_OTLP_PROTOCOL: "http/protobuf"
OTEL_EXPORTER_OTLP_TIMEOUT: 10000
```

Do not store production secrets in Git.

Set `AUTHORIZATION_SERVER_PROFILE` to `fapi2-security` only when the deployed client population is prepared for confidential-client-only operation, PAR-only authorization requests, PKCE S256, `private_key_jwt` or mTLS client authentication, and DPoP or mTLS sender-constrained tokens. Use `fapi2-message-signing-authz-request` when signed request objects are also mandatory at PAR. Discovery metadata reflects this setting and omits mTLS capabilities unless `TRUSTED_PROXY_CIDRS` is non-empty.

OpenTelemetry is opt-in. Set `OTEL_ENABLED: true` and `OTEL_EXPORTER_OTLP_ENDPOINT` to an OTLP/HTTP collector base URL such as `http://otel-collector:4318` to export traces, metrics, and logs. The service appends `/v1/traces`, `/v1/metrics`, and `/v1/logs` internally. `OTEL_EXPORTER_OTLP_PROTOCOL` is currently `http/protobuf`; leave `RUST_LOG` configured for local stdout logs even when OTLP export is enabled.

## Container Build

Build the image:

```sh
docker build -f Containerfile -t nazo-oauth-server:$(git rev-parse --short=7 HEAD) .
```

Run migrations:

```sh
docker run --rm \
  --network <deployment-network> \
  -v /opt/nazo-oauth/.env.yaml:/app/.env.yaml:ro \
  -v /opt/nazo-oauth/runtime/keys:/var/lib/nazo_oauth/keys:rw \
  -v /opt/nazo-oauth/runtime/avatars:/var/lib/nazo_oauth/avatars:rw \
  nazo-oauth-server:<tag> \
  nazo-oauth-migrate
```

Run the server:

```sh
docker run -d --name nazo-oauth-server \
  --network <deployment-network> \
  -v /opt/nazo-oauth/.env.yaml:/app/.env.yaml:ro \
  -v /opt/nazo-oauth/runtime/keys:/var/lib/nazo_oauth/keys:rw \
  -v /opt/nazo-oauth/runtime/avatars:/var/lib/nazo_oauth/avatars:rw \
  nazo-oauth-server:<tag> \
  nazo-oauth-server
```

The repository also includes `compose.yml` for local integration. Treat it as a development baseline, not a complete production topology.

## Release Security

Before promoting an image, require a successful `conformance-security` workflow for the exact commit. That workflow runs Rust advisory checks, dependency policy checks, SBOM generation, image build, and Trivy scanning in addition to the Rust and real HTTP gates.

For versioned releases, create a `v*` tag and require the `release-security` workflow to complete successfully. It builds release binaries, generates the Rust SBOM, signs the binaries, SBOM, and image archive through keyless Sigstore signing, uploads artifacts, and emits GitHub provenance attestations. Preserve the release evidence listed in [docs/release-security.md](release-security.md).

## Live Deployment Script

The repository includes [scripts/deploy_live.ps1](../scripts/deploy_live.ps1), which builds an image, transfers it to a remote host, runs migrations, replaces the running Podman container, and verifies health and discovery.

Default live assumptions in the script:

| Setting | Default |
| --- | --- |
| Remote host | `nazo.run` |
| Container name | `nazo-oauth-server` |
| Network | `nazo_oauth_net` |
| Container IP | `10.101.0.20` |
| Remote config | `/opt/nazo-oauth/.env.yaml` |
| Keys path | `/opt/nazo-oauth/runtime/keys` |
| Avatars path | `/opt/nazo-oauth/runtime/avatars` |
| Health URL | `https://oauth.nazo.run/health` |
| Discovery URL | `https://oauth.nazo.run/.well-known/openid-configuration` |
| Expected issuer | `https://oauth.nazo.run` |

Example:

```powershell
pwsh scripts/deploy_live.ps1 `
  -RemoteHost nazo.run `
  -ImageRepository localhost/nazo-oauth-server `
  -ImageTag main-$(git rev-parse --short=7 HEAD)
```

The script is intentionally opinionated for the current `nazo.run` environment. Recheck the live listener, reverse-proxy config, container network, TLS settings, and expected issuer before reusing it for another host.

## Reverse Proxy

Production proxy requirements:

- Terminate TLS with the public issuer hostname.
- Forward only sanitized proxy headers to the service.
- Strip inbound client-supplied `Forwarded`, `X-Forwarded-*`, mTLS, and certificate headers before adding trusted values.
- Configure `TRUSTED_PROXY_CIDRS` to include only the reverse proxy addresses that are allowed to forward client IP and mTLS certificate metadata.
- Protect the proxy-to-application hop with TLS, mTLS, or an equivalent private network boundary; forwarded certificate metadata is only meaningful on a trusted internal channel.
- Use one certificate forwarding representation where possible. If multiple forwarded certificate thumbprint/certificate headers are present, the application rejects the request unless they resolve to the same SHA-256 certificate thumbprint. If multiple forwarded subject-DN headers are present, they must be byte-identical after trimming.
- For `tls_client_auth`, register at least one of `tls_client_auth_subject_dn`, `tls_client_auth_san_dns`, `tls_client_auth_san_uri`, `tls_client_auth_san_ip`, `tls_client_auth_san_email`, or `tls_client_auth_cert_sha256`. The application matches these values against trusted forwarded certificate metadata; forwarded PEM certificates are parsed directly for subject DN and DNS/URI/IP/email SAN values.
- For `self_signed_tls_client_auth`, register current client certificates in `jwks.keys[].x5c[0]`. Multiple current `x5c` certificates are the rotation window; removing an old certificate retires it. Expired or not-yet-valid registered certificates are ignored.
- Preserve the exact path for OAuth endpoints.
- Disable response caching for protocol endpoints unless the endpoint is explicitly cacheable.
- Ensure `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`, `/jwks.json`, `/authorize`, `/par`, `/token`, `/userinfo`, `/introspect`, and `/revoke` are reachable as intended.

For mTLS sender constraint and mTLS client authentication, the service currently relies on a trusted reverse proxy to verify the client certificate and forward certificate evidence. This is a strict trust boundary: the application accepts forwarded certificate metadata only when the connection peer is in `TRUSTED_PROXY_CIDRS`; traffic from any other peer is treated as not having verified client certificate evidence.

## Key Rotation

Initial startup creates a signing key if no keyset exists. For controlled rotation:

```sh
nazo-oauth-keyctl generate --alg RS256
nazo-oauth-keyctl validate
nazo-oauth-keyctl activate <kid>
```

After the maximum access-token and ID-token TTL has elapsed:

```sh
nazo-oauth-keyctl retire <old-kid> --at <timestamp>
nazo-oauth-keyctl validate
```

Back up the key directory before and after rotation. Losing active private keys invalidates token signing continuity.

### External KMS/HSM signing

Local PEM keys remain the default. For non-exportable signing keys, register an external key whose public JWK is stored in `keyset.json` while signing is delegated to a trusted command or sidecar:

```sh
nazo-oauth-keyctl register-external \
  --kid rs256-kms-2026-06 \
  --alg RS256 \
  --key-ref kms://prod/oauth/rs256-kms-2026-06 \
  --public-jwk /secure/exported-public-jwk.json
nazo-oauth-keyctl validate
nazo-oauth-keyctl activate rs256-kms-2026-06
```

Configure `SIGNING_EXTERNAL_COMMAND` as a comma-separated argv list, for example `/usr/local/bin/oauth-kms-signer,--profile,prod`, and set `SIGNING_EXTERNAL_TIMEOUT_MS` to the maximum allowed signing latency. The service sends one JSON request on stdin:

```json
{"version":1,"kid":"rs256-kms-2026-06","alg":"RS256","key_ref":"kms://prod/oauth/rs256-kms-2026-06","signing_input":"<base64url(header)>.<base64url(payload)>"}
```

The signer must return JSON on stdout with a base64url raw JWS signature:

```json
{"signature":"<base64url-signature>"}
```

The application rejects active external keys unless `SIGNING_EXTERNAL_COMMAND` is configured, kills timed-out signer processes, rejects empty or malformed signatures, and never falls back to unsigned or query-mode responses after signing failure.

## Database and Valkey

PostgreSQL stores durable users, clients, grants, tokens, and revocation state. Production operation requires:

- automated backups
- restore rehearsals
- migration rollback planning
- monitoring for replication lag or storage saturation

Valkey stores short-lived sessions, authorization codes, PAR handles, DPoP/client assertion replay state, and rate-limit counters. Production operation requires:

- bounded memory policy
- latency monitoring
- persistence or HA appropriate to your risk model
- clear failure handling expectations

If Valkey is unavailable, sensitive protocol paths should fail closed with OAuth errors instead of silently weakening replay or rate-limit controls.

The full HA, backup, restore, timeout, and partial-outage requirements are maintained in [docs/ha-operations.md](ha-operations.md).

## Verification

After deployment:

```sh
curl -fsS https://oauth.example.com/health
curl -fsS https://oauth.example.com/.well-known/openid-configuration
curl -fsS https://oauth.example.com/.well-known/oauth-authorization-server
curl -fsS https://oauth.example.com/jwks.json
```

Check that discovery `issuer` exactly equals `ISSUER`.

For the current live environment, [scripts/verify_live_full_interfaces.py](../scripts/verify_live_full_interfaces.py) exercises a broader HTTPS path against `https://oauth.nazo.run`. It reads host-local secrets and should be run only in the intended deployment environment.

## OIDF Readiness

Before launching a full OpenID Foundation conformance run:

1. Deploy the exact commit to be tested.
2. Verify discovery and JWKS over the public issuer.
3. Confirm redirect URIs in the suite plan config.
4. Confirm browser automation rules match the real login, consent, and callback pages.
5. Confirm mTLS endpoint aliases and proxy certificate forwarding.
6. Run `.github/workflows/oidf-conformance-full.yml`.
7. Preserve the final result index under `docs/conformance`.

## Operations Checklist

- HTTPS issuer only in production.
- `COOKIE_SECURE=true`.
- Minimal `CORS_ALLOWED_ORIGINS`.
- Strict trusted proxy CIDRs.
- No proxy header spoofing path.
- PostgreSQL backup and restore tested.
- Valkey availability and memory monitored.
- PostgreSQL and Valkey HA and partial-outage behavior documented.
- Signing key backups and rotation schedule.
- Audit logs collected and retained.
- Admin accounts hardened.
- Dependency and image scanning in release flow.
- Release SBOM, image signature, and provenance attestation retained.
- OIDF conformance records updated before artifacts expire.
