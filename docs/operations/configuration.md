# Configuration

## Model

Nazo Auth Server is configured in two layers:

- startup configuration: values needed before the process can run
- runtime/application configuration: feature and integration settings that can
  move to the administrator UI over time

`nazoauth server` uses `.env.yaml` in its working directory. If the file is
absent, the command copies the minimal example to `.env.yaml`, reports the new
path, materializes required service-owned secrets, and continues startup.
Explicit YAML and environment values still take precedence.

The default deployment is same-origin per tenant issuer. `PUBLIC_BASE_URL`
(and an optional `ISSUER`) seed the initial system-tenant directory binding:

```text
PUBLIC_BASE_URL=https://auth.example.com
ISSUER=https://auth.example.com
CLIENT_SECRET_PEPPER=<random 32+ byte secret>
TOKEN_ISSUANCE_RESPONSE_ENCRYPTION_KEY=<base64url-encoded 32-byte key>
TOKEN_ISSUANCE_RESPONSE_ENCRYPTION_KEY_ID=response-2026-08
```

After `nazoauth tenant-bootstrap` initializes the directory, an active binding
owns the tenant, realm, organization, canonical external Host, and HTTPS issuer.
The process builds a separate immutable runtime graph for each binding and
routes a request only by its canonical Host. The directory-derived issuer then
supplies that graph's frontend and CORS defaults; there is no process-wide
`TENANT_ID`, `REALM_ID`, or `ORGANIZATION_ID` request selector.

## Minimal deployment

```yaml
BIND: "0.0.0.0:8000"
PUBLIC_BASE_URL: "https://auth.example.com"
TRANSPORT_MODE: "trusted-proxy"
TRUSTED_PROXY_CIDRS: "127.0.0.1/32"
MTLS_CERTIFICATE_SOURCE: "disabled"
DATABASE_URL: "postgresql://nazo_oauth:<password>@postgres:5432/oauth"
VALKEY_URL: "redis://valkey:6379/0"
VALKEY_STATE_EPOCH: "<fresh UUIDv7 for this deployment>"
SIGNING_KEY_ENCRYPTION_KEY_ID: "deployment-signing-root"
SIGNING_KEY_ENCRYPTION_KEY_FILE: "/run/secrets/signing-key-encryption-key"
DATA_DIR: "/var/lib/nazo_oauth"
CLIENT_SECRET_PEPPER: "<random 32+ byte secret>"
TOKEN_ISSUANCE_RESPONSE_ENCRYPTION_KEY: "<base64url-encoded 32-byte key>"
TOKEN_ISSUANCE_RESPONSE_ENCRYPTION_KEY_ID: "response-2026-08"
RUST_LOG: "info"
```

Replace all placeholders, supply the deployment wrapping root as an unpadded
base64url 32-byte key in the referenced file, and initialize the current schema
and tenant directory through the deployment lifecycle before serving traffic.
Reuse the same wrapping root and state epoch on ordinary restarts; a restore
uses the [recovery procedure](ha-operations.md#state-epoch-and-restore-boundary).

`DATA_DIR` defaults the persistent file locations:

```text
avatar directory = DATA_DIR + "/tenants/{tenant_uuid}/avatars"
```

## Startup settings

| Setting | Default | Notes |
| --- | --- | --- |
| `BIND` | `0.0.0.0:8000` | Public listener; HTTPS in `direct-tls`, HTTP otherwise |
| `PUBLIC_BASE_URL` | `http://127.0.0.1:8000` | Seeds the initial system-tenant directory binding and process-level control settings. Active directory bindings supply the request issuer and Host. |
| `ISSUER` | `PUBLIC_BASE_URL` | Optional issuer for the initial system binding. A directory binding replaces it for that tenant graph. |
| `TRANSPORT_MODE` | implicit only for loopback HTTP | `loopback-http`, `direct-tls`, or `trusted-proxy`; required for non-loopback issuers. This is a process transport boundary, not a tenant selector. |
| `DATABASE_URL` | `postgresql://postgres:postgres@127.0.0.1:5432/oauth` | PostgreSQL connection string for the current `nazoauth` launcher |
| `DATABASE_MAX_CONNECTIONS` | `32` | Maximum PostgreSQL pool size per NazoAuth process |
| `VALKEY_URL` | `redis://127.0.0.1:6379/0` | Valkey connection string; startup rejects an unmarked nonempty database rather than adopting historical keys |
| `VALKEY_STATE_EPOCH` | none (required UUIDv7) | Deployment state boundary. Every transient business key is physically namespaced as `nazo:state:v1:<deployment>:<epoch>:`. Set a fresh UUIDv7 before a restored candidate starts; never reuse a prior epoch. |
| `DATA_DIR` | `runtime` | Base directory for persistent local files |
| `UI_ENABLED` | `true` | Host the default or custom static UI under `/ui/`; set false for API-only or external UI hosting |
| `UI_STATIC_DIR` | `${DATA_DIR}/ui/current` | Existing custom UI directory. When unset, first use installs official NazoAuthWeb; existing files are preserved and can be replaced without restarting |
| `CLIENT_SECRET_PEPPER` | generated under `DATA_DIR/secrets` | Explicit values override the persisted generated value; keep it stable and back it up with the database |
| `PASSWORD_HASH_MAX_CONCURRENCY` | `8` | Maximum concurrent Argon2 password verifications per process; tune from CPU and memory capacity, not by lowering Argon2 cost |
| `PASSWORD_HASH_QUEUE_TIMEOUT_MS` | `100` | Maximum bounded wait for a password-verification slot before returning `temporarily_unavailable` |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | Window for the broad source-IP admission buckets |
| `AUTH_RATE_LIMIT_MAX_REQUESTS` | `100000` | Broad source-IP admission ceiling for authentication endpoints; this is not the failed-login throttle |
| `TOKEN_RATE_LIMIT_MAX_REQUESTS` | `100000` | Broad source-IP admission ceiling for token issuance, sized to tolerate shared client egress |
| `TOKEN_MANAGEMENT_RATE_LIMIT_MAX_REQUESTS` | `100000` | Broad source-IP admission ceiling shared by token-management, PAR, and dynamic-registration paths |
| `EMAIL_CODE_TTL_SECONDS` | `900` | Lifetime of a local-registration email verification code |
| `EMAIL_CODE_SEND_COOLDOWN_SECONDS` | `60` | Per-tenant, per-normalized-email send cooldown |
| `EMAIL_CODE_PEER_COOLDOWN_SECONDS` | `5` | Per-tenant, per-peer send cooldown; the broader authentication rate limiter remains a separate deployment-wide admission control |
| `LOGIN_FAILURE_WINDOW_SECONDS` | `900` | Window for failed-login throttling |
| `LOGIN_FAILURE_IP_EMAIL_MAX_ATTEMPTS` | `5` | Maximum failed login attempts per source IP and normalized email in the failed-login window |
| `AUTHORIZATION_SERVER_PROFILE` | `oauth2-baseline` | Global protocol profile. Every OAuth client must carry an explicit current `security_policy`; rows without it are rejected rather than inferred from this setting. |
| `CIBA_SECURITY_PROFILE` | `fapi-ciba-id1` | CIBA-specific policy: FAPI-CIBA ID1 with orthogonal poll/ping delivery and private-key/mTLS client authentication, or internal `fapi2-ciba` hardening. Only these canonical values are accepted. |
| `MFA_TOTP_ENCRYPTION_KEY` / `MFA_TOTP_ENCRYPTION_KEY_ID` | generated under `DATA_DIR/secrets` | Current 32-byte base64url key and derived version id for TOTP seed envelope encryption. Prefer `MFA_TOTP_ENCRYPTION_KEY_FILE` when importing a controlled existing key. |
| `MFA_TOTP_PREVIOUS_ENCRYPTION_KEY` / `MFA_TOTP_PREVIOUS_ENCRYPTION_KEY_ID` | unset | Optional prior key for decrypting existing encrypted envelopes during a controlled key transition. Startup never scans, encrypts, or re-wraps credential rows. |
| `TOKEN_ISSUANCE_RESPONSE_ENCRYPTION_KEY` / `_ID` | generated under `DATA_DIR/secrets` | Independent current 32-byte base64url key and derived id for durable OAuth token-response envelopes. Do not derive it from `CLIENT_SECRET_PEPPER`; file injection remains available for controlled rotation. Missing or malformed pairs fail startup. |
| `TOKEN_ISSUANCE_RESPONSE_PREVIOUS_ENCRYPTION_KEY` / `_ID` | unset | Optional previous key retained only during a rotation overlap; use `TOKEN_ISSUANCE_RESPONSE_PREVIOUS_ENCRYPTION_KEY_FILE` for file injection. Existing live envelopes decrypt with current or previous; new envelopes always use current. Startup authenticates every live envelope, and expired rows are lazily removed before a grant key is reused. Remove the previous pair only after all rows encrypted with that id have expired and no writer still uses that key id. |
| `OPENID4VC_REVOCATION_POLICY` | `disabled` | `disabled`, `optional`, or `required`. The VP verifier requires `required`. Certificate, trust-anchor, and revocation facts are read from the managed shared signing-key generation, so VP verification performs no network or file I/O. |
| `OPENID4VC_MDOC_ISSUING_COUNTRY` | unset | Required only when local keyctl generates a certificate for an enabled `mso_mdoc` configuration. Two uppercase ASCII letters, and the generated DS/IACA Subject `C` uses this value. It is not required for externally issued certificate chains. |
| `SECURITY_AUDIT_REQUIRE_LEAST_PRIVILEGE` | `true` | Reject startup and high-impact administration when the server role is a superuser, can assume a ledger owner/privileged role, has direct ledger table capabilities, or lacks the writer function grants. |
| `FAPI_HTTP_SIGNATURE_MAX_AGE_SECONDS` | `60` | Request signature age and replay-marker lifetime; accepted range is 1–300 seconds, with at most five seconds of future clock skew |
| `SCIM_EVENT_RETENTION_SECONDS` | `604800` | Per-receiver delivery window and outbox retention; accepted range is 3600–2592000 seconds |
| `RUST_LOG` | `info` | Tracing filter |

The response key id is not the envelope format. The current format is `v1` and
is stored separately from `response_key_id`; a format change requires an
explicit migration. Keep the current and previous key material available for
the full durable-response recovery window. Managed schema changes run only in
the signed install, update, or recover lifecycle. An irreversible migration
requires verified snapshot recovery rather than artifact rollback.

PostgreSQL connections use Rustls with the AWS-LC provider. `DATABASE_URL`
accepts `sslmode=disable`, `prefer` (the PostgreSQL client default), or
`require`. TLS connections validate the server hostname and certificate against
the operating system trust store; bundled WebPKI roots are used only when the
platform store is empty. This path does not load `libpq` or the system OpenSSL
ABI. Use `sslmode=require` for remote or untrusted networks and
`sslmode=disable` only for a separately protected local/private transport.

## Secret file inputs

A secret can be supplied as its direct setting or through its paired `_FILE`
setting. A direct value takes precedence; otherwise NazoAuth reads the referenced
file during startup. Relative file paths resolve from the configuration
directory. `_FILE` is intentionally limited to secret material: it is not a
generic indirection for URLs, endpoint addresses, flags, identifiers, or limits.

The supported pairs are:

| Primary setting | File setting |
| --- | --- |
| `CLIENT_SECRET_PEPPER` | `CLIENT_SECRET_PEPPER_FILE` |
| `DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN` | `DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN_FILE` |
| `PAIRWISE_SUBJECT_SECRET` | `PAIRWISE_SUBJECT_SECRET_FILE` |
| `MFA_TOTP_ENCRYPTION_KEY`, `MFA_TOTP_PREVIOUS_ENCRYPTION_KEY` | `MFA_TOTP_ENCRYPTION_KEY_FILE`, `MFA_TOTP_PREVIOUS_ENCRYPTION_KEY_FILE` |
| `TOKEN_ISSUANCE_RESPONSE_ENCRYPTION_KEY`, `TOKEN_ISSUANCE_RESPONSE_PREVIOUS_ENCRYPTION_KEY` | `TOKEN_ISSUANCE_RESPONSE_ENCRYPTION_KEY_FILE`, `TOKEN_ISSUANCE_RESPONSE_PREVIOUS_ENCRYPTION_KEY_FILE` |
| `SIGNING_KEY_ENCRYPTION_KEY`, `SIGNING_KEY_PREVIOUS_ENCRYPTION_KEY` | `SIGNING_KEY_ENCRYPTION_KEY_FILE`, `SIGNING_KEY_PREVIOUS_ENCRYPTION_KEY_FILE` |
| `OPENID4VC_DATA_ENCRYPTION_KEY` | `OPENID4VC_DATA_ENCRYPTION_KEY_FILE` |
| `OPENID4VCI_ISSUER_MANAGEMENT_TOKEN` | `OPENID4VCI_ISSUER_MANAGEMENT_TOKEN_FILE` |
| `OPENID4VP_VERIFIER_MANAGEMENT_TOKEN` | `OPENID4VP_VERIFIER_MANAGEMENT_TOKEN_FILE` |

Use the exact pair names above; the code allowlist is authoritative.
The independent audit worker additionally accepts `AUDIT_ANCHOR_TOKEN_FILE`;
that input is not loaded into the server process. See
[audit anchoring](../security/audit-anchor.md#configuration) for its separate
configuration and database credentials.

## Local mdoc certificates and CRLs

Set `OPENID4VC_MDOC_ISSUING_COUNTRY` in the server `.env.yaml` before an
ordinary tenant receives locally generated mdoc material. The OIDF Suite's
current mDL dataset uses `UT`, so the conformance deployment's server
configuration must set `OPENID4VC_MDOC_ISSUING_COUNTRY: "UT"` before its
temporary tenant is materialized. Tenant-local settings inherit this root
configuration through the existing directory-binding path; the OIDF resource
Apply does not carry a second country value.

Tenant bootstrap or key generation commits the certificate chain, IACA private
material, and local revocation facts in the encrypted shared tenant keyset.
Normal startup reads this aggregate; it does not create or reload authority
files. The public keyset never exposes IACA private material.

The DS publishes `/.well-known/mdoc/<iaca-sha256>.crl`. Each request reads the
current durable authority state and signs with that IACA's retained key. A
revoked DS appears with its recorded revocation time; missing or inconsistent
authority material fails closed. Rotation retains historical IACA records and
CRL URLs for already issued credentials. See
[managed OpenID4VC state](mdoc-shared-state.md) for import, refresh windows,
rotation, and revocation commands.

## Derived settings

For the initial system binding, the root configuration derives these values.
For each active directory binding, its issuer replaces the configured issuer;
that issuer also derives the tenant graph's frontend URL and CORS default.
Explicit deployment-wide security settings remain global, and passkey settings
still derive from the binding issuer when no explicit passkey override exists.

| Derived value | Rule |
| --- | --- |
| `ISSUER` | `PUBLIC_BASE_URL`, unless explicitly overridden for the initial system binding; a directory binding replaces it for its tenant graph. |
| `FRONTEND_BASE_URL` | `PUBLIC_BASE_URL + "/ui/"` for the initial system binding; a directory tenant uses its issuer + `/ui/`. |
| `CORS_ALLOWED_ORIGINS` | origin of `PUBLIC_BASE_URL` for the initial system binding; a directory tenant uses its issuer origin. |
| `COOKIE_SECURE` | `true` when issuer uses HTTPS |
| `PASSKEY_ORIGIN` | issuer, unless explicitly overridden |
| `PASSKEY_RP_ID` | host of `PASSKEY_ORIGIN`, unless explicitly overridden |
| `PROTECTED_RESOURCE_IDENTIFIER` | `ISSUER + "/fapi/resource"`, unless explicitly overridden |
| `SIGNING_KEY_ENCRYPTION_KEY_ID` | required deployment-provided nonempty wrapping-key identifier |
| `SIGNING_KEY_ENCRYPTION_KEY` | required deployment-provided unpadded base64url 32-byte signing-key wrapping key |
| `SIGNING_KEY_PREVIOUS_ENCRYPTION_KEY_ID` / `SIGNING_KEY_PREVIOUS_ENCRYPTION_KEY` | optional matched previous wrapping-key pair while rewrapping persisted signing material |
| `AVATAR_OBJECT_STORE` | Optional shared avatar storage: `local` or `s3`. Unset by default; tenants without their own configuration then have no avatar storage. |
| `AVATAR_STORAGE_DIR` | Optional local base directory; each tenant uses `{base}/{tenant_uuid}`. Without it, use `DATA_DIR/tenants/{tenant_uuid}/avatars`. A directory alone does not enable local storage. |
| `AVATAR_TENANT_STORAGE_JSON` | Optional complete tenant storage overrides keyed by tenant UUID; absent tenants inherit configured global storage, or have avatar storage disabled. With no global storage, these entries form the allowlist. See [avatar storage configuration and manual migration](avatar-direct-upload.md#global-default-and-tenant-overrides). |

Explicit overrides are retained for advanced deployments. New deployments
should prefer same-origin defaults.

Signing keys, their dedicated request-object decryption key, and their public
projection are one encrypted generation in PostgreSQL.

Every server instance for a deployment must receive the same
`SIGNING_KEY_ENCRYPTION_KEY_ID` and `SIGNING_KEY_ENCRYPTION_KEY`. The key is
32 bytes encoded as unpadded base64url. Do not generate it per instance or replace
it before the database generation is rewrapped. During a wrapping-key change,
deploy the current and previous pair to every instance, let an operator publish
a new generation, verify all instances can load it, then remove the previous
pair. Back up the encrypted PostgreSQL row and the wrapping root together;
the database ciphertext cannot recover private keys without its wrapping root.

Fresh deployment initializes the database keyset through tenant bootstrap.
Historical file keysets are not imported or converted. Before 0.5.0, version
updates do not preserve compatibility with historical releases; retain the
backup and matching recovery tools for an existing deployment.

## Authorization-code replay state

A consumed authorization-code marker is Valkey security state, not a disposable
cache entry. It retains the redemption binding, issued access-token identity and
expiry, and the optional refresh-token family so a later matching replay can
revoke the issued access token and refresh family.

The marker keeps the access-token TTL used at the original exchange when no
refresh token was issued. When that exchange issued a refresh token, it keeps
that exchange's refresh-token TTL instead. Expiry changes this one marker to
`Missing`; it cannot revive the authorization code. Each refresh successor has
its own relative TTL, so the marker does not attempt to retain an unbounded
refresh family forever. Do not shorten these configured TTLs below the lifetime
of credentials that a replay must still be able to revoke.

## Composable capability defaults

New databases activate stable, non-conflicting server modules together.
Client authority remains default-deny: a client still needs the appropriate
grant allowlist, metadata, sender constraint, and versioned `security_policy`.
Device Grant and CIBA therefore have active server support but new clients
cannot use either until `allow_cross_device_flows=true` and the corresponding
grant/metadata are assigned. Session Management similarly requires
`session_management=true`.

Dynamic Client Registration is active only when
`DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN` is non-empty. The token is
generated and persisted by the server/managed installer when it is not
provided. Experimental, draft, remote-trust, and role-specific modules remain
conditional on their complete prerequisites.

Before crossing migration `20260828000600`, an existing deployment must
materialize one explicit `enabled` or `disabled` row for every runtime module.
Missing rows or `inherit` stop migration; the server does not reconstruct old
configuration. After migration, runtime module administration is the only
authority. The removed stable-module flags must be deleted from older
`.env.yaml` files before restarting.

The same migration is an offline persisted-security cut, not a data converter.
Before applying it, stop every old writer and retain a verified database
snapshot. Materialize and review a complete v1 `security_policy` for every
OAuth client; terminate refresh families that lack the current issuer,
client-audience, authentication-time, AMR, or claim contract; and remove
pre-binding OpenID4VP transactions. Every TOTP row must already contain a v1
encrypted envelope and a non-empty key id, with no plaintext seed remaining.
Before removing any current or previous TOTP key, an operator-controlled
pre-cut procedure must authenticate-decrypt every retained row using the same
tenant/user AAD as the server and record that every distinct stored key id is
available. Migration 006 can validate envelope shape but cannot prove AEAD
authenticity or key availability. If any probe fails, do not run the migration;
repair the stopped candidate before proceeding. After the cut, artifact rollback
is rejected; `nazoauthctl recover` is the only managed path from a verified
snapshot. The current server has no startup plaintext encryption, policy
inference, runtime-state materializer, or alternate read path.

See
[Composable Capability Policy](../protocol/composable-capability-policy.md)
for the server/client boundary, default matrix, policy JSON, and upgrade rules.

## Experimental FAPI HTTP signatures

The explicit persisted `http_message_signatures` runtime-module state changes
only `/fapi/resource`. It is default-off, has no discovery metadata, and is
not a claimed certification profile.
Each token's `client_id` must resolve to an active client with an exact public
JWK matching the request `keyid` and algorithm. Supported algorithms are
Ed25519, RSA PKCS#1 v1.5 SHA-256 with RSA keys of at least 2048 bits, and
ECDSA P-256 SHA-256. Private JWK material, ambiguous keys, unsupported curves,
or algorithm/key mismatches fail closed.

Operators own client-key provisioning and revocation, clock synchronization,
Valkey availability for atomic replay consumption, server signing-key custody,
and signed-message evidence retention. A replay-store or response-signing
failure returns a signed error when possible and never falls back to an
unsigned success. See the [experimental resource contract](../protocol/fapi-http-signatures.md).

## Public OP/AS security boundary

Production deployments must expose the issuer through HTTPS. Select exactly one
transport owner with `TRANSPORT_MODE`: NazoAuth terminates TLS in `direct-tls`,
or a reverse proxy terminates TLS in `trusted-proxy`. Public listeners should use
TLS 1.3 where available, allow only modern TLS 1.2 suites when TLS 1.2 is
required, reject TLS 1.0/1.1, and set `Strict-Transport-Security` for
browser-facing issuer hosts. `ISSUER`, `PUBLIC_BASE_URL`, and
`FRONTEND_BASE_URL` must use the externally visible HTTPS origin in production.

The supported proxy preset strips inbound `Forwarded`, `X-Forwarded-*`,
`Client-Cert`, `Client-Cert-Chain`, and every `X-SSL-*` certificate header. It
adds only the singleton RFC 9440 `Client-Cert` value derived from the verified
TLS peer on the dedicated mTLS listener. Configure `TRUSTED_PROXY_CIDRS` only
for the exact proxy addresses and keep `CLIENT_IP_HEADER_MODE=none` for this
boundary.

Trusted mTLS header mode is a deployment boundary, not a browser feature. The
proxy or sidecar must verify the client certificate, forward only normalized
certificate evidence over the trusted internal hop, and reject or overwrite any
same-named header received from the public internet. Raw certificate material,
client assertions, DPoP proofs, access tokens, refresh tokens, authorization
codes, provider tokens, and secret references must not be logged or returned in
error responses.

For the concrete HAProxy 3.2 preset, trust-bundle installation, atomic reload,
and rollback requirements, see
[`deploy/proxy/README.md`](../../deploy/proxy/README.md).

CORS is endpoint-scoped. `CORS_ALLOWED_ORIGINS` is an exact allowlist, not proof
that a browser client is confidential. Authorization and browser-redirect
endpoints are navigation-only and are not CORS APIs. `/token` and `/revoke`
allow non-credentialed browser CORS only for POST with the protocol headers
needed for content type, client/token authorization, DPoP nonce, challenge, and
retry handling. `/userinfo` permits non-credentialed GET/POST bearer or DPoP
access. These public OAuth routes do not accept the session-only
`X-CSRF-Token` header. Auth and admin session APIs may use credentialed CORS
only for exact configured origins and only with CSRF-bearing write requests.
Session cookies are
`HttpOnly`, `SameSite=Lax`, and `Secure` by default; disabling `COOKIE_SECURE`
is only appropriate for local loopback development.

## Advanced settings

The following settings are still supported but should not be part of a quick
deployment path. They are candidates for the administrator UI:

- conditional OpenID4VC service settings: `ENABLE_OPENID4VCI_ISSUER`,
  `ENABLE_OPENID4VP_VERIFIER`, `ENABLE_DIRECTORY_OPENID4VCI_ISSUER`, and
  `ENABLE_DIRECTORY_OPENID4VP_VERIFIER`. Each directory flag defaults to its
  matching global flag; tenant-specific settings use the directory value, while
  routes register if either value is enabled. These flags do not replace the
  explicit persisted desired state for runtime modules.
- protocol tuning: `DPOP_NONCE_POLICY`, `FAPI_RESOURCE_DPOP_NONCE_POLICY`, `REQUEST_OBJECT_JTI_POLICY`,
  `CIBA_SECURITY_PROFILE`, `REQUIRE_PUSHED_AUTHORIZATION_REQUESTS`,
  `PAR_TTL_SECONDS`,
  `PROTECTED_RESOURCE_IDENTIFIER`, `DEVICE_AUTHORIZATION_TTL_SECONDS`,
  `DEVICE_AUTHORIZATION_POLL_INTERVAL_SECONDS`,
  `DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN`,
  `REMOTE_CLIENT_DOCUMENT_PRIVATE_ORIGINS`,
  `BACKCHANNEL_LOGOUT_PRIVATE_ORIGINS`
- token and session lifetimes: `SESSION_TTL_SECONDS`, `AUTH_CODE_TTL_SECONDS`,
  `ACCESS_TOKEN_TTL_SECONDS`, `ID_TOKEN_TTL_SECONDS`,
  `REFRESH_TOKEN_TTL_SECONDS`

`REMOTE_CLIENT_DOCUMENT_PRIVATE_ORIGINS` is a comma-separated list of exact
HTTPS origins allowed to resolve to private/loopback addresses for remote
dynamic-client JWKS and Request Objects. Leave it empty in production unless a
specific private client-document service is required. Public destinations are
always DNS-resolved and blocked when any result is loopback, link-local,
private, unspecified, or multicast; redirects are disabled.

`BACKCHANNEL_LOGOUT_PRIVATE_ORIGINS` is a comma-separated list of exact HTTP(S)
origins that are explicitly permitted to resolve to private or loopback
addresses for Back-Channel Logout delivery. Leave it empty in production unless
a specific private RP is required. Each delivery is DNS-resolved before use,
pinned to the resolved addresses, rejected if any address is private without an
exact allowlist match, and sent with redirects disabled. HTTP remains limited to
loopback endpoints.
- rate limits: `RATE_LIMIT_WINDOW_SECONDS`, `AUTH_RATE_LIMIT_MAX_REQUESTS`,
  `TOKEN_RATE_LIMIT_MAX_REQUESTS`,
  `TOKEN_MANAGEMENT_RATE_LIMIT_MAX_REQUESTS`,
  `LOGIN_FAILURE_WINDOW_SECONDS`,
  `LOGIN_FAILURE_IP_EMAIL_MAX_ATTEMPTS`
- password verification capacity: `PASSWORD_HASH_MAX_CONCURRENCY`,
  `PASSWORD_HASH_QUEUE_TIMEOUT_MS`
- email delivery: `EMAIL_DELIVERY`, `EMAIL_SMTP_HOST`, `EMAIL_SMTP_PORT`,
  `EMAIL_SMTP_TLS`, `EMAIL_SMTP_USERNAME`, `EMAIL_SMTP_PASSWORD`,
  `EMAIL_FROM`
- passkeys: `PASSKEY_RP_NAME`, `PASSKEY_REQUIRE_USER_VERIFICATION`,
  `PASSKEY_REQUIRE_USER_HANDLE`, `PASSKEY_STRICT_BASE64`
- federation: `FEDERATION_PROVIDER_CONFIGS`, `FEDERATION_SAML_GATEWAY_*`
- SCIM: `SCIM_EVENT_RETENTION_SECONDS`
- external signing: `SIGNING_EXTERNAL_COMMAND`,
  `SIGNING_EXTERNAL_TIMEOUT_MS`,
  `SIGNING_KEY_ROTATION_INTERVAL_SECONDS`,
  `SIGNING_KEY_PREPUBLISH_SECONDS`
- observability: `OTEL_ENABLED`, `OTEL_EXPORTER_OTLP_ENDPOINT`,
  `OTEL_EXPORTER_OTLP_PROTOCOL`, `OTEL_EXPORTER_OTLP_TIMEOUT`
- proxy and client IP handling: `TRUSTED_PROXY_CIDRS`,
  `CLIENT_IP_HEADER_MODE`, `MTLS_CERTIFICATE_SOURCE`

`MTLS_CERTIFICATE_SOURCE` accepts `disabled`, `direct-tls`, or `rfc9440`.
`rfc9440` consumes the singleton RFC 9440 `Client-Cert` DER byte sequence.
`trusted-proxy` requires both `TRUSTED_PROXY_CIDRS` and an explicit certificate
source; use `disabled` when that proxy does not authenticate client certificates.
`loopback-http` rejects proxy and certificate-source settings. No public mode is
inferred from the presence of proxy CIDRs or certificate headers.

`direct-tls` serves normal HTTPS on `BIND` and client-certificate-capable HTTPS
on `TLS_BIND`, using the same server identity. It requires
`TLS_CERTIFICATE_FILE`, `TLS_PRIVATE_KEY_FILE`, and `TLS_CLIENT_CA_FILE`.
The leaf certificate must be currently valid, match the private key, and cover
the issuer and mTLS endpoint hosts. On Unix,
the private key must be a regular owner-only file, or a root-owned `0640` file
whose group is the service's effective group.
Route the RFC 8705 mTLS endpoint aliases to `TLS_BIND`; direct mode rejects all
proxy trust settings and derives client certificate identity only from the TLS
  session. The process revalidates the server certificate chain and private key
  as one immutable TLS identity
generation every `TLS_RELOAD_INTERVAL_SECONDS` (default `5`, allowed `1..=3600`).
A candidate is published only after a non-empty parseable certificate chain,
  leaf/private-key match, current leaf validity, endpoint names, file bounds, and key
permissions pass. Invalid or partially installed material leaves the previous
generation active. New handshakes use the published generation; existing
connections keep the generation they accepted. Server-side TLS resumption is
  disabled so a new connection cannot bypass a server identity change. The
  deployment client-CA bundle is validated and fixed at startup; changing it
  requires a controlled restart. In proxy mode, the optional `TLS_CLIENT_CA_FILE`
  applies the same PKI validation to the forwarded leaf and `Client-Cert-Chain`.
  A trusted proxy must verify possession of the client private key and replace
  incoming certificate headers; header forwarding alone does not establish CA trust.

The mTLS listener verifies CertificateVerify signatures while permitting unknown
CAs and absent certificates to reach OAuth client authentication. `tls_client_auth`
requires the registered certificate selector and a chain trusted by either the
deployment CA bundle or the selected tenant/client's currently approved anchors.
Anchor revocation is checked on each authentication, including existing connections.
`self_signed_tls_client_auth` requires the certificate registered in the client's
JWKS. Neither an unknown CA nor a matching subject alone authenticates a client.
The deployment owner remains responsible for crash-safe staged file activation,
public health verification, and restoring the previous files after a failed
rollout. The deployment certificate may cover tenant hosts through SANs or a
wildcard. The tenant directory remains authoritative for routing; an unknown
Host is rejected and a differing SNI/Host pair returns 421.

An active machine-resource binding is the sole authority for its managed user,
OAuth client, mTLS anchor, or OpenID4VC dataset. Ordinary admin/SCIM writes may
not change an actively bound user or client; the database rejects such drift.
Resource identities are immutable version fences: changing payload content
requires an explicit digest-fenced Revoke followed by Apply (normally with a
new resource identity), and clearing the desired set uses explicit Revoke.
Successful user/client revocation disables the resource, removes grants and
refresh credentials, and blacklists every still-live OAuth and OpenID4VC access
token owned by the resource in the same transaction.

`EMAIL_SMTP_TLS` accepts only `starttls`, `implicit`, or `none`. The `none`
mode is rejected unless the issuer is loopback HTTP and no SMTP credentials
are configured; production deployments must use encrypted mail submission.
`EMAIL_CODE_DEV_RESPONSE_ENABLED=true` is accepted only by a debug build with
a loopback HTTP issuer, so a deployable server cannot return verification
codes in API responses.

Security-sensitive values such as `DATABASE_URL`, `VALKEY_URL`, SMTP
credentials, federation client secrets, and SAML shared secrets must not be
committed to Git.

`FEDERATION_PROVIDER_CONFIGS` is a JSON array for modular third-party login
providers. Each enabled entry must include `provider_id`, `enabled`,
`display_name`, `adapter_type`, client credentials, redirect URI, scope,
endpoint or issuer configuration, and claim mapping. Providers default to
disabled unless `enabled` is true. Incomplete enabled provider configuration
fails startup; disabled providers do not appear in `/auth/federation/providers`.

Security-state lifetimes and cooldowns must be positive. Startup rejects zero
or negative values for session, authorization-code, access-token, ID-token,
refresh-token, PAR, client-delivery, and email-code lifetimes because those
settings back Valkey `EX` keys, database expiry timestamps, or abuse-control
windows.
