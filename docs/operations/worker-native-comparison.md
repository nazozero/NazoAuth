# Cloudflare Workers and native NazoAuth

Both deployments use the shared NazoAuth protocol, identity, and key-management
implementation. Select a deployment by its issuer, storage, lifecycle, and
integration requirements. See the [Workers adapter guide](cloudflare-workers.md)
for configuration and the [runtime module matrix](cloudflare-workers.md#optional-module-matrix)
for the profile prerequisites of each protocol module.

| Capability | Cloudflare Workers | Native host |
| --- | --- | --- |
| Runtime and deployment | Rust/WASM HTTP handler with Cloudflare ingress, static assets, and scheduled events | Native Rust HTTP service on a host, Docker, or Podman |
| Issuer and tenant routing | One configured issuer and tenant per Worker deployment. Other authorities are rejected. Deploy another issuer independently. | Configured multi-issuer and tenant directories with per-tenant application composition |
| Persistent and transient state | D1 is authoritative for protocol and account state and replay protection. | PostgreSQL and Valkey adapters. PostgreSQL deployment roles separate runtime and lifecycle permissions. |
| OAuth and OIDC | Shared Discovery, JWKS, authorization code with PKCE, client credentials, refresh, UserInfo, revocation and introspection. Machine-only restricts public routes to service authentication. | Shared protocol support. Administrators configure client policy, grants and deployment capabilities. |
| Web sign-in and accounts | Bundled NazoAuthWeb under `/ui/` or a separately configured frontend. Interactive profiles support Passkey and account security. Password and the wider service routes require the full profile. | Separately hosted NazoAuthWeb. Account and authentication capabilities follow the deployment configuration. |
| Optional shared modules | Full profile can construct all 16 shared protocol modules. D1 persists module intent and Worker requests or scheduled invocations reconcile it. | The native runtime constructs the configured modules and reconciles administrative changes. |
| Avatar storage | Authenticated multipart upload. D1 chunks by default, or image bytes in a private `NAZO_AVATARS` R2 bucket with metadata in D1. Browser-direct upload is unavailable. | Optional local storage or S3-compatible storage. The S3 adapter supports browser-direct uploads when configured. |
| Token signing and key lifecycle | Encrypted key generations in D1, with signing through shared Workers WebCrypto. Provision the first generation offline. The shared manager handles prepublication, activation and retirement. | Encrypted persisted generations and shared lifecycle, with local keys or a configured external signer. |
| HTTP KMS or HSM | Remote signer adapter unavailable. | External signing can be integrated through the native operator signer configuration and a separate signing service. |
| mdoc CRLs | The Worker publishes an offline-signed CRL after checking it against current D1 public authority and the monotonic publication record. The offline operator renews it before expiration. | The native provisioning and publication path supports IACA-held signing material under operator control. |
| Mail and federation | Verification mail uses a configured HTTPS relay. OIDC and social logins require actual provider registration. SAML uses the authenticated gateway contract. | Verification mail can use configured SMTP. Federation also requires the corresponding providers and gateway. |
| CIBA ping and RP back-channel logout | D1 delivery outboxes and scheduled HTTPS delivery. Configure reachable, explicitly admitted client or RP notification origins. | Durable delivery through the native service, with configured client or RP notification endpoints. |
| mTLS | Inbound client certificates use trusted Cloudflare metadata and configured trust policy. Outbound client-certificate bindings are outside the current adapter. | Inbound certificate facts and trust depend on the native ingress configuration. |
| Operational telemetry | Workers Logs and Traces. Cloudflare can export logs and traces to a configured OpenTelemetry destination. | Application OpenTelemetry exporters configured through the native observability settings. |
| Durable audit | Required audit and business mutations commit together in D1. | Transactional audit and an optional independent [audit anchor](../security/audit-anchor.md). |
| Deployment, backup and recovery | Operate Workers versions and resources with an identity that can act independently of the Worker. | [NazoAuthCtl](controller-repository-split.md) can manage installation, upgrades, backup and recovery on the host. |

The Workers Free budget applies to the chosen profile and workload. Measure
actual invocation outcomes and CPU distribution at the intended load, including
password and backup-code operations and signing-key generation. Confirm an
external integration against the provider or receiver used by the deployment.

## Public Workers Free integration coverage

The full profile completed these flows on a public Workers Free deployment
using synthetic accounts and independently hosted test services over HTTPS.

| Integration | Verified behavior |
| --- | --- |
| Verification mail | The HTTPS relay delivered the message over SMTP to a private Mailpit inbox. The received code registered an account and a second submission was rejected. |
| OIDC and OAuth 2.0 social login | Separate Keycloak clients completed authorization-code login with PKCE. The OIDC adapter verified the ID token and the custom social adapter fetched UserInfo. Both logins created the expected account link and session and rejected callback replay. |
| SAML gateway | Keycloak issued a signed SAML response. The gateway verified the response and assertion and sent an authenticated envelope to the Worker. The Worker established the account session and rejected envelope replay. |
| CIBA ping | A signed request used mTLS and the user approved it. The receiver checked the bearer token and matched the request ID. After an intentional HTTP 503, the Worker retried with the same idempotency key and received HTTP 204. The client redeemed the request once and received an mTLS-bound access token. |
| RP back-channel logout | The RP verified the signed logout token, matched the issuer, audience and session, and invalidated its session. The OP session also became invalid. |

This coverage uses a controlled SMTP inbox, the custom social adapter and a
SAML gateway against Keycloak. Validate delivery to the destination mail
provider and sign-in with any provider-specific adapter used in production.
