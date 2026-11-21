# Workers and native NazoAuth capability matrix

**√** means the current deployment adapter implements the capability. **—**
means the capability is unavailable through that adapter. The Workers column
uses the full profile. Modules must be constructed and enabled, and clients
need the corresponding grants and policies. The machine-only and Passkey-only
profiles restrict routes as described in the [Workers adapter guide](cloudflare-workers.md#deployment-profile).
Native refers to the native NazoAuth service, with NazoAuthCtl for the rows
that name it.

The [protocol profiles](../protocol/profile-matrix.md) and
[specification matrix](../protocol/rfc-compliance-matrix.md) define the scope
of each protocol. Implementation checks do not confer certification. The
[OpenID certification records](../../README.md#openid-certified) identify the
registered profiles and versions. Public Workers acceptance is recorded below.

## Sign-in and account management

| Capability or specification | Workers | Native | Conditions |
| --- | :---: | :---: | --- |
| NazoAuthWeb sign-in, consent and account UI | √ | √ | Workers can serve the bundled Web app. Native hosts the Web app separately. |
| Password sign-in | √ | √ | Shared Argon2id policy. Workers requires the full profile. |
| Email verification codes and local registration | √ | √ | Requires email delivery configuration. |
| Verification email via HTTPS relay | √ | — | Workers requires a relay token and an admitted HTTPS origin. |
| Verification email via direct SMTP | — | √ | Native supports configured SMTP transport. |
| WebAuthn Passkey enrollment and removal | √ | √ | Requires WebAuthn relying-party configuration. |
| WebAuthn Passkey sign-in | √ | √ | Works in the Workers full and Passkey-only profiles. |
| TOTP enrollment and MFA verification (RFC 6238) | √ | √ | Workers needs the service data-encryption key. |
| MFA backup codes and regeneration | √ | √ | Shared one-use and hashing policy. |
| Remembered devices | √ | √ | Interactive proof remains required for recent MFA. |
| MFA step-up and disabling MFA | √ | √ | Shared interactive proof and session policy. |
| Session cookies, CSRF protection and account logout | √ | √ | Configured cookie and origin policies apply. |
| Profile read and edit | √ | √ | Worker Passkey-only has a restricted profile route set. |
| Authorized applications and authorization history | √ | √ | Includes current grants, counts and last authorization where recorded. |
| Upstream OpenID Connect login | √ | √ | Requires provider registration and callback configuration. |
| OAuth 2.0 social login with QQ | √ | √ | Requires QQ application credentials and provider endpoints. |
| OAuth 2.0 social login with WeChat | √ | √ | Requires WeChat application credentials and provider endpoints. |
| OAuth 2.0 social login with a custom provider | √ | √ | Requires upstream endpoints and identity claim mapping. |
| SAML 2.0 sign-in via authenticated gateway | √ | √ | The SAML gateway handles upstream SAML and sends an authenticated assertion to NazoAuth. |
| External identity links, listing and unlinking | √ | √ | Shared account ownership and replay protections. |
| Authenticated multipart avatar upload | √ | √ | Requires the host's avatar store. |
| Authenticated avatar read and deletion | √ | √ | Shared profile and revision checks. |
| Avatar bytes stored in D1 | √ | — | Worker default without an R2 binding. |
| Avatar bytes stored via a private R2 binding | √ | — | Configure `NAZO_AVATARS`. Metadata remains in D1. |
| Avatar bytes stored on the local filesystem | — | √ | Configure native local avatar storage. |
| Avatar bytes stored via the S3-compatible adapter | — | √ | Configure the native S3 adapter. |
| Browser-direct avatar upload and completion | — | √ | Requires the native S3-compatible adapter. |

See the [identity guides](../README.md) and [direct avatar upload](avatar-direct-upload.md).

## OAuth 2.0 and OpenID Connect

| Capability or specification | Workers | Native | Conditions |
| --- | :---: | :---: | --- |
| OAuth 2.0 authorization code (RFC 6749) | √ | √ | Exact redirect binding, state and single-use redemption. |
| Client Credentials (RFC 6749) | √ | √ | Confidential service client. |
| Refresh Token grant and rotation (RFC 6749, RFC 9700) | √ | √ | Includes reuse detection, family revocation and audience narrowing. |
| PKCE S256 (RFC 7636) | √ | √ | Required according to client policy. Explicit baseline confidential OIDC compatibility can omit PKCE. |
| OAuth 2.1 draft-17 authorization-code profile | √ | √ | Per-client profile with mandatory S256 and the draft redirect contract. |
| Native app loopback redirects (RFC 8252) | √ | √ | Registered loopback redirect policy allows port variance. |
| Bearer access tokens (RFC 6750) | √ | √ | Shared header transport and narrow baseline UserInfo compatibility. |
| JWT access token profile (RFC 9068) | √ | √ | Issuer, audience, scope and signing policy apply. |
| OAuth authorization server metadata (RFC 8414) | √ | √ | Advertises enabled capabilities. |
| Protected resource metadata (RFC 9728) | √ | √ | Includes the protected resource route metadata. |
| Authorization response issuer identification (RFC 9207) | √ | √ | Authorization server mix-up defense. |
| Resource Indicators (RFC 8707) | √ | √ | Repeatable `resource` values and grant-bound audience selection. |
| Token Revocation (RFC 7009) | √ | √ | Client ownership and token family policy apply. |
| JSON Token Introspection (RFC 7662) | √ | √ | Authenticated client or resource-server access. |
| JWT Token Introspection (RFC 9701) | √ | √ | Signed and optionally encrypted under the selected response policy. |
| OpenID Connect Core 1.0 Basic OP | √ | √ | Authorization code, ID Token, and UserInfo. |
| OpenID Connect Discovery 1.0 Config OP and JWKS | √ | √ | Publishes issuers and active or retained public keys. |
| OIDC nonce and authentication context | √ | √ | Includes `auth_time`, `acr` and `amr` where supported by the authentication event. |
| OIDC prompts, `max_age` and fresh authentication | √ | √ | Includes `prompt=none` and `prompt=login` handling. |
| OIDC claims selection and essential claims | √ | √ | Shared supported-claim and scope policy. |
| OIDC public and pairwise subject identifiers | √ | √ | Remote sector documents on Workers require admitted origins. |
| OIDC consent, consent reuse and `offline_access` | √ | √ | Authorization and refresh policy are client-specific. |
| OIDC UserInfo JSON | √ | √ | Token binding and claim release follow client policy. |
| Per-client signed and encrypted OIDC ID Token | √ | √ | Registered keys and supported JOSE algorithms. |
| Per-client signed and encrypted OIDC UserInfo | √ | √ | Registered keys and supported JOSE algorithms. |
| Query authorization response | √ | √ | Authorization code response. |
| OAuth Form Post Response Mode | √ | √ | Baseline `form_post` code response. |
| OpenID Connect Third-Party Initiated Login | √ | √ | Registered HTTPS RP metadata and application integration. |
| OIDC RP-Initiated Logout | √ | √ | Supports registered post-logout redirects. |
| OIDC Session Management | √ | √ | `session_management` and per-client opt-in. |
| OIDC Front-Channel Logout | √ | √ | `frontchannel_logout` and registered browser callback. |
| OIDC Back-Channel Logout | √ | √ | Registered HTTPS callback. Workers needs an admitted origin and scheduled delivery. |
| Dynamic Client Registration (RFC 7591 and OIDC Registration) | √ | √ | `dynamic_client_registration` and initial access token. |
| Client configuration management (RFC 7592) | √ | √ | Registration access token, credential rotation and deactivation. |

## Client security and extended grants

| Capability or specification | Workers | Native | Conditions |
| --- | :---: | :---: | --- |
| Public OAuth clients | √ | √ | Registered public grants and PKCE where applicable. |
| `client_secret_basic` and `client_secret_post` | √ | √ | Shared secrets are baseline methods. POST is compatibility-scoped. |
| `private_key_jwt` (RFC 7523, RFC 10070) | √ | √ | Registered JWK and issuer-only client-authentication audience. |
| OAuth mTLS client authentication (RFC 8705) | √ | √ | Includes PKI and self-signed client registration options. Trusted ingress is required. |
| Certificate-bound access tokens (RFC 8705) | √ | √ | Protected use requires the matching TLS client certificate. |
| FAPI protected resource and token verification | √ | √ | Shared JWT, audience, scope and sender-binding checks at `/fapi/resource`. |
| DPoP proofs, token binding and nonce handling (RFC 9449) | √ | √ | Includes proof replay checks and binding through token endpoints and protected resources. |
| OAuth Security BCP controls (RFC 9700) | √ | √ | Shared server-side security policy and explicit compatibility boundaries. |
| JWT BCP controls (RFC 8725) | √ | √ | Shared JOSE validation and algorithm/key policies. |
| JWS, JWE, JWK and JWT (RFC 7515–7519) | √ | √ | Implemented JOSE formats and the algorithm subsets defined by each profile. |
| Pushed Authorization Requests (RFC 9126) | √ | √ | Shared PAR endpoint and one-use handles. |
| JWT Secured Authorization Request (RFC 9101, JAR) | √ | √ | `request_objects` for signed objects. Workers remote fetch requires an admitted origin. |
| Registered remote Request Objects and client JWK sets | √ | √ | Baseline registered HTTPS requests and bounded document resolution. FAPI uses PAR handles. |
| Request Object replay protection | √ | √ | Shared policy and one-use state. |
| JWT Secured Authorization Response Mode (JARM) | √ | √ | `jarm` for signed or signed-and-encrypted responses. |
| Rich Authorization Requests (RFC 9396) | √ | √ | `authorization_details` with consent and token/refresh binding. |
| FAPI 2.0 Security Profile Final for authorization code | √ | √ | Per-client FAPI 2.0 assurance with PAR, PKCE and sender constraints. |
| FAPI 2.0 Security Profile Final for Client Credentials | √ | √ | Per-client FAPI 2.0 assurance and sender constraints. |
| FAPI 2.0 Message Signing Final for authorization requests | √ | √ | Per-client requirement for signed Request Objects at PAR. |
| FAPI 2.0 Message Signing Final for authorization responses | √ | √ | Per-client JARM requirement. |
| FAPI 2.0 Message Signing Final for introspection | √ | √ | Per-client JWT or nested encrypted introspection policy. |
| FAPI 2.0 HTTP Signatures draft (RFC 9421 and RFC 9530) | √ | √ | `http_message_signatures`. Bounded signed resource requests and request-bound responses. |
| Device Authorization Grant (RFC 8628) | √ | √ | `device_authorization`, approved client cross-device policy and user decision. |
| JWT Bearer Grant (RFC 7523) | √ | √ | `jwt_bearer_grant`. Bounded confidential-client self-assertion. |
| OAuth Token Exchange (RFC 8693) | √ | √ | `token_exchange`. Bounded local tokens, targets and scopes. |
| OpenID Connect Native SSO for Mobile Apps | √ | √ | `native_sso` and `token_exchange`. Uses the ID Token and `device_secret`; Final-spec audit pending. |
| OpenID Connect CIBA poll | √ | √ | `ciba`, signed request and explicit client cross-device policy. |
| OpenID Connect CIBA ping | √ | √ | `ciba` and authenticated callback. Workers needs an admitted HTTPS origin and scheduled delivery. |
| FAPI-CIBA ID1 profile | √ | √ | Poll and ping, private-key JWT or mTLS client auth, and mTLS-bound tokens. |
| Internal `fapi2-ciba` hardening profile | — | √ | Native can select it with `CIBA_SECURITY_PROFILE`. Workers uses FAPI-CIBA ID1. |
| OAuth browser-based apps (RFC 10017 server-side controls) | √ | √ | Covers server-side controls. Application and BFF design are deployment responsibilities. |
| Cross-device flows (RFC 10027 server-side controls) | √ | √ | Device/CIBA policy and lifecycle controls. Deployment assessment remains required. |

See the [OAuth/OIDC integration guide](../integration/openid-connect.md) for client
choices and the [protocol profile matrix](../protocol/profile-matrix.md) for the
assurance requirements.

## Administration, provisioning and security events

| Capability or specification | Workers | Native | Conditions |
| --- | :---: | :---: | --- |
| User administration and tenant administrator hierarchy | √ | √ | List, create, update roles and deactivate within the tenant. |
| Client templates and administrator-managed clients | √ | √ | Current administrator authority and client policy checks apply. |
| Application access requests and approval or rejection | √ | √ | Approval provisions the allowed client. |
| Protected one-use client credential delivery | √ | √ | Delivery is tied to the approved client and current credential version. |
| Grant administration and revocation | √ | √ | Retires dependent token families and credential access. |
| Client certificate trust requests and approvals | √ | √ | Tenant-bound trust anchors, revoke and PEM export. Requires mTLS configuration. |
| External login provider administration view | √ | √ | Displays configured provider metadata. |
| Runtime module enable, disable, drain and event history | √ | √ | Dependencies, expected revisions and deployment capability ceiling apply. |
| SCIM 2.0 discovery (RFC 7643 and RFC 7644) | √ | √ | `scim` and a scoped SCIM credential. |
| SCIM Users create, retrieve, list, replace, bounded PATCH and soft delete | √ | √ | `scim`. Includes deactivation and active-user policy. |
| SCIM index pagination and bounded userName filter | √ | √ | Exact supported `userName eq` filter. |
| SCIM cursor pagination (RFC 9865) | √ | √ | Credential-, filter- and tenant-bound cursor. |
| Signed Security Event Tokens (RFC 8417) | √ | √ | `scim_security_events` and `scim`. |
| SCIM provisioning notices (RFC 9967) | √ | √ | Bounded User mutation notices. Soft delete emits a deactivation notice. |
| Security event polling, acknowledgements and errors (RFC 8936) | √ | √ | Receiver-bound signed SETs and bounded long polling. |
| Required audit committed with protected mutations | √ | √ | Append-only ledger. |
| Independent external audit anchoring | — | √ | Native audit exporter, receipts and checkpoints. |

See [SCIM](../features/scim.md), [onboarding](../features/ecosystem-onboarding.md)
and [audit anchoring](../security/audit-anchor.md).

## Digital credentials

| Capability or specification | Workers | Native | Conditions |
| --- | :---: | :---: | --- |
| OpenID4VCI 1.0 Final Credential Issuer | √ | √ | `openid4vci_issuer`, managed key material, configuration and issuer-management authority. |
| Credential issuer metadata and proof nonce | √ | √ | Published and admitted with the issuer module. |
| Credential offers and issuer-initiated pre-authorized issuance | √ | √ | Managed offer, subject and one-use grant policy. |
| Wallet-initiated authorization-code issuance | √ | √ | Configured credential profile and authorization requirements. |
| Managed credential datasets | √ | √ | Subject/configuration-scoped administration. |
| Immediate credential issuance | √ | √ | Available for the configured credential format and signing policy. |
| Deferred credential issuance | √ | √ | Explicit per-credential configuration. |
| Credential response retry and wallet notification | √ | √ | Protected response state and bounded replay semantics. |
| Credential proof and holder binding | √ | √ | Configured proof types, attestation trust and issuer policy. |
| OpenID4VCI refresh and client instance key binding | √ | √ | Credential authorization and active sender binding are rechecked. |
| OAuth Client Attestation draft-07 for OpenID4VCI/HAIP | √ | √ | `attest_jwt_client_auth` requires attestation trust and applicable client policy. |
| OpenID4VP 1.0 Final Verifier | √ | √ | `openid4vp_verifier`, verifier-management authority and trust configuration. |
| OpenID4VP signed requests and DCQL | √ | √ | Supported query shapes, client identifier and request binding. |
| OpenID4VP `direct_post.jwt` presentation and result retrieval | √ | √ | Encrypted response, replay protection and protected result access. |
| HAIP 1.0 SD-JWT VC (`dc+sd-jwt`), issuance and verification | √ | √ | Configured certificate, trust and holder-binding profile. |
| HAIP 1.0 mdoc (`mso_mdoc`, ISO/IEC 18013-5), issuance and verification | √ | √ | Configured DS/IACA material, certificate path and revocation policy. |
| JWT/CWT Token Status List verification (draft-21) | √ | √ | Bounded validation. Workers requires admitted status-list HTTPS origins. |
| Certificate revocation checks for credential verification | √ | √ | Worker verifier uses the required-revocation policy. |
| mdoc CRL publication | √ | √ | Worker validates and publishes offline-signed CRLs. Native can generate and publish with managed IACA material. |
| Host-managed mdoc CRL signing and automatic renewal | — | √ | Native can renew on demand when the current CRL expires or authority changes. |

See the [OpenID4VC verification boundaries](../protocol/openid4vc-validation.md)
and [managed mdoc state](mdoc-shared-state.md).

## Hosting, keys and operations

| Capability or specification | Workers | Native | Conditions |
| --- | :---: | :---: | --- |
| Single configured HTTPS issuer and tenant | √ | √ | Tenant, realm and organization are bound to the configured issuer. |
| Configured tenant, realm and organization isolation | √ | √ | Tenant-scoped clients, users, grants, state and signing keys. |
| Multiple issuers and tenant directories in one service deployment | — | √ | Native resolves configured hosts to separate tenant service graphs. |
| Live tenant directory management and convergence | — | √ | Native directory and control-plane configuration required. |
| Cross-tenant administrator management | — | √ | Requires native control-plane authority. |
| Independent deployment per issuer | √ | √ | Each Worker needs its own issuer and bindings. |
| D1 database and transient state | √ | — | D1 owns durable and one-use security state on Workers. |
| PostgreSQL persistent state | — | √ | Supports separate runtime and lifecycle database roles. |
| Valkey transient state | — | √ | Native replay, rate-limit and other transient state. |
| Atomic state consumption, replay protection and revocation | √ | √ | Shared behavior with host-specific persistence. |
| HTTP readiness, liveness and startup probes | √ | √ | Shared service routes. |
| Trusted inbound client certificates | √ | √ | Direct Cloudflare metadata on Workers. Direct TLS or trusted ingress on native. |
| Dedicated native mTLS listener or trusted-proxy certificate forwarding | — | √ | Requires explicit certificate source and proxy trust configuration where applicable. |
| HTTPS/TLS deployment controls (RFC 9325 / BCP 195) | √ | √ | Cloudflare ingress or native TLS configuration. TLS policy is a deployment responsibility. |
| NazoAuth-managed outbound client certificates for integration callbacks | — | — | Inbound mTLS is covered separately. |
| Bounded outbound retrieval of JWKS, Request Objects and sector documents | √ | √ | Workers admits exact HTTPS origins. Native applies its outbound transport policy. |
| Configurable CORS and trusted source IP handling | √ | √ | Host-specific ingress trust and endpoint policies. |
| Rate limiting and expiry maintenance | √ | √ | Workers uses D1 and scheduled events. Native uses host stores and workers. |
| Service-wide protocol tuning and token/session lifetime settings | — | √ | Native exposes PAR, DPoP nonce, Request Object replay and lifetime settings. Shared per-client controls are listed above. |
| Local issuer signing (RS256, PS256, ES256, EdDSA) | √ | √ | Shared algorithms. Worker signing uses WebCrypto. |
| Encrypted signing generations and wrapping-key rotation | √ | √ | Host persistence and configured wrapping keys. |
| Signing key generation, prepublication, activation and retirement | √ | √ | Worker initial material is provisioned offline. Measure generation capacity on the selected plan. |
| External signing through an operator subprocess | — | √ | `SIGNING_EXTERNAL_COMMAND` can bridge to a KMS or HSM. |
| Built-in direct HTTP KMS/HSM signing adapter | — | — | Native integrates via its external signer command. |
| Application-level OTLP export | — | √ | Native OTLP HTTP/protobuf for traces, metrics and logs. |
| Cloudflare-managed Workers Logs and Traces export | √ | — | Platform observability and configured destinations. |
| NazoAuthCtl control discovery and controller registry | — | √ | Native `deployment-control` surface. |
| NazoAuthCtl recovery-root management and recovery handshake | — | √ | Native with separate recovery authority. |
| NazoAuthCtl host install, upgrade, backup and restore | — | √ | Companion controller. Workers versions and resource recovery use Cloudflare tooling. |
| Cloudflare Worker version deployment and rollback | √ | — | Operated independently of the Worker runtime. |
| Native host/container deployment | — | √ | Host, Docker or Podman deployment. |

The [Workers guide](cloudflare-workers.md#service-prerequisites-and-remaining-host-boundaries)
and [native configuration guide](configuration.md) document host prerequisites.
The Workers Free CPU and startup budgets apply to the selected profile and
workload.

## Capabilities outside both implementations

| Capability or specification | Workers | Native | Boundary |
| --- | :---: | :---: | --- |
| OAuth Implicit Grant and OIDC Implicit OP | — | — | The authorization endpoint issues codes. |
| OIDC Hybrid OP | — | — | Front-channel token issuance is excluded. |
| Resource Owner Password Credentials Grant | — | — | Local password sign-in is supported separately. |
| PKCE `plain` | — | — | S256 is the only accepted challenge method. |
| Unsigned Request Objects (`alg=none`) | — | — | Shared Request Object policy requires a signature. |
| `client_secret_jwt` authentication | — | — | JWT client authentication uses `private_key_jwt`. |
| JARM `form_post.jwt` | — | — | `jwt` is available for JARM. |
| CIBA push delivery and `user_code` | — | — | Poll and ping are implemented. |
| NazoAuth as a direct SAML service provider | — | — | The configured SAML gateway handles the upstream SAML protocol. |
| OpenID Federation 1.1 trust chains and trust marks | — | — | Configured external sign-in is supported separately. |
| Third-party JWT assertions and cross-domain Token Exchange | — | — | Shared grant profiles are bounded to registered clients and local tokens. |
| SCIM Groups, Bulk, sorting and enterprise-user extensions | — | — | Shared supported SCIM subset is Users. |
| SCIM async operations, hard-delete SETs and push delivery | — | — | Shared SET delivery is bounded provisioning notices via poll. |
| OpenID4VC Wallet role | — | — | NazoAuth provides Issuer and Verifier roles. |
| Token Status List allocation and publication | — | — | Credential verifiers can validate externally published lists. |
| Refresh Token and Authorization Expiration draft | — | — | Shared refresh rotation and configured lifetime are available. |
| OAuth First-Party Applications and Client ID Metadata Document drafts | — | — | Tracked in the standards roadmap. |
| SPIFFE Client Authentication, Identity Assertion, Identity Chaining and Transaction Tokens | — | — | Tracked in the standards roadmap. |

See the [security exclusions](../protocol/not-implemented-security-policy.md)
and [standards roadmap](../protocol/rfc-compliance-matrix.md#current-oauth-standards-roadmap)
for compatibility exceptions, unaudited revisions and watchlist drafts.

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
