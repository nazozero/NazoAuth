# External Identity Federation

## Scope

External federation belongs to the identity-platform surface. It is separate
from OAuth/OIDC authorization-server conformance.

Supported federation modes:

- configuration-driven external provider registry
- multiple external OIDC providers with static endpoints or issuer configuration
- OAuth2 social provider adapters for QQ, WeChat, and custom JSON userinfo providers
- one trusted SAML gateway integration
- tenant-scoped external identity links in the resolved request runtime
- HTTPOnly server-side sessions that retain the local account MFA requirement

`nazo-identity::federation` owns state, nonce and PKCE lifecycles, OIDC RP
authorization requests, ID Token validation, UserInfo subject binding and
upstream identity normalization. Its existing service resolves accounts,
creates sessions and records federation audit events. Shared JOSE key import
and S256 derivation belong to `nazo-crypto`.

The framework-neutral `nazoauth` facade owns callback extraction, HTTP request
construction, redirects and cookie presentation. The native host supplies
reqwest transport; the Worker host supplies bounded Fetch transport and admits
configured outbound origins. Both use the same RP semantics and provider
registry.

## Local MFA

OIDC, social, and SAML gateway login use the local account's `mfa_enabled`
setting. An enabled account receives a pending-MFA session and
`mfa_required=true`; its storage TTL, session/CSRF cookie lifetimes and response
`expires_in` use `PENDING_MFA_SESSION_TTL_SECONDS`. It must complete the existing
local MFA flow before accessing an authenticated session. Accounts without
local MFA receive the regular session lifetime.

## Provider Registry

Third-party login providers are loaded from `FEDERATION_PROVIDER_CONFIGS`, a
JSON array of provider definitions. Each provider has its own `provider_id`,
`enabled` flag, display name, adapter type, client credentials, redirect URI,
scope, provider endpoints, claim mapping, optional icon, and display order.

Enabled providers are exposed to the login UI through:

- `GET /auth/federation/providers`

Provider-specific login routes are:

- `GET /auth/federation/{provider_id}/start`
- `GET /auth/federation/{provider_id}/callback`

Disabled providers are not returned by the public provider list and cannot be
started through the dynamic route. Admin onboarding can inspect non-secret
provider state through:

- `GET /admin/federation/providers`

The admin view reports callback URLs and endpoint/credential configuration
status, including which OIDC providers enable discovery or Back-Channel Logout. Client
secrets, provider access tokens, JWKS contents and raw assertions are excluded.

## External OIDC Login

OIDC providers can be configured as registry entries with `adapter_type:
"oidc"` inside `FEDERATION_PROVIDER_CONFIGS`. Each provider owns its callback
URL through its `provider_id`.

Endpoints:

- `GET /auth/federation/{provider_id}/start`
- `GET /auth/federation/{provider_id}/callback`

The flow uses authorization code, PKCE S256, nonce, short-lived server-side
state, `client_secret_basic` token exchange, JWKS lookup and ID Token
verification. The native host stores transient state in Valkey; the Worker
host uses its D1 state adapter.

ID Token verification checks the exact configured issuer, subject, client
audience, expiry, required `iat`, nonce and signature. Each audience must equal
the configured client ID; `azp` does not establish trust in another audience.
Expiry must be later than the current time, and `iat` may be at most 60 seconds
in the future. The default signing algorithm is RS256. Configure
`id_token_signed_response_alg` to match a registration using PS256, ES256 or
EdDSA with Ed25519. Both ID Tokens and Logout Tokens must use the selected
algorithm.

JWKS is fetched for each callback. A supplied `kid` must occur exactly once in
the JWKS, and that key must be usable for the declared algorithm. An ID Token
without `kid` is accepted only when the JWKS contains exactly one usable public
signing key for its declared algorithm.

### Issuer Configuration

Set `discovery: true` with a preconfigured HTTPS `issuer`, the existing client
credentials and the registered callback. Omit the static authorization, token,
JWKS and UserInfo endpoints. NazoAuth fetches the issuer's
`/.well-known/openid-configuration` document at login start, checks the exact
issuer, required subject and signing capabilities, and support for authorization
code with `client_secret_basic`. The document must advertise the selected
signing algorithm. The validated endpoints are bound to that browser's callback
state. Discovery is limited to the configured issuer. See
[OpenID Connect Discovery §4](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig).

Discovered endpoints must use HTTPS. The configured issuer origin has the
operator's explicit trust, so Native supports private enterprise issuers and
same-origin discovery endpoints through its configured transport. Metadata-selected
origins that differ by host, scheme or port use the public-network transport:
Native validates the actual DNS answers when opening a connection and reuses
admitted TLS connections. IP literals receive the same check against private and
special-use networks. Worker requires every server-side origin, including the
issuer and any distinct JWKS or UserInfo origin, in its outbound allowlist. TLS
validation, response limits and the no-redirect policy apply to both paths.

### Back-Channel Logout

Enable `backchannel_logout: true` on an OIDC entry and register
`POST /auth/federation/{provider_id}/backchannel-logout` as the client's
back-channel logout URI at the upstream OP. Register an absolute URL for the
same tenant host used for sign-in. For new logins, the RP records the verified
upstream session ID if present and the upstream subject, scoped to the tenant,
provider, issuer and client. The tenant UUID is part of each upstream scope digest;
Valkey and D1 therefore cannot share revocation markers across tenants. Reauthenticate sessions established before the
setting was enabled to attach them to the upstream session.

The OP posts a signed `logout_token` as form data. NazoAuth verifies it against
the configured issuer and client, invalidates sessions by `sid` when provided,
or by `sub` otherwise, and returns HTTP 200 even if those sessions have already
expired. Invalid tokens and failed logout operations return HTTP 400.
A logged-out `sid` remains invalid through the local session lifetime,
including when another ID Token for that same upstream session has a later
`iat`. A subject-only logout revokes matching local login sessions, including
pending MFA and callbacks whose login flow began before the logout was accepted.
This cutoff uses local flow start and receipt times at second precision; flows
started in the same second are included. RP instances must keep their clocks
synchronized. An in-flight callback must finish within the original login flow's
lifetime before its session is returned. Each accepted subject-only retry applies
to the sessions present at that time. Downstream client
logout delivery and downstream token revocation are outside this flow. See
[OpenID Connect Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html).

### Initiating logout with the upstream OP

For a discovery provider with back-channel logout enabled, set
`post_logout_redirect_uri` to an application URL on the callback's origin and
register that URL with the OP. The OP must publish an HTTPS
`end_session_endpoint`. Send the signed-in browser to
`POST /auth/federation/{provider_id}/logout` with its session and a CSRF token
in the `csrf_token` form field or `X-CSRF-Token` header.

The endpoint returns an auto-submitting form addressed to the upstream OP.
The form carries the verified ID Token as an `id_token_hint` and the registered
return URL. NazoAuth keeps the hint and endpoint encrypted in the session
for this opt-in flow. Rotating the upstream client secret requires a fresh
login to initiate logout. The incoming signed Back-Channel Logout request
invalidates the local session.

### UserInfo and Profile Claims

An OIDC provider can configure an optional `userinfo_endpoint` in its registry
entry or obtain it through discovery. With discovery and only the `openid`
scope, the callback uses the signed ID Token alone. When UserInfo is used, the
callback fetches JSON UserInfo after ID Token
verification, using the token response's Bearer access token. UserInfo `sub`
must exactly match the subject in the verified ID Token before any profile
claim is used. A failed request, invalid response or subject mismatch stops
the login.

With UserInfo configured, its email and name claims supply the upstream profile.
With the endpoint omitted, the profile comes from the signed ID Token.
The identity projection retains issuer, subject, normalized verified email and
name fields. Third-party access and refresh tokens remain request-local.
Opted-in upstream logout retains only the encrypted ID Token hint and its
destination for the lifetime of the local session.

An existing active `(tenant_id, provider_type, provider_id, subject)` link can
authenticate without a verified email claim. Creating a new account requires
a syntactically valid email with `email_verified=true`. Missing, invalid or
unverified email cannot provision an account, and matching the email of an
existing local account never creates a new link to that account.

## Browser Binding and Callback State

OIDC and social starts require a browser binding independently of upstream nonce
and PKCE. HTTP reuses a canonical 32-byte random seed encoded as exactly 43
URL-safe base64 characters without padding. A missing or invalid seed is replaced
only on start. Each successful state write returns the redirect and renews the
same seed cookie for 300 seconds:

- Secure deployments use `__Host-nazo_federation_binding` with Secure,
  HttpOnly, SameSite=Lax, Path=/ and no Domain.
- The existing loopback HTTP development mode with `COOKIE_SECURE=false` uses
  `nazo_federation_binding` with the same attributes except Secure.

Identity accepts the borrowed seed and derives a 64-character lowercase BLAKE3
digest from the fixed `NazoAuth/federation/browser-binding/v1\0` domain,
tenant UUID bytes and seed. New state always carries this digest. The seed and
digest never enter provider URLs, token requests or audit events.

Callback validates the existing provider/query rules, then requires the configured
cookie before touching the federation state store, upstream exchange, account,
link or session. A missing or invalid cookie returns InvalidState (HTTP 400).
The native Valkey adapter uses one namespaced EVAL to read the value, check its
JSON browser binding and delete only on a match. The Worker D1 adapter performs
the same ownership check with a conditional `DELETE ... RETURNING` scoped to
the tenant, state kind, state key and expiry. A missing, expired, legacy,
corrupt-JSON or wrong-browser value returns StateExpired (HTTP 400); an existing
nonmatching value and its expiry are untouched. A matching but typed-corrupt
payload is consumed and rejected. State backend failures remain HTTP 503.
After a match, provider binding, freshness, nonce, PKCE and required audit
decisions retain their existing behavior.

Callback only reads this cookie and never clears or rotates it. An established
cookie supports parallel flows across providers. Two simultaneous first starts
without a cookie can create different seeds; whichever Set-Cookie arrives last
can make the other flow fail closed. Restart that flow after the browser has the
cookie. There is no per-flow cookie map or unbound acceptance path. Normal
session/CSRF cookies and SAML processing are unchanged.

### Upgrade Cutover

Quiesce old OIDC/social callback handlers and upgrade their routing before
enabling new starts. Old unbound state is rejected by the new callback path
throughout its remaining 300-second lifetime; users must restart those flows.
Keep callback routing on one version throughout this cutover. The transition
requires no database migration.

## OAuth2 Social Login

OAuth2 social providers use `adapter_type: "oauth2_social"` and a
provider-specific adapter. Built-in presets exist for:

- `provider_kind: "qq"`
- `provider_kind: "wechat"`

Custom providers can supply explicit authorization, token, and userinfo
endpoints plus claim names. QQ and WeChat are not treated as OIDC providers and
do not use ID Token validation. Their third-party access tokens are used only
inside the adapter to fetch external identity claims and are not persisted as
NazoAuth access tokens, session credentials, or long-lived local privileges.

Social adapters normalize a provider subject from `openid`, `unionid`, or a
configured subject claim. A verified email claim may be used as a contact and
provisioning attribute, but email is not the external identity root. Providers
without email authenticate an already linked external identity. An authenticated
local user can create that link through the account-binding endpoint below;
email is never required to bind a verified provider subject.

This is not an OpenID Federation trust-chain implementation. The service does
not expose `/.well-known/openid-federation` or implement Federation entity
statements, trust anchors, metadata policy, trust marks, or federation
fetch/list/resolve endpoints.

## SAML Gateway Federation

The application does not parse raw SAML XML and does not accept unsigned
browser-posted assertions. SAML support runs through a trusted gateway. The
gateway handles XML parsing, XMLDSig validation, IdP metadata checks, and replay
protection before forwarding a compact signed assertion to this service.

Configuration:

- `FEDERATION_SAML_GATEWAY_ENABLED`
- `FEDERATION_SAML_GATEWAY_ISSUER`
- `FEDERATION_SAML_GATEWAY_AUDIENCE`
- `FEDERATION_SAML_GATEWAY_SECRET`

Endpoint:

- `POST /auth/federation/saml/acs`

The gateway assertion is HMAC-SHA256 signed over issuer, audience, subject,
normalized email, `iat`, and `exp`. The application enforces issuer, audience,
timestamp bounds, a five-minute maximum assertion lifetime, normalized email,
and constant-time signature comparison. This is the application's custom JSON
gateway envelope, not a direct XML SAML assertion parser. The legacy `name`
member is unsigned; it is stored only as `untrusted_display_name` link metadata
and does not initialize the local display name or select identity/permissions.
Identity selection uses the authenticated provider type, issuer and subject.

## Identity Linking

Native PostgreSQL stores external identities in `external_identity_links`;
Worker D1 uses `nazo_federation_links`. Both bind links to the tenant selected
from the request host with the unique key `(tenant_id, provider_type,
provider_id, subject)`. The host configures the provider registry, while account
lookup, linking, provisioning, session creation and transient federation state
execute through that resolved tenant graph.

Resolution order:

- an existing active link selects the linked user
- without an existing link, a verified email is required to provision an account
- a same-email local user is not auto-linked
- otherwise a local user is provisioned with a random unusable password hash and
  `email_verified=true`

Existing lookup, new provisioning and unique-conflict recovery all pass the same
active-account gate on the account returned by storage before session creation.
Upstream identity proof is not repeated at this gate.

Successful federation login creates the normal HTTPOnly server-side session.
The session `amr` contains the federation method and `federated`.

Current users can inspect, explicitly bind and remove their own external identity links through:

- `GET /auth/me/federation/links`
- `POST /auth/me/federation/links/{provider_id}/start` (authenticated OIDC or OAuth2 social link start)
- `DELETE /auth/me/federation/links/{link_id}`

Linking starts with a fresh, fully authenticated local session and the
existing CSRF token (header or form field). The RP reuses the configured
provider's authorization-code flow, PKCE, browser binding, single-use state
and checked upstream subject. OIDC also validates its existing nonce and ID Token;
social providers use their existing token and UserInfo adapter. The consumed link state also binds the
initiating local user and session. The callback requires that exact active
session and a recent credential-management authentication, then inserts the
tenant-scoped subject or returns a conflict if another user owns it.
Successful binding does not rotate the local login session, create a user
or infer identity from matching email. A verified OIDC or social subject needs
no email claim when linked by a recently authenticated user. A new link and required
`external_identity_linked` audit event commit atomically on PostgreSQL and D1;
a repeated binding to the same user is idempotent. This is an ordinary
production account feature.

The link list uses a tenant/user-scoped metadata projection without loading raw
provider claims. Unlink keeps the complete deleted-link result for its existing
audit contract. Unlink operations are scoped by the
current session user and require a valid cookie/header CSRF token before
account/link lookup. A password or Passkey authentication completed
within five minutes is required, including interactive MFA for accounts that
require it. A federated-only session must first authenticate with a local
credential; users without a usable password can enroll and sign in with a
Passkey before unlinking. Successful removal emits
`external_identity_unlinked` in the same transaction.

Local session state remains the NazoAuth fact source. External provider logout
failures do not mark remote logout as complete; local `/auth/logout` and OIDC
OP logout clear the local session independently of upstream provider state.

Account creation, provider-link insertion and their Required
`external_identity_linked` audit event share one PostgreSQL transaction or D1
atomic batch. Reusing an existing link does not emit a second creation event.
A failed audit commit cannot leave a new linked account behind.

Endpoint and callback URLs may contain query parameters and trailing slashes;
the authorization redirect merges protocol parameters using URL query encoding.
Issuer identifiers retain their exact trailing slash and reject query
parameters, fragments and URL credentials. Client IDs and secrets retain their
exact configured bytes. OAuth Basic authentication form-encodes each credential
component before constructing the header.

Unlinking a federation identity and its required lifecycle audit share one
persistence transaction. Audit failure leaves the link intact.
