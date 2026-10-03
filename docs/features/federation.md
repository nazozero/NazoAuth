# External Identity Federation

## Scope

External federation belongs to the identity-platform surface. It is separate
from OAuth/OIDC authorization-server conformance.

Supported federation modes:

- configuration-driven external provider registry
- multiple modular external OIDC provider instances
- OAuth2 social provider adapters for QQ, WeChat, and custom JSON userinfo providers
- one trusted SAML gateway integration
- tenant-scoped external identity links in the resolved request runtime
- normal HTTPOnly server-side sessions after successful federation login

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

The admin view reports callback URLs and whether secret-backed fields are
configured, but it does not return client secrets, provider access tokens, JWKS
contents, or raw assertions.

## External OIDC Login

OIDC providers can be configured as registry entries with `adapter_type:
"oidc"` inside `FEDERATION_PROVIDER_CONFIGS`. Each provider owns its callback
URL through its `provider_id`.

Endpoints:

- `GET /auth/federation/{provider_id}/start`
- `GET /auth/federation/{provider_id}/callback`

The flow uses authorization code, PKCE S256, nonce, short-lived Valkey state,
token endpoint exchange, JWKS lookup, and ID Token verification. The server
checks issuer, audience, expiry, nonce, `kid`, and signature. The ID Token must
contain an email claim and `email_verified=true`; absent or false verification
claims are rejected before account lookup, linking, or provisioning.

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
The Valkey adapter performs exactly one namespaced EVAL: GET, protected JSON
decode, browser-hash comparison, and DEL only on a match. A missing, legacy,
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
There is no legacy grace acceptance and no safety guarantee for mixed old/new
callback handlers. No database migration or queue is required.

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
without email can only authenticate an already linked external identity; they do
not auto-provision or auto-link local accounts.

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

External identities are stored in `external_identity_links` and bound to the
tenant selected from the request host. The unique key is `(tenant_id,
provider_type, provider_id, subject)`. The provider registry is process
configuration, while account lookup, linking, provisioning, session creation,
and transient federation state execute through that resolved tenant graph.

Resolution order:

- an existing active link selects the linked user
- without an existing link, a same-email local user is not auto-linked
- otherwise a local user is provisioned with a random unusable password hash and
  `email_verified=true`

Existing lookup, new provisioning and unique-conflict recovery all pass the same
active-account gate on the account returned by storage before session creation.
Upstream identity proof is not repeated at this gate.

Successful federation login creates the normal HTTPOnly server-side session.
The session `amr` contains the federation method and `federated`.

Current users can inspect and remove their own external identity links through:

- `GET /auth/me/federation/links`
- `DELETE /auth/me/federation/links/{link_id}`

The link list uses a tenant/user-scoped metadata projection without loading raw
provider claims. Unlink keeps the complete deleted-link result for its existing
audit contract. Unlink operations are scoped by the
current session user, require the same configured cookie/header CSRF token check
as other profile writes before account/link lookup, and emit
`external_identity_unlinked` audit events.

Local session state remains the NazoAuth fact source. External provider logout
failures do not mark remote logout as complete; local `/auth/logout` and OIDC
OP logout clear the local session independently of upstream provider state.
