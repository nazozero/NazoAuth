# External Identity Federation

## Scope

External federation belongs to the identity-platform surface. It is separate
from OAuth/OIDC authorization-server conformance.

Supported federation modes:

- one configured external OIDC provider
- one trusted SAML gateway integration
- default-tenant external identity links
- normal HTTPOnly server-side sessions after successful federation login

## External OIDC Login

Configure the OIDC provider with:

- `FEDERATION_OIDC_PROVIDER_ID`
- `FEDERATION_OIDC_ISSUER`
- `FEDERATION_OIDC_AUTHORIZATION_ENDPOINT`
- `FEDERATION_OIDC_TOKEN_ENDPOINT`
- `FEDERATION_OIDC_JWKS_URL`
- `FEDERATION_OIDC_CLIENT_ID`
- `FEDERATION_OIDC_CLIENT_SECRET`
- `FEDERATION_OIDC_REDIRECT_URI`
- `FEDERATION_OIDC_SCOPES`

Endpoints:

- `GET /auth/federation/oidc/start`
- `GET /auth/federation/oidc/callback`

The flow uses authorization code, PKCE S256, nonce, short-lived Valkey state,
token endpoint exchange, JWKS lookup, and ID Token verification. The server
checks issuer, audience, expiry, nonce, `kid`, and signature. The ID Token must
contain an email claim and `email_verified=true`; absent or false verification
claims are rejected before account lookup, linking, or provisioning.

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
and constant-time signature comparison.

## Identity Linking

External identities are stored in `external_identity_links` and bound to the
default tenant. The unique key is `(tenant_id, provider_type, provider_id,
subject)`.

Resolution order:

- an existing active link selects the linked user
- an active same-email user in the default tenant receives the new link
- otherwise a local user is provisioned with a random unusable password hash and
  `email_verified=true`

Successful federation login creates the normal HTTPOnly server-side session.
The session `amr` contains the federation method and `federated`.
