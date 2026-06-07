# External Identity Federation

The identity platform supports external OIDC federation and a trusted SAML gateway mode. Federation is a product identity feature and is not part of OAuth/OIDC AS conformance.

## OIDC Federation

OIDC federation is configured as a single deployment provider:

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

The flow uses authorization code, PKCE S256, nonce, short-lived Valkey state, token endpoint exchange, JWKS lookup, and ID Token verification for issuer, audience, expiry, nonce, `kid`, and signature. The server requires an email claim and rejects explicitly unverified email.

## SAML Gateway Federation

The app does not directly accept raw SAML XML or unsigned browser-posted assertions. SAML support is through a trusted gateway that performs SAML XML parsing, XMLDSig validation, IdP metadata enforcement, and replay handling before forwarding a compact signed assertion to this service.

Configuration:

- `FEDERATION_SAML_GATEWAY_ENABLED`
- `FEDERATION_SAML_GATEWAY_ISSUER`
- `FEDERATION_SAML_GATEWAY_AUDIENCE`
- `FEDERATION_SAML_GATEWAY_SECRET`

Endpoint:

- `POST /auth/federation/saml/acs`

The gateway assertion is HMAC-SHA256 signed over issuer, audience, subject, normalized email, `iat`, and `exp`. The app enforces issuer, audience, timestamp bounds, five-minute maximum assertion lifetime, normalized email, and constant-time signature comparison.

## Identity Linking

External identities are stored in `external_identity_links` and bound to the default tenant. The unique key is `(tenant_id, provider_type, provider_id, subject)`.

If a link already exists, the linked active user is used. If no link exists but an active user with the same email exists in the default tenant, the new external identity is linked to that user. If no user exists, a local user is provisioned with a random unusable password hash and `email_verified=true`.

Successful federation login creates the normal HTTPOnly server-side session with `amr` containing the federation method and `federated`.
