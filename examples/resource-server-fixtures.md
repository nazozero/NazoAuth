# Resource Server and Client Fixtures

## Scope

Fixtures define minimum example coverage for resource servers and common
OAuth/OIDC clients. They act as protocol contracts until executable example
clients move into dedicated crates.

## Backend Web Client

Positive path:

- Confidential client using authorization code + S256 PKCE.
- Exact registered redirect URI.
- `state` and OIDC `nonce`.
- `openid profile email offline_access`.
- Exact `post_logout_redirect_uri` for RP-Initiated Logout.

Negative path:

- Mismatched redirect URI is rejected.
- Authorization code cannot be redeemed without the matching PKCE verifier.
- Unregistered post-logout redirect URI is rejected.

## SPA Client

Positive path:

- Public client with authorization code + S256 PKCE.
- No client secret.
- Browser origin present in CORS allowlist.

Negative path:

- `client_secret_post` is rejected for public clients.
- Plain PKCE is rejected.
- Redirect URI not registered to the SPA is rejected.

## Native Client

Positive path:

- Public client with loopback redirect URI and dynamic port.
- S256 PKCE.

Negative path:

- Non-loopback HTTP redirect URI is rejected.
- Custom scheme redirect URI must match the registered scheme exactly.
- Missing PKCE is rejected.

## Machine-to-Machine Client

Positive path:

- Confidential client credentials grant.
- `private_key_jwt` or mTLS client authentication.
- Explicit resource audience.
- No OIDC `openid` scope.

Negative path:

- `openid` scope is rejected for client credentials clients.
- Wrong client assertion `aud` is rejected.
- Access token with wrong audience is rejected by the resource-server verifier.

## DPoP Client

Positive path:

- Authorization code or client credentials flow with DPoP proof.
- Access token includes `cnf.jkt`.
- Resource request includes DPoP proof with matching `ath`, `htu`, `htm`, and unused `jti`.

Negative path:

- Replayed proof `jti` is rejected.
- Wrong `ath` is rejected.
- Bearer presentation of a DPoP-bound token is rejected.
- Missing nonce is challenged when nonce policy requires it.

## `private_key_jwt` Client

Positive path:

- Confidential client with registered JWKS.
- Client assertion includes exact `iss`, `sub`, accepted `aud`, bounded `iat`/`exp`, and unique `jti`.

Negative path:

- Replayed assertion `jti` is rejected.
- Stale JWKS `kid` is rejected until metadata is rotated.
- Disabled client cannot authenticate even with a valid assertion.
