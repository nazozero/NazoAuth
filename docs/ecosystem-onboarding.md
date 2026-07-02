# Ecosystem Onboarding

## Scope

The default scope keeps ecosystem onboarding features outside the
authorization-server core. The features expand the protocol attack surface and
stay out of discovery metadata until implementation, tests, and deployment
policy explicitly enable them.

## Dynamic Client Registration

### Boundary

RFC 7591 Dynamic Client Registration is implemented as a default-closed
protocol surface.

- DCR changes client creation from an administrator-controlled action into a protocol surface exposed to external callers.
- Redirect URI validation, inline JWKS, software statements, initial access tokens, and client metadata updates all become security-critical input paths.
- The admin client API remains the default explicit onboarding path.
- `/register` is mounted and `registration_endpoint` is advertised only when
  `ENABLE_DYNAMIC_CLIENT_REGISTRATION=true`.
- Public deployments should set
  `DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN`; otherwise registration is
  intentionally open for controlled test deployments only.
- `software_statement` and remote `jwks_uri` fetching are not supported by
  the baseline RFC 7591 endpoint.
- RFC 7592 Client Configuration Management is available only for clients
  created through DCR and only while `ENABLE_DYNAMIC_CLIENT_REGISTRATION=true`.

### Activation Criteria

- Initial access token issuance, scope, expiry, replay prevention, and revocation for public ecosystem onboarding.
- Redirect URI validation, including loopback/native exceptions and exact-match web redirects.
- Client metadata overclaiming, including grant types, response types, token endpoint auth methods, JAR/JARM policy, PAR policy, and logout URLs.
- Optional `jwks_uri` fetching, cache lifetime, stale-key behavior, SSRF prevention, host allowlists, size limits, MIME validation, timeout policy, and key rotation.
- Inline `jwks` validation, including rejection of private key material and unsupported `use`, `kty`, `alg`, or duplicate `kid` values.
- Software statement trust anchors, issuer/audience validation, expiry windows, replay prevention, metadata merge rules, and audit evidence.
- Registration access token storage and rotation use server-side BLAKE3 hashes;
  plaintext registration access tokens are returned only in DCR management
  responses.
- Metadata truth tests proving discovery only advertises DCR when the registration endpoint is enabled and protected.

### Required Tests

- DCR is absent from discovery by default and `/register` is not routed when disabled.
- Invalid redirect URIs are rejected.
- Weak or unsupported client authentication metadata is rejected.
- `jwks_uri` is rejected until remote fetch policy exists; if adopted later, it cannot fetch loopback, link-local, private, metadata-service, or non-HTTPS URLs unless an explicit deployment allowlist permits them.
- Duplicate `kid`, private JWK material, and stale JWKS cache behavior are covered.
- Initial access token replay and expired-token paths fail closed.
- Registered clients cannot escalate from public to confidential or from baseline to FAPI profile capabilities without policy approval.

## Client Configuration Management

### Boundary

RFC 7592 Client Configuration Management is implemented as part of the
default-closed DCR surface.

- DCRM inherits every DCR risk and adds update/delete authority over existing clients.
- Client update is full-replacement PUT semantics, not partial PATCH. The
  client must present the current `client_id`; clients with a stored
  `client_secret` must also present the matching current secret.
- Server-managed fields are immutable from the client request:
  `registration_access_token`, `registration_client_uri`,
  `client_secret_expires_at`, and `client_id_issued_at`.
- Successful read and update responses rotate the registration access token.
  Secret-authenticated dynamic clients also receive a rotated `client_secret`
  because the server stores only Argon2 hashes, never recoverable plaintext
  secrets.
- DELETE deactivates the client, clears the registration access token hash,
  revokes active refresh-token rows for the client, and removes stored user
  grants. Existing self-contained access tokens remain bounded by their normal
  expiry and resource-side revocation checks.

### Activation Criteria

- Audit events for RFC 7592 read/update/delete lifecycle operations.
- Optional `jwks_uri` fetching, if ever supported, with SSRF and cache controls.
- Software statement trust anchors and metadata merge policy.
- Browser or black-box conformance fixtures that exercise the full
  registration management lifecycle against a deployed issuer.

## Device Authorization Grant

### Boundary

The Device Authorization Grant is implemented but outside the default scope. It
fits CLI, TV, appliance, and constrained-input clients only when
`ENABLE_DEVICE_AUTHORIZATION_GRANT=true` and the client registration explicitly
allows `urn:ietf:params:oauth:grant-type:device_code`.

### Activation Criteria

- User code entropy, display format, expiry, brute-force limits, and replay behavior.
- Device code entropy, storage, expiry, and one-time completion.
- Polling interval enforcement, `slow_down`, expired token behavior, and client rate limits.
- Binding between the browser approval session, displayed client identity, requested scopes, `authorization_details`, resources, and the device code.
- Phishing-resistant UI language and audit events for approved, denied, expired, and rate-limited flows.
- Profile matrix changes for public versus confidential device clients.
- Discovery metadata must remain absent unless `ENABLE_DEVICE_AUTHORIZATION_GRANT=true`.

### Required Tests

- Pending token request returns `authorization_pending`.
- Too-frequent polling returns `slow_down`.
- Expired device code and expired user code fail closed.
- Wrong user code cannot reveal whether a real code exists beyond generic errors.
- Approved code issues tokens only once and preserves scope, audience, DPoP/mTLS sender constraints where applicable, and consent binding.

## Token Exchange

### Boundary

RFC 8693 Token Exchange is implemented for a bounded local profile: a
confidential client registered for
`urn:ietf:params:oauth:grant-type:token-exchange` can exchange a locally issued
access token for a new locally issued access token. The request must include a
valid `subject_token`, `subject_token_type`, and an explicit `resource` or
`audience`. `actor_token` is optional and, when present, must also be a locally
issued access token for the authenticated client.

The implementation does not trust external issuers, does not exchange refresh
tokens or ID tokens, and does not issue refresh tokens from token exchange.

### Activation Criteria

- External subject-token or actor-token issuer trust.
- Refresh-token and ID-token exchange profiles.
- `authorization_details` propagation beyond empty access-token exchanges.
- Sender-constrained actor-token proof composition.
- Product audit events that distinguish the requesting client, subject token client, subject, actor, audience, and policy decision.

### Required Tests

- Exchange cannot mint a token for a target not allowed to the requesting client.
- Requested scopes must be equal to or narrower than both the subject token and client registration.
- Expired, revoked, wrong-issuer, wrong-tenant, unauthorized-subject, and sender-constraint mismatch tokens are rejected.
- Actor tokens are validated and serialized through the `act` claim when delegation is requested.

## Example Client Matrix

Examples and fixtures are protocol contracts. Each example includes at least one
negative path.

| Client type | Primary profile | Required fixture coverage |
| --- | --- | --- |
| Backend web | OIDC authorization code + PKCE | exact redirect URI, nonce, state, refresh policy, logout redirect |
| SPA | public authorization code + PKCE | no client secret, S256 only, CORS and redirect boundary |
| Native app | public authorization code + PKCE | loopback redirect port exception, custom scheme rejection rules |
| Machine-to-machine | client credentials | confidential client auth, no `openid`, audience binding |
| DPoP client | authorization code or client credentials | proof `jti`, `ath`, nonce challenge, sender-constrained token |
| `private_key_jwt` client | confidential profiles | assertion `aud`, `exp`, `iat`, `jti`, replay, key rotation |

Fixtures belong under `docs/conformance` or `examples` and must stay aligned with discovery metadata and the profile matrix.
