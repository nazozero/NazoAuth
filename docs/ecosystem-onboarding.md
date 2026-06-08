# Ecosystem Onboarding

Version 1 keeps ecosystem onboarding features outside the default authorization-server core. They are useful for some deployments, but they expand the protocol attack surface and stay out of discovery metadata until implemented, tested, and enabled by policy.

## Dynamic Client Registration

RFC 7591 Dynamic Client Registration is outside the default version 1 scope.

Rationale:

- DCR changes client creation from an administrator-controlled action into a protocol surface exposed to external callers.
- Redirect URI validation, JWKS URI fetching, software statements, initial access tokens, and client metadata updates all become security-critical input paths.
- The current admin client API already supports explicit client onboarding without advertising DCR metadata.

Enable DCR only after a dedicated threat model covers:

- Initial access token issuance, scope, expiry, replay prevention, and revocation.
- Redirect URI validation, including loopback/native exceptions and exact-match web redirects.
- Client metadata overclaiming, including grant types, response types, token endpoint auth methods, JAR/JARM policy, PAR policy, and logout URLs.
- `jwks_uri` fetching, cache lifetime, stale-key behavior, SSRF prevention, host allowlists, size limits, MIME validation, timeout policy, and key rotation.
- Inline `jwks` validation, including rejection of private key material and unsupported `use`, `kty`, `alg`, or duplicate `kid` values.
- Software statement trust anchors, issuer/audience validation, expiry windows, replay prevention, metadata merge rules, and audit evidence.
- Registration access token storage, rotation, update/delete authorization, disabled-client behavior, and audit events.
- Metadata truth tests proving discovery only advertises DCR when the registration endpoint is enabled and protected.

Acceptance tests before enabling DCR:

- DCR is absent from discovery by default.
- Invalid redirect URIs are rejected.
- Weak or unsupported client authentication metadata is rejected.
- `jwks_uri` cannot fetch loopback, link-local, private, metadata-service, or non-HTTPS URLs unless an explicit deployment allowlist permits them.
- Duplicate `kid`, private JWK material, and stale JWKS cache behavior are covered.
- Initial access token replay and expired-token paths fail closed.
- Registered clients cannot escalate from public to confidential or from baseline to FAPI profile capabilities without policy approval.

## Client Configuration Management

RFC 7592 Client Configuration Management stays disabled until DCR has a complete implementation and threat model.

Rationale:

- DCRM inherits every DCR risk and adds update/delete authority over existing clients.
- Client update can silently weaken redirect URI, JWKS, logout, token auth, grant, or profile policy if metadata merge rules are not strict.
- Delete/deactivate semantics affect active sessions, refresh token families, outstanding authorization codes, PAR handles, and audit retention.

Enable DCRM only after these semantics are defined:

- Registration access token binding to a single client.
- Full replacement versus partial update semantics.
- Immutable fields, including internal database id, tenant or realm binding, initial trust source, and profile assignment.
- Rotation semantics for `client_secret`, `jwks`, `jwks_uri`, mTLS certificate material, and back-channel logout URLs.
- Deactivation and deletion effects on active tokens, refresh families, grants, sessions, and back-channel logout.
- Negative tests for update attempts that add overclaimed metadata or weaken authentication.

## Device Authorization Grant

The Device Authorization Grant is outside the default version 1 scope. It fits CLI, TV, appliance, and constrained-input clients after user-code phishing and polling-abuse controls are designed.

Required design points:

- User code entropy, display format, expiry, brute-force limits, and replay behavior.
- Device code entropy, storage, expiry, and one-time completion.
- Polling interval enforcement, `slow_down`, expired token behavior, and client rate limits.
- Binding between the browser approval session, displayed client identity, requested scopes, `authorization_details`, resources, and the device code.
- Phishing-resistant UI language and audit events for approved, denied, expired, and rate-limited flows.
- Profile matrix changes for public versus confidential device clients.

Minimum acceptance tests:

- Pending token request returns `authorization_pending`.
- Too-frequent polling returns `slow_down`.
- Expired device code and expired user code fail closed.
- Wrong user code cannot reveal whether a real code exists beyond generic errors.
- Approved code issues tokens only once and preserves scope, audience, DPoP/mTLS sender constraints where applicable, and consent binding.

## Token Exchange

RFC 8693 Token Exchange is outside the default version 1 scope. It fits service delegation, impersonation, and actor-token deployments after policy and audit boundaries are specified.

Required design points:

- Allowed subject token types and actor token types.
- Delegation versus impersonation semantics.
- Audience narrowing and prohibition on privilege amplification.
- Scope and `authorization_details` downscoping rules.
- `act` claim shape for actor chains and maximum chain length.
- Sender-constraint preservation or rebinding policy for DPoP and mTLS-bound tokens.
- Introspection and revocation behavior for exchanged tokens.
- Audit events that distinguish the requesting client, subject token client, subject, actor, audience, and policy decision.

Minimum acceptance tests:

- Exchange cannot mint a token for an audience not allowed to the requesting client and subject token.
- Requested scopes and authorization details must be equal or narrower than the subject token unless an explicit policy grants escalation.
- Expired, revoked, wrong-issuer, wrong-audience, and bearer-at-sender-constrained-boundary tokens are rejected.
- Actor token chains are bounded and serialized consistently.
- Introspection exposes enough data for a resource server to enforce delegated access.

## Example Client Matrix

The project maintains examples and fixtures as protocol contracts, not marketing samples. Each example must include at least one negative path.

| Client type | Primary profile | Required fixture coverage |
| --- | --- | --- |
| Backend web | OIDC authorization code + PKCE | exact redirect URI, nonce, state, refresh policy, logout redirect |
| SPA | public authorization code + PKCE | no client secret, S256 only, CORS and redirect boundary |
| Native app | public authorization code + PKCE | loopback redirect port exception, custom scheme rejection rules |
| Machine-to-machine | client credentials | confidential client auth, no `openid`, audience binding |
| DPoP client | authorization code or client credentials | proof `jti`, `ath`, nonce challenge, sender-constrained token |
| `private_key_jwt` client | confidential profiles | assertion `aud`, `exp`, `iat`, `jti`, replay, key rotation |

Fixtures belong under `docs/conformance` or `examples` and must stay aligned with discovery metadata and the profile matrix.
