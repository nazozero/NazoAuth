# Profile Matrix

This matrix defines the project profiles separately from product hardening. A profile may only advertise metadata and behavior that the implementation and deployment can actually satisfy.

## Summary

| Profile | Purpose | Status |
| --- | --- | --- |
| `oauth2-baseline` | General OAuth authorization server profile for authorization code, refresh token, client credentials, revocation, introspection, metadata, and JWKS. | Implemented and covered by local matrix tests |
| `oauth2-security-bcp` | OAuth baseline constrained by RFC 9700-style security defaults. | Policy defined; enforced through baseline controls and client/profile policy |
| `oidc-basic-op` | OpenID Connect Authorization Code OP with discovery, ID Token, JWKS, and UserInfo. | OIDF-tested |
| `oidc-config` | OIDC discovery/server metadata verification. | OIDF-tested |
| `fapi2-security` | FAPI2 Security profile without message-signing options. | Runtime profile switch implemented; OIDF-tested for recorded matrix variants |
| `fapi2-message-signing-authz-request` | FAPI2 Security plus signed authorization requests at PAR. | Runtime profile switch implemented; OIDF-tested for recorded matrix variants |
| `fapi2-message-signing-jarm` | FAPI2 Message Signing authorization response signing option. | OIDF-tested for recorded matrix variant |
| `fapi2-message-signing-introspection` | FAPI2 Message Signing signed introspection response option. | Separately defined; not advertised until implemented and tested |

## `oauth2-baseline`

| Field | Policy |
| --- | --- |
| Grants | `authorization_code`, `refresh_token`, `client_credentials` |
| Response types | `code` |
| Client auth | `none`, `client_secret_basic`, `client_secret_post`, `private_key_jwt`, `tls_client_auth`, `self_signed_tls_client_auth` |
| Token binding | Bearer, DPoP-bound, mTLS-bound |
| PAR | Supported, not globally required by default |
| JAR | Supported; unsigned request objects are baseline compatibility only |
| JARM | Supported as `response_mode=jwt` when negotiated |
| RAR | RFC 9396-style `authorization_details` accepted on authorization, PAR, and signed request object inputs for advertised supported types |
| Refresh policy | Rotation by default for refresh-token grants |
| Token TTLs | Authorization code <= configured `AUTH_CODE_TTL_SECONDS`; access token <= configured `ACCESS_TOKEN_TTL_SECONDS` |
| Metadata | Generated from `AUTHORIZATION_SERVER_PROFILE`; mTLS capabilities advertised only when trusted proxy CIDRs are configured; `authorization_details_types_supported` must match parser allowlist |

Refresh-token rotation follows the state machine in `docs/refresh-token-rotation.md`. The lost-response retry window is a compatibility recovery path, not a replay bypass.

Negative tests:

- duplicate OAuth parameters
- unsafe redirect URI
- non-S256 PKCE
- mixed client authentication methods
- invalid client assertion audience
- access token transport ambiguity
- unknown or malformed `authorization_details`

## `oauth2-security-bcp`

`oauth2-security-bcp` is a documented policy profile layered onto the baseline
runtime behavior. It is not a separate `AUTHORIZATION_SERVER_PROFILE` switch in
the current implementation; high-risk clients use the same protocol invariants
through registration policy, PAR/JAR/client-auth settings, sender constraint,
and negative conformance tests.

| Field | Policy |
| --- | --- |
| Grants | Authorization code and client credentials; no implicit or password grants |
| Response types | `code` only |
| Client auth | Public clients must use PKCE; confidential clients must authenticate |
| Token binding | Sender-constrained tokens preferred for high-risk clients |
| PAR | Recommended for high-risk clients |
| JAR | Signed JAR recommended for high-risk clients |
| Refresh policy | Rotation or sender constraint according to client risk |
| Metadata | Must not overclaim disabled high-security behavior |
| RAR | High-risk `authorization_details` require explicit transaction binding and exact stored-detail matching for non-high-risk silent consent reuse |

Negative tests:

- authorization without required PKCE
- redirect URI mismatch
- stale authorization code
- authorization code replay
- refresh token reuse
- bearer use of sender-constrained token at protected resources

## `oidc-basic-op`

| Field | Policy |
| --- | --- |
| Grants | `authorization_code`, optional `refresh_token` |
| Response types | `code` |
| Client auth | Static clients, public or confidential according to registration |
| Token binding | Bearer, DPoP, or mTLS depending on client policy |
| DPoP nonce | `DPOP_NONCE_POLICY=required` by default; `optional` is available only for baseline interoperability |
| PAR | Optional unless client/profile requires it |
| JAR | Optional; signed request objects validated when supplied |
| ID Token | RS256 support must be real; active signing alg is advertised |
| UserInfo | Requires valid access token with `openid` scope |
| Logout | RP-Initiated Logout at `/logout`; exact `post_logout_redirect_uri` matching; best-effort Back-Channel Logout for registered clients |
| Metadata | OIDC discovery must match runtime issuer and endpoints, including `end_session_endpoint` and back-channel logout support |

Negative tests:

- invalid issuer
- invalid ID Token signature alg
- missing or invalid nonce where required
- userinfo without `openid`
- unsupported prompt combinations
- unregistered `post_logout_redirect_uri`
- multi-audience `id_token_hint` without matching `client_id`
- logout token containing forbidden `nonce`

## `oidc-config`

| Field | Policy |
| --- | --- |
| Discovery | `/.well-known/openid-configuration` |
| OAuth metadata | `/.well-known/oauth-authorization-server` |
| JWKS | `/jwks.json` publishes active and previous non-retired keys |
| Metadata truth | Discovery values must correspond to real endpoint behavior |

Negative tests:

- stale issuer
- advertised alg without usable key
- advertised auth method without working path
- disabled profile still advertised
- advertised logout endpoint without exact redirect validation or signed logout token support

## `fapi2-security`

| Field | Policy |
| --- | --- |
| Clients | Confidential clients only |
| Grants | Authorization code and client credentials variants covered by the OIDF plan set |
| Response types | `code` |
| Client auth | `private_key_jwt` or mTLS |
| Token binding | DPoP or mTLS sender-constrained access tokens |
| DPoP nonce | Required, regardless of `DPOP_NONCE_POLICY` compatibility settings |
| PAR | Required; authorization requests that do not use PAR must be rejected |
| PKCE | S256 required for authorization code flow |
| Authorization code TTL | 60 seconds or less |
| JAR/JARM | Not required by this profile unless a Message Signing option is selected |
| Refresh policy | Sender-constrained tokens; no routine refresh-token rotation for FAPI2 Security by default |
| Metadata | Must reflect selected client auth and sender constraint behavior |

If a deployment enables refresh-token rotation for migration or compatibility, it must document that exception and keep the replay-detection state machine from `docs/refresh-token-rotation.md`.

Runtime enforcement is selected with `AUTHORIZATION_SERVER_PROFILE=fapi2-security`. This setting forces PAR globally, caps authorization code lifetime at 60 seconds, rejects password grant requests, limits clients to confidential clients, allows only `private_key_jwt` or mTLS client authentication, requires DPoP or mTLS sender-constrained access tokens, and keeps DPoP nonce enforcement required even if a baseline deployment configured `DPOP_NONCE_POLICY=optional`.

Negative tests:

- public client usage
- non-PAR authorization request
- missing PKCE S256
- bearer token where sender-constrained token is required
- weak client authentication
- wrong client assertion audience
- DPoP proof mismatch or replay
- mTLS certificate mismatch

## `fapi2-message-signing-authz-request`

| Field | Policy |
| --- | --- |
| Base | `fapi2-security` |
| PAR | Signed request object accepted and required at PAR |
| JAR claims | `aud` required, `nbf` required, `exp` required with lifetime <= 60 minutes |
| JAR header | Accept `typ=oauth-authz-req+jwt` |
| Request object `jti` | Optional product hardening unless `REQUEST_OBJECT_JTI_POLICY=required-for-signed-jar` is selected |

Runtime enforcement is selected with `AUTHORIZATION_SERVER_PROFILE=fapi2-message-signing-authz-request`. This includes the `fapi2-security` controls and requires a signed request object at PAR. Existing signed JAR validation requires `aud`, `nbf`, and `exp`; the implementation currently uses a 5-minute maximum lifetime, which is stricter than the FAPI2 Message Signing 60-minute ceiling. `REQUEST_OBJECT_JTI_POLICY=required-for-signed-jar` is a stricter-than-FAPI product hardening switch that requires signed JAR request objects to carry a valid `jti` and stores it in the request-object replay cache.

Negative tests:

- unsigned JAR when signed JAR is required
- missing `aud`, `nbf`, or `exp`
- request object lifetime > 60 minutes
- request object/client mismatch
- parameter override after PAR

## `fapi2-message-signing-jarm`

| Field | Policy |
| --- | --- |
| Base | `fapi2-security` |
| Authorization response | Signed authorization response JWT |
| Metadata | `authorization_signing_alg_values_supported` must match active signing capability |
| Failure behavior | Signing failure must not fall back to query response |

Negative tests:

- unsigned response where JARM is required
- wrong `iss` or `aud`
- missing `state` preservation
- fallback to plain query after signing failure

## `fapi2-message-signing-introspection`

| Field | Policy |
| --- | --- |
| Base | `fapi2-security` |
| Status | Separately defined; not advertised until implemented and tested |
| Required before advertising | Signed introspection response generation, metadata, and OIDF tests |

Negative tests:

- unsigned introspection response when advertised
- wrong response issuer/audience
- stale or revoked token reported active
