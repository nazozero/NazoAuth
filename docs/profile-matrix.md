# Profile Matrix

This matrix defines the project profiles separately from product hardening. A profile may only advertise metadata and behavior that the implementation and deployment can actually satisfy.

## Summary

| Profile | Purpose | Status |
| --- | --- | --- |
| `oauth2-baseline` | General OAuth authorization server profile for authorization code, refresh token, client credentials, revocation, introspection, metadata, and JWKS. | Implemented, needs matrix tests |
| `oauth2-security-bcp` | OAuth baseline constrained by RFC 9700-style security defaults. | In progress |
| `oidc-basic-op` | OpenID Connect Authorization Code OP with discovery, ID Token, JWKS, and UserInfo. | OIDF-tested |
| `oidc-config` | OIDC discovery/server metadata verification. | OIDF-tested |
| `fapi2-security` | FAPI2 Security profile without message-signing options. | OIDF-tested for recorded matrix variants |
| `fapi2-message-signing-authz-request` | FAPI2 Security plus signed authorization requests at PAR. | OIDF-tested for recorded matrix variants |
| `fapi2-message-signing-jarm` | FAPI2 Message Signing authorization response signing option. | OIDF-tested for recorded matrix variant |
| `fapi2-message-signing-introspection` | FAPI2 Message Signing signed introspection response option. | Not implemented |

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
| Refresh policy | Rotation by default for refresh-token grants |
| Token TTLs | Authorization code <= configured `AUTH_CODE_TTL_SECONDS`; access token <= configured `ACCESS_TOKEN_TTL_SECONDS` |
| Metadata | Must only advertise capabilities enabled in the deployed profile |

Refresh-token rotation follows the state machine in `docs/refresh-token-rotation.md`. The lost-response retry window is a compatibility recovery path, not a replay bypass.

Negative tests:

- duplicate OAuth parameters
- unsafe redirect URI
- non-S256 PKCE
- mixed client authentication methods
- invalid client assertion audience
- access token transport ambiguity

## `oauth2-security-bcp`

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
| PAR | Optional unless client/profile requires it |
| JAR | Optional; signed request objects validated when supplied |
| ID Token | RS256 support must be real; active signing alg is advertised |
| UserInfo | Requires valid access token with `openid` scope |
| Metadata | OIDC discovery must match runtime issuer and endpoints |

Negative tests:

- invalid issuer
- invalid ID Token signature alg
- missing or invalid nonce where required
- userinfo without `openid`
- unsupported prompt combinations

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

## `fapi2-security`

| Field | Policy |
| --- | --- |
| Clients | Confidential clients only |
| Grants | Authorization code and client credentials variants covered by the OIDF plan set |
| Response types | `code` |
| Client auth | `private_key_jwt` or mTLS |
| Token binding | DPoP or mTLS sender-constrained access tokens |
| PAR | Required; authorization requests that do not use PAR must be rejected |
| PKCE | S256 required for authorization code flow |
| Authorization code TTL | 60 seconds or less |
| JAR/JARM | Not required by this profile unless a Message Signing option is selected |
| Refresh policy | Sender-constrained tokens; no routine refresh-token rotation for FAPI2 Security by default |
| Metadata | Must reflect selected client auth and sender constraint behavior |

If a deployment enables refresh-token rotation for migration or compatibility, it must document that exception and keep the replay-detection state machine from `docs/refresh-token-rotation.md`.

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
| Request object `jti` | Optional product hardening unless a selected ecosystem profile requires it |

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
| Status | Not implemented |
| Required before advertising | Signed introspection response generation, metadata, and OIDF tests |

Negative tests:

- unsigned introspection response when advertised
- wrong response issuer/audience
- stale or revoked token reported active
