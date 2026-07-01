# OAuth, OpenID Connect, and FAPI Specification Backlog

Last reviewed: 2026-06-30.

This document records standards and active drafts that were found in the current
OAuth 2.x, OpenID Connect, and FAPI 2.0 specification landscape but are not
implemented by Nazo Auth Server at the code level.

The scan used primary sources only:

- IETF OAuth Working Group documents:
  <https://datatracker.ietf.org/wg/oauth/documents/>
- RFC Editor records for published OAuth-related RFCs:
  <https://www.rfc-editor.org/>
- OpenID Foundation specifications index:
  <https://openid.net/specs/>
- OpenID Foundation FAPI Working Group specifications:
  <https://openid.net/wg/fapi/specifications/>

The code comparison used route registration, discovery metadata, token
`grant_type` dispatch, client metadata validation, and protocol handlers as the
authority. README claims were not used as implementation evidence.

## Current Implemented Surface

The following capabilities are present in code and are therefore not duplicated
in the backlog table below:

| Area | Code evidence |
| --- | --- |
| Authorization Code flow, PKCE S256, refresh tokens, and client credentials | `src/bootstrap/routes.rs`, `src/http/token/dispatch.rs`, `src/http/token/authorization_code.rs`, `src/http/token/refresh.rs`, `src/http/token/client_credentials.rs` |
| OAuth Authorization Server Metadata and OpenID Provider Configuration | `src/http/well_known.rs` publishes `/.well-known/oauth-authorization-server` and `/.well-known/openid-configuration` metadata |
| OAuth Protected Resource Metadata | `src/http/well_known.rs` publishes `/.well-known/oauth-protected-resource` and `/.well-known/oauth-protected-resource/fapi/resource`; authorization server metadata lists `protected_resources` |
| Revocation and introspection | `src/bootstrap/routes.rs`, `src/http/token/revoke.rs`, `src/http/token/introspect.rs` |
| PAR, JAR, JARM-style JWT authorization responses, and issuer identification | `src/http/authorization/par.rs`, `src/http/authorization/request.rs`, `src/http/well_known.rs` |
| Resource Indicators and Rich Authorization Requests | `resource`/`authorization_details` handling in `src/http/authorization`, `src/http/token`, and `src/resource_server.rs`, including PAR/request-object inputs and refresh-token resource narrowing |
| JWT access tokens and resource-server verification | `src/http/token/issue.rs`, `src/resource_server.rs` |
| DPoP and mTLS sender-constrained tokens | `src/support/dpop.rs`, `src/support/mtls.rs`, `src/http/token/authorization_code.rs`, `src/http/token/client_credentials.rs`, `src/http/fapi_resource.rs` |
| `private_key_jwt`, mTLS client authentication, and client secret auth methods | `src/http/token/client_auth.rs`, `src/support/oauth.rs`, `src/http/well_known.rs` |
| OIDC Core code flow, Discovery, UserInfo, RP-Initiated Logout, and Back-Channel Logout | `src/bootstrap/routes.rs`, `src/http/well_known.rs`, `src/http/userinfo.rs`, `src/http/profile/oidc_logout.rs` |
| FAPI 2.0 Security Profile and Message Signing profile controls | `src/http/well_known.rs`, `src/http/authorization/request.rs`, `src/http/token/dispatch.rs`, FAPI profile tests under `tests/in_source` |

## Backlog

Priority values describe expected project fit, not protocol importance.

| Priority | Specification or draft | Current code status | Required implementation work |
| --- | --- | --- | --- |
| P1 | [OAuth 2.1 Authorization Framework, `draft-ietf-oauth-v2-1-15`](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/) | Partially aligned. Code already uses code-only authorization responses, PKCE S256, no implicit grant, no resource owner password grant, and OAuth 2.1-style defaults. There is no dedicated OAuth 2.1 conformance matrix tracking the draft as a single profile. | Track the latest OAuth 2.1 draft as a profile audit item until it becomes an RFC. Add a test matrix that maps the final draft/RFC requirements to code and discovery metadata. |
| Done | [RFC 8628, OAuth 2.0 Device Authorization Grant](https://www.rfc-editor.org/rfc/rfc8628) | Implemented behind `ENABLE_DEVICE_AUTHORIZATION_GRANT`; default deployments do not advertise it. | Keep user-code UX, polling interval, `slow_down`, expiration, denial handling, rate limiting, token dispatch, and discovery metadata covered by local tests; add OIDF official suite coverage if the suite publishes AS-side RFC 8628 plans. |
| P2 | [RFC 8693, OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693) | `/token` dispatch only handles `authorization_code`, `refresh_token`, and `client_credentials`. No `subject_token`, `actor_token`, `requested_token_type`, or token exchange grant handling was found. | Add token exchange policy model, token subject/actor validation, audience/resource restrictions, issued token type selection, and tests for delegation and impersonation boundaries. |
| P2 | [RFC 7591, OAuth 2.0 Dynamic Client Registration](https://www.rfc-editor.org/rfc/rfc7591) and [OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html) | Client metadata validation exists in `src/support/oauth.rs`, and admin-managed client CRUD exists under `/api/admin/clients`. No standards-compliant dynamic registration endpoint or `registration_endpoint` discovery metadata was found. | Add standards-compliant registration endpoint, initial access token policy if required, client metadata response shape, software statement handling if adopted, and discovery metadata. |
| P2 | [RFC 7592, OAuth 2.0 Dynamic Client Registration Management](https://www.rfc-editor.org/rfc/rfc7592) | Admin client update/delete APIs exist, but no `registration_client_uri`, registration access token, or RFC 7592 management semantics were found. | Add registration management endpoints only after RFC 7591/DCR scope is accepted; enforce registration access token lifecycle, read/update/delete semantics, and metadata validation. |
| P2 | [OpenID Connect Client-Initiated Backchannel Authentication Core 1.0](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html) | No `backchannel_authentication_endpoint`, `auth_req_id`, CIBA polling grant, or decoupled authentication state was found. | Add CIBA endpoint, authentication request validation, user binding and consent UX, `auth_req_id` token grant, polling interval enforcement, and discovery metadata. |
| P2 | [FAPI CIBA Profile](https://openid.net/specs/openid-financial-api-ciba.html) | FAPI profile controls exist, but CIBA itself is not implemented. | Implement only after OIDC CIBA Core exists. Add FAPI-specific CIBA constraints for client authentication, request signing, PAR/JAR expectations where applicable, and conformance tests. |
| P2 | [Grant Management for OAuth 2.0](https://openid.net/specs/oauth-v2-grant-management-ID1.html) | Admin grant listing/revocation exists under `/api/admin/grants`, but no end-user or client-facing grant management endpoint, grant identifiers, or grant management metadata was found. | Add grant identifier model, grant management endpoint, partial grant revocation/update semantics, client/user authorization checks, and metadata. |
| P3 | [RFC 7523 JWT Bearer Authorization Grant](https://www.rfc-editor.org/rfc/rfc7523) | `private_key_jwt` client authentication is implemented. The JWT bearer authorization grant `urn:ietf:params:oauth:grant-type:jwt-bearer` is not dispatched by `/token`. | Decide whether assertion grants are in scope. If adopted, add assertion validation, subject/audience policy, replay protection, and grant-type metadata. |
| P3 | [RFC 7522 SAML 2.0 Profile for OAuth 2.0 Client Authentication and Authorization Grants](https://www.rfc-editor.org/rfc/rfc7522) | External SAML federation login exists, but no SAML bearer OAuth client authentication or SAML bearer authorization grant was found. | Decide whether SAML bearer OAuth profiles are in scope. If adopted, add assertion validation, issuer trust configuration, replay protection, and grant dispatch. |
| P3 | [OAuth 2.0 Step Up Authentication Challenge Protocol, RFC 9470](https://www.rfc-editor.org/rfc/rfc9470) | Authorization requests may carry authentication context inputs, but no protected-resource challenge protocol for step-up authentication was found. | Add resource challenge generation/validation, ACR/AMR policy integration, and tests spanning resource server to authorization server escalation. |
| P3 | [OpenID Connect Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html) | Back-channel logout and RP-initiated logout exist. No front-channel logout iframe/session notification route or client metadata handling was found. | Add front-channel logout client metadata, logout notification rendering, session correlation, and browser behavior tests. |
| P3 | [OpenID Connect Session Management 1.0](https://openid.net/specs/openid-connect-session-1_0.html) | No `check_session_iframe` discovery metadata or browser session polling iframe was found. | Add check-session iframe endpoint and session state calculation only if browser-session polling interoperability is required. |
| P3 | [OpenID Connect Federation 1.0](https://openid.net/specs/openid-connect-federation-1_0.html) | `/api/auth/federation/oidc/*` implements external OIDC login. It is not OIDC Federation 1.0: no entity statement, trust chain, federation fetch/list/resolve, or trust mark support was found. | Add entity statement signing, trust anchor configuration, trust chain resolution, federation metadata policy processing, and endpoint discovery. |
| P3 | [OpenID Connect Native SSO for Mobile Apps 1.0](https://openid.net/specs/openid-connect-native-sso-1_0.html) | Native redirect URI policy exists through RFC 8252-style validation. No Native SSO `device_secret` issuance, grant type, or metadata was found. | Add device secret issuance and rotation, token grant support, mobile client metadata, and revocation semantics if first-party mobile SSO is in scope. |
| P3 | [OAuth 2.0 Attestation-Based Client Authentication, `draft-ietf-oauth-attestation-based-client-auth-09`](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/) | Passkey/WebAuthn attestation exists for user authentication, and release provenance attestations exist in CI documentation. No OAuth client attestation authentication method was found. | Track the active OAuth WG draft. If adopted, add client attestation statement validation, nonce/challenge handling, trust store configuration, and token endpoint auth method metadata. |
| P3 | [Transaction Tokens, `draft-ietf-oauth-transaction-tokens-08`](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/) | No transaction token issuance or validation model was found. | Track the active OAuth WG draft and decide whether transaction-bound API authorization is in scope. |
| P3 | [FAPI 2.0 HTTP Signatures working draft](https://openid.bitbucket.io/fapi/fapi-2_0-http-signatures.html) | FAPI 2.0 Message Signing support exists through signed authorization requests and JARM-style authorization responses. No HTTP Message Signatures implementation for arbitrary FAPI client, authorization server, or resource server HTTP messages was found. | Track whether this working draft remains part of the target FAPI 2.0 suite. If adopted, add HTTP message signature generation and verification, key binding, canonicalization tests, and resource-server integration. |
| P4 | [OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) | No credential issuer metadata, credential endpoint, deferred credential endpoint, nonce endpoint, or credential offer model was found. | Treat as a product-scope decision. If adopted, add credential issuer domain model, credential formats, proof validation, lifecycle policy, and conformance tests. |
| P4 | [OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) | No wallet/verifier presentation request or response processing model was found. | Treat as a product-scope decision. If adopted, add verifier endpoints, presentation definition handling, wallet response validation, nonce/state lifecycle, and trust policy. |

## Items Not Added As Missing Work

The following were checked but are already represented by existing code paths or
are informational/security guidance rather than standalone product features:

| Specification | Reason |
| --- | --- |
| RFC 7009 Token Revocation | `/revoke` exists. |
| RFC 7636 PKCE | S256 PKCE validation exists. |
| RFC 7662 Token Introspection | `/introspect` exists for authenticated JSON introspection. |
| RFC 9701 JWT Response for OAuth Token Introspection | Signed and nested encrypted JWT introspection responses are implemented under the signed-introspection profile, with content negotiation, issuer/audience binding, signing key selection, per-client JWE metadata, and negative tests. |
| RFC 8414 Authorization Server Metadata | `/.well-known/oauth-authorization-server` exists. |
| RFC 8705 mTLS | mTLS client authentication and certificate-bound access-token support exist. |
| RFC 8707 Resource Indicators | `resource` handling exists for authorization requests, PAR, token exchange, and refresh-token audience narrowing; JWT access-token `aud` is bound to the resulting resource set. |
| RFC 9068 JWT Access Tokens | Access tokens use JWT shape and resource-server verifier expects `typ=at+jwt`. |
| RFC 9101 JAR | Request object support exists where enabled. |
| RFC 9126 PAR | `/par` exists. |
| RFC 9207 Authorization Server Issuer Identification | Discovery advertises `authorization_response_iss_parameter_supported`. |
| RFC 9396 Rich Authorization Requests | `authorization_details` support exists behind configuration. |
| RFC 9449 DPoP | DPoP proof validation and sender-constrained token handling exist. |
| RFC 9728 OAuth 2.0 Protected Resource Metadata | `/.well-known/oauth-protected-resource` and `/.well-known/oauth-protected-resource/fapi/resource` publish resource metadata; authorization server metadata lists the configured protected resource identifier. |
| FAPI 2.0 Security Profile Final | Implemented as a runtime profile and covered by conformance-oriented tests. |
| FAPI 2.0 Message Signing Final | Implemented through signed authorization request and JWT authorization response support in the FAPI message-signing profile. |
| FAPI 2.0 Attacker Model | Used as security rationale for FAPI profiles; it is not an endpoint-level implementation item. |
