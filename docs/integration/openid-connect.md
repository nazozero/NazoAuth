# OpenID Connect Integration

This document is the entry point for integrating a relying party with NazoAuth
as an OpenID Connect Provider. It is a project-specific integration reference:
it describes the protocol surfaces NazoAuth implements, the capabilities it
intentionally does not implement, and the deployment flags that affect metadata.

Use `https://issuer.example` only as a placeholder in this document. Every
deployment and every conformance run must use its own public HTTPS issuer.

## Standards and profile support

| Standard or profile | NazoAuth support | Notes |
| --- | --- | --- |
| OpenID Connect Core 1.0 | Supported for Authorization Code OP integrations | Interactive login uses `response_type=code`; ID Tokens are signed and client-bound. |
| OpenID Connect Discovery 1.0 | Supported | Discovery metadata is generated from the active runtime profile and enabled modules. |
| OAuth 2.0 Authorization Server Metadata / RFC 8414 | Supported | OAuth metadata mirrors executable authorization-server behavior. |
| OAuth 2.0 Protected Resource Metadata | Supported | Exposes generic and FAPI resource metadata surfaces. |
| OAuth 2.0 Form Post Response Mode | Supported for code responses | Does not enable implicit or hybrid token delivery. |
| OpenID Connect Third-Party Initiated Login | Supported as OP-side client metadata | `initiate_login_uri` is accepted only as HTTPS registration metadata. |
| Dynamic Client Registration / RFC 7591 | Supported, default-closed | Requires `ENABLE_DYNAMIC_CLIENT_REGISTRATION=true`; public deployments should require an initial access token. |
| Dynamic Client Registration Management / RFC 7592 | Supported for DCR-created clients | Uses protected `registration_client_uri` and registration access tokens. |
| Pushed Authorization Requests / RFC 9126 | Supported | Required by FAPI profiles; optional for baseline clients unless client policy requires it. |
| JWT Secured Authorization Request / RFC 9101 | Supported for signed Request Objects | Unsigned Request Objects are rejected. |
| JWT Secured Authorization Response Mode / JARM | Supported when negotiated by client/profile policy | Used by message-signing profiles and client metadata that require it. |
| PKCE / RFC 7636 | Supported; S256 only | Required for public clients, FAPI clients, sender-constrained clients, and recommended for all new code-flow clients. |
| Resource Indicators / RFC 8707 | Supported | Uses repeated URI-valued `resource` parameters; JSON-array syntax is not accepted externally. |
| Token Introspection / RFC 7662 | Supported | FAPI message-signing profiles can use protected introspection responses. |
| Token Revocation / RFC 7009 | Supported | Available through the revocation endpoint. |
| Device Authorization Grant / RFC 8628 | Optional module | Advertised only when enabled and allowed for the client. |
| OpenID CIBA / FAPI-CIBA | Optional module | Supports poll and ping modes for registered CIBA clients; push is not implemented. |
| FAPI 2.0 Security Profile | Supported through runtime profile | Requires confidential clients, PAR, sender constraints, and strong client authentication. |
| FAPI 2.0 Message Signing | Supported through runtime profile/options | Adds signed authorization requests, JARM, and protected response options according to profile. |
| OIDC Implicit OP | Not implemented by security policy | NazoAuth does not return ID Tokens or access tokens from the authorization endpoint front channel. |
| OIDC Hybrid OP | Not implemented by security policy | Interactive flows stay on Authorization Code. |
| Resource Owner Password Credentials | Not implemented by security policy | Rejected as an unsafe legacy grant. |
| Legacy OIDF Dynamic OP certification profile | Not implemented by security policy | That certification profile requires implicit/hybrid metadata; RFC 7591/RFC 7592 dynamic registration remains supported. |

## Discoverable endpoints

Relying parties should read endpoints from discovery. A baseline deployment can
expose the following endpoints when the matching modules are enabled:

| Endpoint | Path | Advertisement rule |
| --- | --- | --- |
| OIDC discovery | `/.well-known/openid-configuration` | Always present for OIDC deployments. |
| OAuth authorization-server metadata | `/.well-known/oauth-authorization-server` | Present for OAuth/OIDC deployments. |
| Protected resource metadata | `/.well-known/oauth-protected-resource` | Present for resource-server metadata. |
| FAPI resource metadata | `/.well-known/oauth-protected-resource/fapi/resource` | Present for the FAPI resource surface. |
| JWKS | `/jwks.json` | Publishes active non-retired signing keys and previous keys still in use. |
| Authorization | `/authorize` | Supports code-flow authorization requests. |
| PAR | `/par` | Advertised/required according to profile and client policy. |
| Token | `/token` | Handles supported grant types and client authentication methods. |
| UserInfo | `/userinfo` | Requires an access token with `openid` scope. |
| Introspection | `/introspect` | For protected resource validation and profile-specific protected responses. |
| Revocation | `/revoke` | For refresh/access token revocation where applicable. |
| Logout | `/logout` | RP-Initiated Logout with exact registered redirect URI validation. |
| Dynamic registration | `/register` | Advertised only when `ENABLE_DYNAMIC_CLIENT_REGISTRATION=true`. |
| Device authorization | `/device_authorization` | Advertised only when `ENABLE_DEVICE_AUTHORIZATION_GRANT=true`. |

Discovery metadata must be treated as authoritative. If a field is absent, the
deployment is not claiming that capability.

## Minimum supported integration

New integrations should use Authorization Code Flow with S256 PKCE.

| Field | Recommended value |
| --- | --- |
| Issuer | `https://issuer.example` |
| Discovery | `https://issuer.example/.well-known/openid-configuration` |
| JWKS | `https://issuer.example/jwks.json` |
| Authorization endpoint | `https://issuer.example/authorize` |
| Token endpoint | `https://issuer.example/token` |
| UserInfo endpoint | `https://issuer.example/userinfo` |
| Logout endpoint | `https://issuer.example/logout` |
| Response type | `code` |
| Response mode | `query`; `form_post` when the client and RP both require it |
| PKCE | `S256` |
| Scopes | Start with `openid`; add only the claims the RP actually needs |
| Client authentication | Public clients use `none` with PKCE; confidential clients should use `private_key_jwt`, mTLS, or `client_secret_basic` according to their risk profile |

The relying party should discover endpoints from metadata instead of hardcoding
paths. Hardcoded paths are shown only to make the integration shape explicit.

## Client registration

NazoAuth supports two client onboarding models:

1. Static administrative registration.
2. RFC 7591 / RFC 7592 Dynamic Client Registration when
   `ENABLE_DYNAMIC_CLIENT_REGISTRATION=true`.

Dynamic registration is default-closed and should be protected by an initial
access token in public deployments. A dynamically registered client receives a
`registration_client_uri` and a registration access token for its own
management lifecycle.

Client metadata accepted by NazoAuth includes the usual OIDC/OAuth fields:

| Metadata | Support |
| --- | --- |
| `client_name` | Supported |
| `redirect_uris` | Required for authorization-code clients; exact matching |
| `post_logout_redirect_uris` | Supported for logout; exact matching |
| `response_types` | `["code"]` |
| `grant_types` | Per-client allowlist of supported grants |
| `scope` | Per-client scope allowlist |
| `token_endpoint_auth_method` | `none`, `client_secret_basic`, `client_secret_post`, `private_key_jwt`, `tls_client_auth`, `self_signed_tls_client_auth` |
| `jwks` | Supported for client signing/encryption keys |
| `jwks_uri` | Supported only under the constrained remote-document policy of the active baseline profile |
| `request_uris` | Supported only for exact HTTPS `request_uri` registration under the constrained baseline policy |
| `userinfo_signed_response_alg` | Supported when the runtime keyset can execute it |
| `userinfo_encrypted_response_alg` / `userinfo_encrypted_response_enc` | Supported with a valid client encryption key |
| `authorization_signed_response_alg` | Supported for JARM-capable clients/profiles |
| `authorization_encrypted_response_alg` / `authorization_encrypted_response_enc` | Supported for nested encrypted JARM when client metadata and keys are valid |
| `initiate_login_uri` | Supported for Third-Party Initiated Login; HTTPS only |
| `software_statement` | Not implemented |

Recommended baseline registration metadata:

```json
{
  "client_name": "Example Application",
  "redirect_uris": ["https://app.example/oauth/callback"],
  "response_types": ["code"],
  "grant_types": ["authorization_code", "refresh_token"],
  "scope": "openid profile email",
  "token_endpoint_auth_method": "client_secret_basic"
}
```

For public browser, native, or SPA clients:

```json
{
  "client_name": "Example Public Application",
  "redirect_uris": ["https://app.example/oauth/callback"],
  "response_types": ["code"],
  "grant_types": ["authorization_code"],
  "scope": "openid profile email",
  "token_endpoint_auth_method": "none"
}
```

Public clients must send S256 PKCE. Baseline confidential OIDC code-flow
compatibility may accept a request without PKCE, but new integrations should
still send PKCE. FAPI, sender-constrained, public, and non-OIDC authorization
code clients must use S256 PKCE.

## Request, scope, and resource boundaries

NazoAuth applies subset rules at every step that can widen authority:

- a token request cannot widen the scopes or resource indicators granted by an
  authorization request;
- a refresh request cannot exceed the grant's stored scope/resource boundary;
- a client cannot request scopes or resources outside its current registration;
- resource indicators use RFC 8707 repeated `resource` parameters;
- the legacy OAuth `audience` parameter is not accepted for authorization or
  token requests outside the explicit Token Exchange profile.

Use the smallest scope set the application needs. Start with `openid`, then add
`profile`, `email`, `phone`, or API-specific scopes only when the RP consumes
those claims or resources.

Common OIDC scopes:

| Scope | Purpose |
| --- | --- |
| `openid` | Required for OIDC authentication and ID Token issuance. |
| `profile` | Enables standard profile claims when policy permits them. |
| `email` | Enables email claims when policy permits them. |
| `phone` | Enables phone claims when policy permits them. |
| `offline_access` | Enables refresh-token issuance only when the client and consent policy allow it. |

## ID Token, UserInfo, and access token audiences

The ID Token is for the relying party. Its `aud` identifies the client that
requested authentication.

Access tokens are for resource servers. A relying party should not infer access
token semantics from the ID Token. If a resource server needs to validate access
tokens, use the resource-server verifier guidance or introspection endpoint
appropriate for that deployment.

UserInfo requires an access token with `openid` scope. Per-client signed or
encrypted UserInfo can be configured when the client has registered the required
metadata and keys.

## Algorithms and request objects

NazoAuth advertises only algorithms that the active runtime keyset can execute.

Current integration rules:

- ID Token, UserInfo, JARM, and Request Object algorithms must be selected from
  discovery metadata and client registration policy;
- unsigned Request Objects (`alg=none`) are not supported;
- signed Request Objects use asymmetric algorithms and registered client keys;
- external `request_uri` is available only as a constrained baseline feature for
  exact HTTPS URIs registered through authenticated dynamic registration;
- FAPI profiles continue to use server-issued PAR request URIs instead of
  client-hosted `request_uri` documents;
- ID Token signing defaults should be read from discovery, not assumed by the
  RP.

For high-assurance clients, prefer PAR, signed Request Objects, JARM, DPoP, or
mTLS according to the selected profile.

Do not configure a relying party to require an algorithm that the current
discovery document does not advertise. Metadata truth is a hard contract in
NazoAuth: advertised algorithms must be executable, and unadvertised algorithms
must not be assumed.

## Response types and response modes

Supported interactive response type:

| Response type | Status |
| --- | --- |
| `code` | Supported |
| `id_token`, `token`, `id_token token` | Not implemented by security policy |
| Hybrid combinations such as `code id_token` or `code token` | Not implemented by security policy |

Supported response modes for baseline OIDC:

| Response mode | Status |
| --- | --- |
| `query` | Supported for code responses |
| `form_post` | Supported for code responses |
| `jwt` / JARM response modes | Supported when negotiated and enabled by client/profile policy |
| `fragment` carrying tokens | Not implemented for interactive token delivery |

`form_post` does not enable implicit or hybrid token delivery. It is only a
browser transport for supported authorization responses.

## Grant types

| Grant type | Status |
| --- | --- |
| `authorization_code` | Supported |
| `refresh_token` | Supported according to client policy |
| `client_credentials` | Supported for OAuth resource access; not an OIDC login flow |
| `urn:ietf:params:oauth:grant-type:device_code` | Supported only when the Device Authorization Grant module and client allowlist are enabled |
| OpenID CIBA grant | Supported only when CIBA is enabled and the client is registered for it |
| `urn:ietf:params:oauth:grant-type:token-exchange` | Supported as a bounded local profile |
| `password` | Not implemented by security policy |
| `implicit` | Not implemented by security policy |

## Client authentication

Baseline clients may use:

- `none` for public clients with PKCE;
- `client_secret_basic`;
- `client_secret_post` for compatibility only;
- `private_key_jwt`;
- `tls_client_auth`;
- `self_signed_tls_client_auth`.

High-assurance integrations should prefer asymmetric or sender-constrained
client authentication. FAPI profiles exclude shared-secret POST authentication.

For `private_key_jwt`, use the issuer or token endpoint audience accepted by
the deployment profile and keep assertion lifetimes short. For mTLS, register
the correct certificate-bound client metadata and make sure the deployment's
trusted proxy/mTLS termination boundary is configured before advertising mTLS
metadata.

## Logout and sessions

NazoAuth supports RP-Initiated Logout at `/logout` and validates registered
`post_logout_redirect_uri` values exactly. Logout integrations should use
metadata discovery and register all post-logout redirect URIs explicitly.

Front-channel and session-management behavior is profile-tested in the OIDF
matrix. Browser-sensitive logout/session flows should be tested separately from
high-concurrency authorization matrices because they depend on shared browser
state.

## Third-party initiated login

NazoAuth supports the OP-side metadata required for OpenID Connect
Third-Party-Initiated Login:

- `initiate_login_uri` can be registered through dynamic client metadata;
- the URI must be HTTPS;
- non-HTTPS metadata is rejected.

This profile does not add an OP-side initiation endpoint. The initiation URI is
an RP endpoint; the RP uses it to start a normal authorization request against
NazoAuth.

## Dynamic registration is not legacy Dynamic OP

NazoAuth implements secure RFC 7591 / RFC 7592 dynamic client registration, but
does not implement the legacy OIDF Dynamic OP certification profile. That
profile requires discovery metadata for implicit and hybrid flows, which are
not implemented by security policy.

Use this terminology precisely:

- "Dynamic Client Registration" means default-closed RFC 7591 / RFC 7592 client
  lifecycle support.
- "Dynamic OP certification profile" is not supported.

## Security boundaries

The following are intentionally not supported for new integrations:

- implicit grant;
- OIDC Implicit OP;
- OIDC Hybrid OP;
- Resource Owner Password Credentials grant;
- unsigned Request Objects;
- query-string bearer tokens;
- FAPI form-body bearer tokens;
- CIBA push mode.

These are security policy decisions, not missing configuration switches. Do not
attempt to enable them with hidden deployment options.

## Metadata truth and deployment flags

Several capabilities are controlled by runtime modules or profile settings. The
server must not advertise disabled or incomplete behavior.

| Capability | Required deployment state before advertising |
| --- | --- |
| Dynamic Client Registration | `ENABLE_DYNAMIC_CLIENT_REGISTRATION=true`; public deployments should configure an initial access token. |
| Device Authorization Grant | `ENABLE_DEVICE_AUTHORIZATION_GRANT=true` and client grant allowlist includes device code. |
| CIBA | `ENABLE_CIBA=true` and registered CIBA clients with allowed delivery mode. |
| SCIM Security Events | SCIM events module enabled and at least one valid receiver configuration. |
| mTLS client authentication / sender constraints | Trusted mTLS/proxy boundary configured and client metadata registered. |
| FAPI profiles | `AUTHORIZATION_SERVER_PROFILE` and client policy must enforce PAR, sender constraints, strong client authentication, and PKCE where applicable. |
| UserInfo/JARM encryption | Client metadata includes valid encryption preferences and exactly one usable public key for the selected algorithm. |

## Integration checklist

Before putting a relying party into production:

1. Configure the client with a public HTTPS redirect URI.
2. Use `response_type=code`.
3. Send S256 PKCE, including for confidential clients.
4. Request only required scopes.
5. Discover endpoints from `/.well-known/openid-configuration`.
6. Validate ID Token `iss`, `aud`, `exp`, `iat`, `nonce` when used, and
   signature.
7. Do not treat the ID Token as an API access token.
8. Register post-logout redirect URIs exactly when logout is used.
9. Use `private_key_jwt`, mTLS, DPoP, PAR, or JARM for higher-risk clients.
10. Re-check discovery metadata after changing runtime profile flags.

## Normative references

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html)
- [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
- [OpenID Connect Third-Party Initiated Login 1.0](https://openid.net/specs/openid-connect-3rd-party-initiated-login.html)
- [OAuth 2.0 Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)
- [OAuth 2.0 Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414.html)
- [OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html)
- [OAuth 2.0 Dynamic Client Registration Protocol](https://www.rfc-editor.org/rfc/rfc7591.html)
- [OAuth 2.0 Dynamic Client Registration Management Protocol](https://www.rfc-editor.org/rfc/rfc7592.html)
- [Proof Key for Code Exchange](https://www.rfc-editor.org/rfc/rfc7636.html)
- [OAuth 2.0 Resource Indicators](https://www.rfc-editor.org/rfc/rfc8707.html)
- [OAuth 2.0 Pushed Authorization Requests](https://www.rfc-editor.org/rfc/rfc9126.html)
- [JWT Secured Authorization Request](https://www.rfc-editor.org/rfc/rfc9101.html)
