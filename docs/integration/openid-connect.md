# OpenID Connect Integration

This document is the entry point for integrating a relying party with NazoAuth
as an OpenID Connect Provider. It follows the same kind of operator-facing
structure as Authelia's OpenID Connect integration reference, but the support
matrix and security boundaries below are NazoAuth-specific.

Use `https://issuer.example` only as a placeholder in this document. Every
deployment and every conformance run must use its own public HTTPS issuer.

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

## References

- [Authelia OpenID Connect integration reference](https://www.authelia.com/integration/openid-connect/introduction/)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [OAuth 2.0 Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414.html)
- [OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html)
- [OAuth 2.0 Pushed Authorization Requests](https://www.rfc-editor.org/rfc/rfc9126.html)
- [JWT Secured Authorization Request](https://www.rfc-editor.org/rfc/rfc9101.html)
