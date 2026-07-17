# Security Policy for Capabilities We Never Support

This document is normative for this implementation. A capability marked **Never
supported by security policy** has no runtime flag, metadata advertisement,
client field, or hidden compatibility path. Reintroducing one requires a new
threat model, standards evidence, negative tests, metadata-truth tests, and an
explicit policy reversal in the same review.

## Never supported by security policy

| Capability | Decision and evidence |
| --- | --- |
| OAuth implicit grant and OIDC Implicit OP | **Never supported by security policy.** OAuth 2.0 Security BCP describes authorization-code injection and access-token leakage defenses and recommends code-based flows; OAuth 2.1 omits the implicit grant. The authorization endpoint issues only `code`. See [RFC 9700 Section 2.1.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.2) and the [OAuth 2.1 draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/). |
| OIDC Hybrid OP | **Never supported by security policy.** OIDC Core defines Hybrid Flow, but it exposes ID Tokens and/or access tokens through the browser front channel before token-endpoint exchange. That creates the same browser, URL, history, Referer, script, and intermediary exposure class that [RFC 9700 Section 2.1.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.2) deprecates for implicit-style token delivery. The supported interactive profile uses authorization code, with PKCE and sender constraints where required. |
| Resource Owner Password Credentials grant | **Never supported by security policy.** RFC 9700 Section 2.4 says this grant **MUST NOT** be used. |
| Authorization code without PKCE for public, FAPI, sender-constrained, or non-OIDC clients; and `plain` PKCE for every client | **Never supported by security policy.** RFC 9700 Section 2.1.1 requires PKCE for public clients, recommends it for confidential clients, and identifies `S256` as the method that does not expose the verifier. Baseline confidential OIDC code flow remains interoperable with OIDC Core when PKCE is absent; all hardened profiles require S256. See also [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html). |
| Unsigned Request Objects (`alg=none`) | **Never supported by security policy.** [RFC 9101 Section 4](https://www.rfc-editor.org/rfc/rfc9101.html#section-4) requires a Request Object to be signed or signed and then encrypted, and [RFC 8725 Section 3.1](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1) requires strict algorithm verification. Discovery advertises only executable asymmetric signing algorithms. |
| Legacy OAuth `audience` parameter outside Token Exchange | **Never supported by security policy.** [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html) defines repeatable URI-valued `resource` parameters for authorization and token requests. `audience` remains valid only inside the explicit RFC 8693 Token Exchange profile. |
| JSON-array syntax for an external RFC 8707 `resource` value | **Never supported by security policy.** RFC 8707 represents multiple targets as repeated `resource` parameters, each containing one absolute URI. Private in-process encoding is not an accepted HTTP syntax. |
| Global SCIM bearer token from process configuration | **Never supported by security policy.** A shared full-access environment secret has no tenant, scope, receiver-audience, expiry, revocation, rotation, or audit identity. SCIM access uses hashed database credentials with explicit scopes and lifecycle state. |
| Query access tokens, and form-body access tokens at FAPI resources | **Never supported by security policy.** [RFC 6750 Section 2](https://www.rfc-editor.org/rfc/rfc6750.html#section-2) makes the Authorization header the preferred method, requires resource servers to support it, forbids query use except under narrow conditions, and says form-body transport should not be used unless strict constraints apply. Form-body bearer is permitted only for baseline OIDC UserInfo interoperability; FAPI resources require the Authorization header. |
| CIBA push token delivery | **Never supported by security policy.** The [FAPI-CIBA profile](https://openid.net/specs/openid-financial-api-ciba.html) prohibits push mode and requires poll while allowing ping. Push would deliver tokens directly to an outbound callback and create a larger credential-disclosure and retry surface. The implemented combinations are poll/ping × `private_key_jwt`/mTLS; ping carries only `auth_req_id`, and tokens are still retrieved from the token endpoint. |

## Implemented only in a constrained profile

| Capability | Constraint and evidence |
| --- | --- |
| Client-supplied external `request_uri` | Available only on the baseline profile for an exact HTTPS URI registered through authenticated dynamic registration. The fetcher rejects redirects, userinfo, non-HTTPS schemes, oversized bodies, unexpected content types, and public DNS answers containing private/loopback/link-local/unspecified/multicast addresses; private origins require an explicit exact-origin allowlist. Request Objects remain asymmetrically signed under RFC 9101. FAPI profiles continue to use server-issued, one-time PAR handles under [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126.html). |
| `client_secret_post` | Retained only for baseline interoperability. RFC 9700 Section 2.5 recommends asymmetric client authentication; FAPI profiles therefore exclude shared-secret POST authentication. New high-assurance clients should use `private_key_jwt`, mTLS, or another sender-constrained profile. |
| Cleartext SMTP transport | Accepted only without SMTP credentials when the public issuer is loopback HTTP, including isolated container E2E topology. Production mail submission must use STARTTLS or implicit TLS. See [RFC 8314](https://www.rfc-editor.org/rfc/rfc8314.html). |
| Returning an email verification code in an HTTP response | Accepted only in debug builds with a loopback HTTP issuer. It is rejected at startup in deployable/non-loopback configurations. |

Historical conformance records may describe behavior that existed at the time
of a recorded run. They are evidence snapshots, not current policy. This file,
runtime metadata, and current executable tests take precedence.
