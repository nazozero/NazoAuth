# Security Policy for Capabilities We Do Not Implement

This document is normative for NazoAuth. A capability marked **Not implemented
by security policy** has no runtime flag, metadata advertisement, client field,
or hidden compatibility path. Reintroducing one requires a new threat model,
standards evidence, negative tests, metadata-truth tests, and an explicit policy
change in the same review.

## Not implemented by security policy

| Capability | Decision and evidence |
| --- | --- |
| OAuth implicit grant and OIDC Implicit OP | **Not implemented by security policy.** OAuth 2.0 Security BCP describes authorization-code injection and access-token leakage defenses and recommends code-based flows; OAuth 2.1 omits the implicit grant. NazoAuth issues only `code` from the authorization endpoint. See [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) and the [OAuth 2.1 draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/). |
| OIDC Hybrid OP | **Not implemented by security policy.** Front-channel `id_token`/token responses expand leakage and mix-up surfaces without serving the project's code-flow profiles. OAuth 2.1 and the project's RFC 9700 posture use authorization code plus PKCE. |
| Resource Owner Password Credentials grant | **Not implemented by security policy.** RFC 9700 Section 2.4 says this grant **MUST NOT** be used. |
| Authorization code without PKCE, or `plain` PKCE | **Not implemented by security policy.** RFC 9700 Section 2.1.1 requires PKCE for public clients, recommends it for confidential clients, and identifies `S256` as the challenge method that does not expose the verifier. NazoAuth applies the stronger OAuth 2.1-aligned invariant: every authorization-code request uses S256, with no per-client exception. See also [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html). |
| Unsigned Request Objects (`alg=none`) | **Not implemented by security policy.** RFC 9101 Section 5 requires a Request Object to be signed or signed and then encrypted. Discovery advertises only executable asymmetric signing algorithms. |
| Client-supplied external `request_uri` and `request_uris` registration | **Not implemented by security policy.** RFC 9101 permits this optional transport, but it creates remote-fetch, SSRF, cache, lifetime, and content-type obligations. NazoAuth instead supports server-issued, one-time PAR handles under [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126.html); DCR rejects `request_uris`, and metadata always reports `request_uri_parameter_supported=false`. |
| Legacy OAuth `audience` parameter outside Token Exchange | **Not implemented by security policy.** [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html) defines repeatable URI-valued `resource` parameters for authorization and token requests. `audience` remains valid only inside the explicit RFC 8693 Token Exchange profile. |
| JSON-array syntax for an external RFC 8707 `resource` value | **Not implemented by security policy.** RFC 8707 represents multiple targets as repeated `resource` parameters, each containing one absolute URI. Private in-process encoding is not an accepted HTTP syntax. |
| Global SCIM bearer token from process configuration | **Not implemented by security policy.** A shared full-access environment secret has no tenant, scope, receiver-audience, expiry, revocation, rotation, or audit identity. SCIM access uses hashed database credentials with explicit scopes and lifecycle state. |
| Query access tokens, and form-body access tokens at FAPI resources | **Not implemented by security policy.** RFC 6750 Section 2 makes the Authorization header the preferred method, requires resource servers to support it, forbids query use except under narrow conditions, and says form-body transport should not be used unless strict constraints apply. NazoAuth permits form-body bearer only for baseline OIDC UserInfo interoperability; FAPI resources require the Authorization header. |

## Implemented only in a constrained profile

| Capability | Constraint and evidence |
| --- | --- |
| `client_secret_post` | Retained only for baseline interoperability. RFC 9700 Section 2.5 recommends asymmetric client authentication; FAPI profiles therefore exclude shared-secret POST authentication. New high-assurance clients should use `private_key_jwt`, mTLS, or another sender-constrained profile. |
| Cleartext SMTP transport | Accepted only without SMTP credentials when the public issuer is loopback HTTP, including isolated container E2E topology. Production mail submission must use STARTTLS or implicit TLS. See [RFC 8314](https://www.rfc-editor.org/rfc/rfc8314.html). |
| Returning an email verification code in an HTTP response | Accepted only in debug builds with a loopback HTTP issuer. It is rejected at startup in deployable/non-loopback configurations. |

Historical conformance records may describe behavior that existed at the time
of a recorded run. They are evidence snapshots, not current policy. This file,
runtime metadata, and current executable tests take precedence.
