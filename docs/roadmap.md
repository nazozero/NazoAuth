# Roadmap

This roadmap is derived from the latest static review in `code_revioew.md` and turns it into a maintained project checklist. The target is a Rust-native, security-profiled, conformance-tested OAuth2 / OpenID Connect Authorization Server core.

## Review Findings

| Area | Finding | Status |
| --- | --- | --- |
| Trust evidence | Conformance results, security policy, threat model, and release evidence must be public and repeatable. | In progress |
| Metadata truth | Discovery metadata must not overclaim unsupported or deployment-disabled capabilities. | Planned |
| OIDC completeness | OIDC Core behavior needs a profile-by-profile checklist and tests for required OP features. | Planned |
| mTLS | Current integration is proxy-terminated mTLS and must be documented, constrained, and extended toward full RFC 8705 subject/SAN semantics. | In progress |
| JAR | Unsigned request objects are acceptable for baseline OIDC only; hardened profiles should require signed JAR and replay protection. | Planned |
| DPoP | Strict nonce behavior should be represented as a hardened profile, with compatibility behavior tested separately. | Planned |
| Sessions | Login response should not expose the session identifier in JSON. | Done |
| Password hashing | Argon2 policy should be explicit and versioned. | Done |
| Refresh rotation | Lost-response retry semantics need a state diagram, threat model, and regression tests. | Planned |
| Client secrets | `client_secret_post` should be compatibility-only, not the recommended high-security method. | Planned |
| Resource servers | Provide verifier guidance and eventually Rust middleware so resource servers validate JWT access tokens correctly. | Planned |
| Operations | HA, backups, observability, key lifecycle, SBOM/provenance, and security release process need production evidence. | Planned |

## P0: Trust And Correctness

- [x] Store durable OIDF conformance evidence under `docs/conformance`.
- [x] Add `SECURITY.md` with reporting and production boundary guidance.
- [x] Remove `session_id` from the login JSON response; sessions are carried only by the HTTPOnly session cookie.
- [x] Make the Argon2 password hash policy explicit: Argon2id, version 19, memory 19456 KiB, time cost 2, parallelism 1.
- [ ] Add a threat model covering authorization code theft, redirect mix-up, JAR replay, DPoP replay, mTLS header spoofing, refresh token reuse, CSRF, XSS, key compromise, and partial Valkey/PostgreSQL outage.
- [ ] Add metadata truth tests: each advertised discovery capability must have a corresponding integration or unit test proving the endpoint behavior.
- [ ] Split advertised capabilities by profile or deployment configuration where support depends on mTLS/proxy/JARM/JAR policy.
- [ ] Document and test refresh token lost-response retry semantics as an explicit state machine.

## P0: Security Profiles

- [ ] Define named profiles such as `oauth2-baseline`, `oauth2-security-bcp`, `oidc-basic-op`, `fapi2-security`, and `fapi2-message-signing`.
- [ ] Add a hardened/FAPI profile that requires PAR, signed request objects, request object `jti`, PKCE, exact resource indicators, and sender-constrained access tokens.
- [ ] Keep unsigned request objects available only for baseline OIDC compatibility.
- [ ] Represent DPoP nonce enforcement as profile behavior and test downgrade boundaries.
- [ ] Mark `client_secret_post` as a compatibility method in documentation and examples; recommend `private_key_jwt` or mTLS for high-security clients.

## P0: mTLS / RFC 8705

- [ ] Keep proxy-terminated mTLS as an explicit deployment profile.
- [ ] Enforce trusted proxy CIDR checks before accepting mTLS certificate forwarding headers.
- [ ] Document required reverse-proxy header stripping for all forwarded certificate headers.
- [ ] Implement full `tls_client_auth` subject DN/SAN matching.
- [ ] Implement self-signed certificate registration and rotation semantics for `self_signed_tls_client_auth`.
- [ ] Add certificate expiry and rotation tests.

## P1: Protocol Surface

- [ ] Implement RFC 7591 Dynamic Client Registration.
- [ ] Implement RFC 7592 Client Configuration Management.
- [ ] Implement Device Authorization Grant.
- [ ] Implement RFC 8693 Token Exchange.
- [ ] Implement RFC 9396 Rich Authorization Requests.
- [ ] Expand RFC 8707 support from the current single-resource model to multi-resource handling.
- [ ] Add OIDC RP-Initiated Logout and Back-Channel Logout.
- [ ] Complete OIDC `claims` request semantics for `essential`, `value`, and `values`.
- [ ] Strengthen `auth_time`, `max_age`, `acr_values`, `azp`, `sid`, and session-related ID Token behavior.

## P1: Identity And Operations

- [ ] Add WebAuthn/passkeys.
- [ ] Add TOTP, backup codes, remembered MFA, and step-up authentication.
- [ ] Add external OIDC/SAML identity provider federation.
- [ ] Add tenant/realm/organization boundaries.
- [ ] Add SCIM 2.0 for enterprise provisioning.
- [ ] Add KMS/HSM backends for signing key lifecycle.
- [ ] Add OpenTelemetry traces, metrics, and logs.
- [ ] Define a structured security event taxonomy and SIEM export format.
- [ ] Add `cargo audit`, `cargo deny`, SBOM, container scanning, release signing, and provenance.
- [ ] Add fuzz/property tests for parsers, JWT/JWK handling, redirect URI validation, request object merging, DPoP validation, and OAuth error serialization.

## P2: Rust Ecosystem

- [ ] Publish resource-server verifier crates or middleware for Actix Web, Axum/Tower, and tonic.
- [ ] Provide JWKS cache, issuer/audience validation, scope guards, DPoP checks, mTLS `cnf` checks, and introspection fallback.
- [ ] Publish conformance fixtures and example clients for backend web, SPA, native, machine-to-machine, DPoP, and `private_key_jwt`.
- [ ] Add policy and claims extension points without allowing extensions to bypass protocol invariants.
