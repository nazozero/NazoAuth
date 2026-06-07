# Roadmap

This roadmap is derived from the latest static review in `code_revioew.md` and is maintained as the project checklist. The target is a Rust-native, security-profiled, conformance-tested OAuth2 / OpenID Connect Authorization Server core.

The roadmap separates three concerns that must not be mixed:

- Normative conformance: what OIDC, OAuth, FAPI2 Security, and FAPI2 Message Signing profiles actually require.
- Deployment security: how a production deployment preserves those protocol properties at the proxy, key, database, cache, release, and observability layers.
- Product hardening: stricter-than-profile policies and ecosystem/product capabilities that may be valuable but are not FAPI2 requirements.

## Current Status

| Area | Finding | Status |
| --- | --- | --- |
| Trust evidence | Conformance results, security policy, threat model, and release evidence must be public and repeatable. | In progress |
| Profile matrix | Each profile needs explicit grants, response types, client auth, token binding, JAR/JARM, PAR, refresh policy, TTL, and metadata rules. | Done |
| Metadata truth | Discovery metadata must not overclaim unsupported or deployment-disabled capabilities. | In progress |
| OIDC completeness | OIDC Core behavior needs a profile-by-profile checklist and tests for required OP features. | Done for current profile matrix |
| FAPI2 Security | Baseline FAPI2 Security must stay distinct from Message Signing and product hardening. | Defined |
| FAPI2 Message Signing | Signed authorization requests, JARM, and signed introspection responses should be tracked as separate options. | Defined |
| mTLS | Current integration is proxy-terminated mTLS and must be documented, constrained, and extended toward full RFC 8705 subject/SAN semantics. | In progress |
| DPoP | Proof `jti` replay prevention is normative; strict nonce enforcement is profile/product policy and must be documented that way. | Done |
| Sessions | Login response should not expose the session identifier in JSON. | Done |
| Password hashing | Argon2 policy should be explicit and versioned. | Done |
| Refresh policy | FAPI2 Security should not use rotation by default; non-FAPI rotation needs documented lost-response recovery semantics. | Done |
| Resource servers | Provide verifier guidance and Rust middleware so resource servers validate JWT access tokens correctly. | Done |
| Operations | HA, backups, observability, key lifecycle, SBOM/provenance, and security release process need production evidence. | Done for core deployment controls |

## P0: Normative Conformance

- [x] Store durable OIDF conformance evidence under `docs/conformance`.
- [x] Add `SECURITY.md` with reporting and production boundary guidance.
- [x] Remove `session_id` from the login JSON response; sessions are carried only by the HTTPOnly session cookie.
- [x] Make the Argon2 password hash policy explicit: Argon2id, version 19, memory 19456 KiB, time cost 2, parallelism 1.
- [x] Add a profile matrix. For each profile, list allowed grants, response types, client authentication methods, token binding methods, JAR/JARM policy, PAR policy, refresh policy, token TTLs, and discovery metadata. See `docs/profile-matrix.md`.
- [x] Define `oauth2-baseline`, `oauth2-security-bcp`, `oidc-basic-op`, and `oidc-config` as separate profiles with their exact endpoint, parameter, metadata, and negative-test requirements. See `docs/profile-matrix.md`.
- [x] Define `fapi2-security` as PAR + PKCE S256 + confidential clients + `private_key_jwt` or mTLS client authentication + sender-constrained access tokens via DPoP or mTLS. See `docs/profile-matrix.md`.
- [x] Add a runtime `fapi2-security` profile switch that requires client-authenticated PAR, rejects authorization requests that do not use PAR, enforces authorization code lifetime of 60 seconds or less, and rejects resource owner password credentials.
- [x] Define the `fapi2-security` refresh-token policy: no routine refresh-token rotation by default; use sender-constrained refresh/access tokens.
- [x] If refresh rotation is enabled for compatibility, migration, or non-FAPI profiles, document lost-response retry semantics as a state machine with replay detection tests. See `docs/refresh-token-rotation.md`.
- [x] Define `fapi2-message-signing-authz-request` as FAPI2 Security plus signed JAR request objects at the PAR endpoint. See `docs/profile-matrix.md`.
- [x] Add a runtime `fapi2-message-signing-authz-request` profile switch that requires and verifies signed request objects at PAR, requires `aud`, requires `nbf`, requires `exp` with lifetime no longer than 60 minutes, and accepts `typ=oauth-authz-req+jwt`.
- [x] Define `fapi2-message-signing-jarm` separately when JARM is implemented and tested. See `docs/profile-matrix.md`.
- [x] Define `fapi2-message-signing-introspection` separately when signed introspection responses are implemented and tested. See `docs/profile-matrix.md`.
- [x] Keep request object `jti` replay protection as optional product hardening unless a specific ecosystem profile requires it; do not document it as a normative FAPI2 Message Signing requirement.
- [x] Add DPoP proof replay cache tests: track proof `jti` per proof validity window and reject duplicates.
- [x] Add client assertion replay tests for `private_key_jwt`: exact issuer `aud`, `exp`/`iat` window, and `jti` replay cache.
- [x] Add `private_key_jwt` key rotation and disabled-client behavior tests.
- [x] Enforce audience/resource binding for access tokens.
- [x] If RFC 8707 resource indicators are supported, test single-resource and multi-resource behavior, audience derivation, and rejection of ambiguous, duplicate, or malformed resource values.
- [x] Add JWT access token profile tests: issuer, audience, expiry, `client_id`/`sub` separation, scope or `authorization_details`, `cnf.jkt` or `cnf.x5t#S256`, algorithm allowlist, `kid` handling, and revocation/introspection fallback.
- [x] Add negative conformance fixtures: overclaimed metadata, weak client auth, unsigned JAR in hardened profiles, missing DPoP proof, DPoP without nonce where required, bearer token at sender-constrained resource servers, query-token use, redirect URI mismatch, and stale JWKS. See `docs/conformance/negative-fixtures.md`.

## P0: Deployment Security

- [x] Add a threat model covering authorization code theft, redirect mix-up, JAR replay, DPoP replay, mTLS header spoofing, refresh token reuse, CSRF, XSS, key compromise, and partial Valkey/PostgreSQL outage. See `docs/threat-model.md`.
- [x] Add metadata truth tests: each advertised discovery capability must have a corresponding integration or unit test proving the endpoint behavior.
- [x] Split advertised capabilities by profile or deployment configuration where support depends on mTLS/proxy/JARM/JAR policy.
- [x] Keep proxy-terminated mTLS as an explicit deployment profile, not an implicit application security property.
- [x] Enforce trusted proxy CIDR checks before accepting mTLS certificate forwarding headers.
- [x] Document required reverse-proxy header stripping for all forwarded certificate headers.
- [x] Reject duplicate or conflicting forwarded certificate headers. Standardizing on one representation remains a deployment documentation task.
- [x] Require TLS or mTLS on the proxy-to-app hop, or otherwise bind forwarded certificate metadata to a trusted internal channel.
- [x] Add negative tests for forged forwarded certificate headers from untrusted source IPs.
- [x] Implement full `tls_client_auth` subject DN/SAN matching.
- [x] Implement self-signed certificate registration and rotation semantics for `self_signed_tls_client_auth`.
- [x] Add certificate expiry and rotation tests.
- [x] Add KMS/HSM backends for signing key lifecycle.
- [x] Add OpenTelemetry traces, metrics, and logs.
- [x] Define a structured security event taxonomy and SIEM export format. See `docs/security-events.md`.
- [x] Add `cargo audit`, `cargo deny`, SBOM, container scanning, release signing, and provenance. See `deny.toml`, `docs/release-security.md`, `conformance-security`, and `release-security`.
- [x] Add fuzz/property tests for parsers, JWT/JWK handling, redirect URI validation, request object merging, DPoP validation, and OAuth error serialization.
- [x] Document PostgreSQL and Valkey HA, backup, restore, timeout, and partial-outage behavior. See `docs/ha-operations.md`.

## P1: Product Hardening

- [x] Represent strict DPoP nonce enforcement as hardened profile behavior and test downgrade boundaries.
- [x] Optional stricter-than-FAPI policy: require request object `jti` with replay cache for signed JAR.
- [x] Mark `client_secret_post` as a compatibility method in documentation and examples; recommend `private_key_jwt` or mTLS for high-security clients.
- [x] Complete OIDC `claims` request semantics for `essential`, `value`, and `values`.
- [x] Strengthen `auth_time`, `max_age`, `acr_values`, `azp`, `sid`, and session-related ID Token behavior.
- [x] Add an independent OIDC `sid` value to login sessions and propagate it to ID Tokens without exposing the HTTPOnly session cookie value.
- [x] Add consent and transaction-binding tests for high-risk `authorization_details`, especially payments or write APIs.
- [x] Expand RFC 8707 support to multi-resource handling when an ecosystem use case requires it.
- [x] Implement RFC 9396 Rich Authorization Requests when structured authorization is required.
- [x] Add OIDC RP-Initiated Logout and Back-Channel Logout.

## P1: Ecosystem Onboarding

- [x] Evaluate RFC 7591 Dynamic Client Registration as an ecosystem onboarding feature, not as default AS-core scope. See `docs/ecosystem-onboarding.md`.
- [x] If DCR is added, threat-model redirect URI validation, client metadata, JWKS URI fetching, software statements, initial access tokens, and client update/delete authorization first. See `docs/ecosystem-onboarding.md`.
- [x] Evaluate RFC 7592 Client Configuration Management only after DCR threat modeling is complete. See `docs/ecosystem-onboarding.md`.
- [x] Evaluate Device Authorization Grant for CLI, TV, and constrained-device ecosystems. See `docs/ecosystem-onboarding.md`.
- [x] Evaluate RFC 8693 Token Exchange for service delegation, impersonation, and actor-token ecosystems. See `docs/ecosystem-onboarding.md`.
- [x] Publish conformance fixtures and example clients for backend web, SPA, native, machine-to-machine, DPoP, and `private_key_jwt`. See `examples/resource-server-fixtures.md`.

## P2: Identity Platform

- [ ] Add WebAuthn/passkeys.
- [x] Add TOTP, backup codes, remembered MFA, and step-up authentication. See `docs/mfa.md` and migration `20260607000500_totp_mfa_step_up`.
- [ ] Add external OIDC/SAML identity provider federation.
- [x] Add tenant/realm/organization boundaries. See `docs/tenancy.md` and migration `20260607000400_tenant_realm_organization_boundaries`.
- [x] Add SCIM 2.0 for enterprise provisioning. See `docs/scim.md`.

## P2: Rust Ecosystem

- [x] Publish resource-server verifier core for Rust integrations. See `src/resource_server.rs` and `docs/resource-server-verifier.md`.
- [x] Publish framework-specific resource-server middleware for Actix Web, Axum/Tower, and tonic. See `src/resource_server.rs` and `docs/resource-server-verifier.md`.
- [x] Provide issuer/audience validation, scope guards, DPoP `cnf.jkt` checks, mTLS `cnf.x5t#S256` checks, and introspection fallback guidance. JWKS cache packaging remains a framework/crate follow-up. See `src/resource_server.rs` and `docs/resource-server-verifier.md`.
- [x] Add policy and claims extension points without allowing extensions to bypass protocol invariants. The verifier returns claims only after protocol invariants pass; adapters must run extension hooks after verification.
