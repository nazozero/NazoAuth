# Current Scope

## Scope

Nazo Auth Server is an OAuth 2.1 and OpenID Connect authorization server with
FAPI2-oriented security profiles, repeatable conformance evidence, and
production deployment controls.

The project separates three surfaces:

- protocol conformance
- deployment security
- product extensions

## Core Profiles

| Profile | Status | Evidence |
| --- | --- | --- |
| `oauth2-baseline` | Implemented | Authorization code, PKCE, token, refresh, revocation, introspection, discovery, JWKS |
| `oauth2-security-bcp` | Implemented | Sender constraints, redirect policy, query-token rejection, replay controls |
| `oidc-basic-op` | Implemented and protocol-tested | [profile matrix](../protocol/profile-matrix.md) |
| `oidc-config` | Implemented and protocol-tested | Runtime discovery metadata and metadata truth tests |
| `fapi2-security` | Implemented and protocol-tested | PAR, PKCE S256, confidential clients, DPoP/mTLS-bound tokens |
| `fapi2-message-signing-authz-request` | Implemented and protocol-tested | Signed request objects at PAR with `aud`, `nbf`, and bounded `exp` |
| `fapi2-message-signing-jarm` | Implemented where advertised and protocol-tested | Signed authorization responses without unsafe fallback |
| `fapi2-message-signing-introspection` | Implemented/profile-scoped | RFC 9701 signed and encrypted introspection metadata is advertised only by the signed-introspection runtime profile |

## Protocol Boundaries

- Login responses carry session state only in the HTTPOnly session cookie.
- Password hashes use the documented Argon2id policy.
- Discovery metadata is generated from runtime profile and deployment state.
- FAPI2 Security keeps refresh tokens sender-constrained and avoids routine
  refresh-token rotation by default.
- Non-FAPI refresh-token rotation uses a documented lost-response retry state
  machine with replay detection.
- Request object `jti` replay protection is a stricter product policy, not a
  FAPI2 Message Signing requirement.
- DPoP proof replay protection tracks proof `jti` values within the proof
  validity window.
- `private_key_jwt` assertions enforce exact audience, time windows, `jti`
  replay detection, key rotation behavior, and disabled-client rejection.
- JWT access tokens carry issuer, audience, expiry, client/subject separation,
  scope or `authorization_details`, and DPoP or mTLS confirmation where
  required.
- RFC 8707 resource indicators support single-resource and multi-resource
  audience derivation across authorization requests, PAR, token exchange, and
  refresh-token audience narrowing.
- RFC 9728 protected resource metadata publishes the FAPI resource identifier,
  supported token presentation methods, DPoP algorithms, and optional mTLS/RAR
  capabilities.
- RFC 9396-style `authorization_details` are parsed, consent-bound, and carried
  into tokens for supported detail types.

## Deployment Security

- Proxy-terminated mTLS is explicit. Certificate forwarding is accepted only
  from trusted proxy CIDRs.
- Duplicate or conflicting forwarded certificate headers are rejected.
- The proxy-to-app hop must be protected by TLS, mTLS, or an equivalent trusted
  internal channel.
- `tls_client_auth` supports subject DN and SAN matching.
- `self_signed_tls_client_auth` uses registered client certificates with
  rotation semantics.
- Signing keys use encrypted tenant database generations and an independently
  protected wrapping root, with prepublished, active, grace, and retired states.
  An external-command signer supports provider integration; hardware custody
  and recovery require evidence from the selected KMS/HSM provider.
- External signer output is locally verified against the active public JWK
  before a JWT is returned.
- OpenTelemetry, structured security events, SBOM generation, dependency
  policy checks, container scanning, release signing, and provenance workflows
  are part of the release posture.
- PostgreSQL and Valkey HA, restore, timeout, and partial-outage behavior are
  documented in [ha-operations.md](../operations/ha-operations.md).

## Identity Platform Surface

- Directory-managed, host-routed tenant runtimes. Each active binding supplies
  a tenant, realm, organization, canonical host, and issuer; every request uses
  the matching immutable tenant graph, with no default-tenant fallback.
- TOTP MFA, backup codes, remembered MFA, and step-up authentication.
- WebAuthn/passkeys.
- Configuration-gated external OIDC, OAuth2 social, and trusted SAML-gateway
  federation. These login adapters are distinct from OpenID Federation
  trust-chain protocol support.
- SCIM 2.0 provisioning with hashed, rotatable, scoped, audited database tokens
  in the resolved tenant. No global deployment-token fallback exists.

## Rust Resource Server Support

- JWT access-token verifier for Rust resource servers.
- Framework-independent `http::Request` authorization helpers and the
  project's Actix HTTP integration. Historical Axum/Tower and tonic adapters
  have been removed rather than retained behind feature flags.
- DPoP proof verification for `typ`, embedded-JWK signature, `htu`, `htm`,
  `ath`, `jti` replay, and optional nonce policy before sender-constraint
  context is populated.
- Issuer, audience, scope, DPoP `cnf.jkt`, mTLS `cnf.x5t#S256`, and
  introspection fallback guidance.
- Policy and claims extension points run only after protocol invariants pass.

## Conditional or Excluded Scope

Stable protocol handlers may be active together, but the following surfaces
remain prerequisite-gated or intentionally bounded:

- Dynamic Client Registration / RFC 7591 and RFC 7592 require a configured
  initial access token and issue baseline client policy only.
- Device Authorization Grant server support is active on new databases, while
  client grant and cross-device authority remain explicit.
- External-token, refresh-token, or ID-token Token Exchange profiles.
- OpenID Federation 1.1 trust-chain behavior: entity configuration, trust
  anchors and chains, metadata policy, trust marks, and federation
  fetch/list/resolve endpoints. This is not required for the implemented
  third-party login adapters.
- RFC 9701 encrypted introspection responses outside the signed-introspection
  profile, or without per-client JWE response metadata.

Each item has a threat-model and acceptance-test entry in
[ecosystem-onboarding.md](../features/ecosystem-onboarding.md) or [tenancy.md](../features/tenancy.md).

## Evidence

- Black-box protocol evidence: project-owned protocol tests.
- Current profile behavior: [profile matrix](../protocol/profile-matrix.md).
- Negative protocol behavior: the relevant implementation tests and the
  [RFC compliance matrix](../protocol/rfc-compliance-matrix.md) are the current
  evidence index.
- Deployment guide:
  [deployment.md](../operations/deployment.md).
- Release controls:
  [release-security.md](../operations/release-security.md).
