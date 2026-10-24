# Changelog

Project changes are recorded by release. Before 0.5.0, the project iterates
rapidly and version updates do not preserve compatibility with historical
releases. Entries below describe their respective releases, not current support.
Release dates use UTC+8.

## 0.3.6 - 2026-10-24

### Fixed

- Resolve Device client identity from authenticated credentials when the request
  form omits `client_id`, preventing a panic for valid Basic authentication.
- Give pooled PostgreSQL transactions explicit cancellation ownership, align
  offer and user-disable lock ordering, and retain healthy connections after
  completed rollbacks while discarding unfinished or broken transactions.
- Enforce the shared 12–1024 byte password rule before public registration
  consumes a verification code, matching administrator and CLI provisioning.
- Handle IPv6 literals in logout URI validation and outbound JWKS, Request
  Object, CIBA and logout requests while preserving network and TLS policy.
- Correct Native SSO refresh-family handling, dependency-failure classification,
  DPoP, client-attestation and mTLS parsing, HTTP signatures and SCIM responses.
- Preserve typed credential holder bindings through immediate and deferred
  issuance, and reject malformed stored bindings.

### Maintenance

- Remove redundant transaction and credential conversion work. Correct benchmark
  worker isolation and credential reuse, and align client-registration, Passkey,
  Helm and protocol documentation with the implemented contracts.

[Source changes](https://github.com/nazozero/NazoAuth/compare/v0.3.5...v0.3.6)

## 0.3.5 - 2026-10-22

### Fixed

- Accept PAR requests without an early Token sender binding. Validate supplied
  bindings against client policy and enforce required bindings at token issuance.
- Apply the existing per-client PKCE compatibility policy to baseline confidential
  OIDC dynamic registration. Public, FAPI, sender-constrained and non-OIDC clients
  retain their PKCE requirements; registration updates preserve administrator policy.

### Conformance

- Publish the complete October 22 OIDF regression for this release with
  NazoAuthCtl v0.3.7: 1,169 modules across 44 plans, with 1,121 PASSED, 40 REVIEW,
  8 SKIPPED, zero failures and zero incomplete modules. All FAPI, CIBA and
  OpenID4VCI groups passed. The [release record](https://github.com/nazozero/NazoAuth/releases/tag/v0.3.5)
  links every public plan and the complete module index.

[Source changes](https://github.com/nazozero/NazoAuth/compare/v0.3.4...v0.3.5)

## 0.3.4 - 2026-10-21

The GitHub Release was withdrawn and replaced by v0.3.5; the source tag is retained.

### Security and correctness

- Preserve opaque authorization payloads through KV operations and enforce current
  tenant, client and user eligibility, revocation epochs and administrator-owned
  dynamic-registration limits.
- Correct DPoP endpoint binding, authentication assurance claims, CIBA audiences,
  Device client authentication, PAR/consent lifetimes, SCIM event handling, JOSE
  critical headers and mdoc certificate validation.
- Commit Required identity audit facts with business mutations. External audit
  anchoring remains asynchronous, and durable outcomes survive unknown commit
  acknowledgements.
- Add avatar revision compare-and-swap and ownership-aware object cleanup.
  Complete protocol/JWE key prepublication, activation and retirement, and add
  bounded TOTP rewrapping through the existing maintenance path.
- Preserve operation and candidate identity during controller approval recovery.
  Report actual migration effects and correct storage compatibility exercised by
  the companion controller's fresh-database backup flow.

### Dependencies and execution

- Reduce federation queries and reuse borrowed OpenID4VP encoding inputs.
- Refresh Rust dependencies, CI actions, build images and Python tooling. Update
  TLS verification and certificate-root dependencies, including the audit receiver
  and Python validation tools. Explicitly enable the Sigstore AWS-LC provider.
- Keep database and KV implementation choices in adapters behind application ports.

### Upgrade

- Apply the included user-deletion, device-approval, dataset-ownership, TOTP-rotation
  and avatar-revision migrations through the controller's migration/recovery flow.
- Retain required TOTP decryption keys until rewrapping finishes. Stop old avatar
  writers during the revision transition and restart pending uploads afterward.

[Source changes](https://github.com/nazozero/NazoAuth/compare/v0.3.3...v0.3.4)

## 0.3.3 - 2026-10-18

### Database migration baseline

- Consolidate the 127 migration pairs present in v0.3.2 into one baseline,
  reducing the SQL file count from 254 to 2. Fresh databases install the final
  schema and initial data directly.
- Adopt databases that completed v0.3.2 migrations by adding baseline bookkeeping
  while preserving business data, historical migration records, objects and grants.
- Upgrade databases older than v0.3.2, or with incomplete v0.3.2 migrations, to
  v0.3.2 first. Database rollback uses a verified backup.

[Source changes](https://github.com/nazozero/NazoAuth/compare/v0.3.2...v0.3.3)

## 0.3.2 - 2026-10-17

### Security and correctness

- Enforce federated-login MFA, cross-client token introspection authorization and
  consistent FAPI client-assertion policy.
- Correct SD-JWT disclosure reconstruction and credential validity checks.
- Require administrator-granted `security_policy.introspection_audiences` for
  cross-client introspection. Upgrade every server instance before configuring
  a nonempty value.

### Execution

- Remove repeated database lookups, hashes, parsing and payload copies across
  token, credential, JWE, mdoc and HTTP paths. Borrow JWE header fields and share
  authenticated TLS certificate chains through the existing trust boundary.
- Preserve operator protocol 3 and release-manifest schema 7.

[Source changes](https://github.com/nazozero/NazoAuth/compare/v0.3.1...v0.3.2)

## 0.3.1 - 2026-10-12

### Discovery

- Derive OpenID4VCI discovery scopes from configured credential profiles and
  update their publication with issuance-module enablement and draining state.
- Add optional `ADDITIONAL_SCOPES_SUPPORTED` to publish supported business scopes.
  Client authorization continues to use the existing access policies.
- Keep OIDC and OAuth discovery scopes consistent, deduplicate values and reject
  invalid OAuth scope syntax at startup.

### Dependencies

- Update `sfv` to 0.16.0, `zeroize` to 1.9.1 and GitHub Actions dependencies.

[Source changes](https://github.com/nazozero/NazoAuth/compare/v0.3.0...v0.3.1)

## 0.3.0 - 2026-10-11

### Security and upgrade

- Separate audit receiver acknowledgement authority from exporter credentials;
  preserve commit confirmation and signed durable receipts. Existing audit
  installations require the coordinated receiver/worker/role cutover described
  in [the audit role guide](docs/operations/security-audit-ledger-roles.md).
- Enforce FAPI policy floors, rate-limit unauthenticated SCIM audit admission,
  verify UI provenance, and reconcile tenant routing from PostgreSQL facts.
- Reject cutover while any legacy issuance receipt is live, including rows
  without ciphertext, because their refresh-family revocation link is absent.
- Preserve released issuance and audit facts during database upgrades; follow
  [the v0.2.16 upgrade guide](docs/operations/upgrade-from-v0.2.16.md) and retain
  verified recovery material. Previously applied tenant-policy migrations are
  not automatically replayed.
- Use common UTC-day boundaries for generated mdoc certificates without
  extending credential validity.
- Package and attest the protocol and its crypto dependency together. Operator
  protocol 3 and release-manifest schema 7 remain unchanged.

Conformance and performance reports identify the source revision tested.


### Removed

- The file signing-key backend, `keys-import`, `JWK_KEYS_DIR`, and the obsolete
  performance keyset container. Runtime and test key managers use database
  repositories.
- Valkey state-version aliases. Callers use the core state-version types.
- Implicit revocation-time backfill during mdoc certificate import. Revoked
  records must include their own timestamp.

### Documentation

- Rebuild the English and Chinese READMEs around deployment, application
  integration, and current capabilities; state the pre-0.5.0 version policy.
- List all 29 profiles in the official `Nazo Auth Server 0.2.0` certification
  records, including OID4VCI/OID4VP with HAIP, and display the OpenID Certified
  mark with its registered version.
- Describe the storage interfaces separately from the PostgreSQL and Valkey
  adapters supplied by the current distribution.
- Correct first installation to create an administrator, enroll MFA, and then
  bind the controller.

## 0.2.15 - 2026-09-06

### Fixed

- Preserve the configured mTLS listener port in each tenant's endpoint aliases.
- Accept root-owned Direct TLS keys readable only by the dedicated service
  group, while rejecting broader key access.
- Verify client-certificate possession during the TLS handshake and require
  deployment or currently approved client-specific CA trust for PKI mTLS
  authentication. Direct TLS and trusted RFC 9440 forwarding now apply the
  same client authorization checks; registered self-signed keys remain supported.
- Keep direct TLS and proxy-facing mTLS on the configured AEAD cipher policy.
- Reload server certificates when their configured paths change, preserving the
  previous working certificate if a replacement cannot be loaded.
- Preserve tenant identity in protocol security audit records, including key,
  client, and trust administration events.

## 0.2.14 - 2026-09-05

### Fixed

- Generate ISO/IEC 18013-5 mDL document signer and IACA certificates with a
  PrintableString country name, the mdlDS extended-key-usage identifier, and no
  document-signer Basic Constraints extension. Existing managed certificates
  require an explicit mdoc rotation to publish the corrected profile.

## 0.2.13 - 2026-09-05

### Fixed

- Align tenant key-generation results with the database keyset's canonical
  positive decimal revision. Tenant-scoped generation also rejects requests
  outside the OpenID4VC signing profile before any key material is created.
  This result contract requires NazoAuthCtl 0.2.26 or newer.

## 0.2.12 - 2026-09-05

### Added

- Persist managed OpenID4VC certificate, IACA and revocation material in the
  tenant's encrypted signing-key aggregate, and persist the audit-anchor
  checkpoint in PostgreSQL so every instance observes the same authority.

### Changed

- Replace managed OpenID4VC certificate and revocation files with explicit
  one-shot `keys-import` and `mdoc-import` migration commands for existing
  deployments. Pre-IACA bundles retain their old key and trust anchor through
  import, then use an explicit mdoc rotation to create current IACA material.
  Ordinary startup does not infer or copy legacy material.

### Fixed

- Apply pending database migrations and initialize the tenant directory before
  `keys-import` reads legacy keys. This allows an offline upgrade from a
  file-backed deployment whose database predates the signing-key table.

## 0.2.11 - 2026-09-04

### Added

- Persist encrypted tenant signing keysets through the database repository,
  with shared initialization, rotation and explicit import of existing keys.
- Support browser-direct signed PUT avatar uploads through an S3-compatible
  adapter, shared upload coordination and conditional final publication.
- Allow administrator-defined global avatar storage or complete per-tenant
  configurations, with tenant-isolated paths and optional storage access.

### Changed

- Require NazoAuthCtl 0.2.24 or newer to provision and recover deployment
  signing-key wrapping roots. Existing key material must be explicitly imported
  with the same root before updating an existing deployment; ordinary startup
  does not fall back to local signing-key files.
- Leave avatar storage disabled when neither global nor tenant configuration
  exists. Local storage must be explicitly selected and includes the tenant UUID
  in its path. Existing local avatars require manual migration before cutover.
- Report configured storage failures without silently switching backends.

See [avatar storage](docs/operations/avatar-direct-upload.md) and
[HA operations](docs/operations/ha-operations.md) for current storage and recovery
guidance. This release does not complete Issue #108's remaining
mdoc material and whole-system multi-instance acceptance work.

## 0.2.8 - 2026-09-02

### Added

- Add dynamic tenant directory control operations, tenant-local runtime
  generations, Direct TLS SNI/Host binding, and tenant-owned OpenID4VC secret
  and background-task lifecycles.

### Removed

- Remove third-party validator-specific leases, onboarding, provenance,
  OpenID4VP evidence receipts, migrations, and repository orchestration. An
  external validator now uses only ordinary public tenant/client behavior.

## 0.2.0 - 2026-08-24

### Changed

- Harden protocol policy, TLS, elliptic-curve, URI, client-authentication, and
  credential-validation boundaries against malformed or ambiguous inputs.
- Pin the embedded administration UI to an immutable, attested release artifact
  through the reviewed frontend descriptor chain.
- Update release, CI, container, and dependency controls to preserve exact-source
  provenance through published binaries and OCI images.
- Extend the explicit controller compatibility range through NazoAuthCtl 0.2.x
  while retaining protocol-version and signed-release checks.

### Fixed

- Close fail-open and replay gaps across OAuth/OIDC, FAPI, CIBA, OpenID4VC,
  operator tasks, onboarding, persistence, and key-management state transitions.

## 0.1.36 - 2026-08-13

### Fixed

- Validate BuildKit's current OCI artifact attestation manifests with a closed
  schema that binds the canonical empty config, artifact type, image subject,
  and exact SBOM and provenance predicates before publication.
- Pin release OCI exports to the reviewed artifact representation so runner
  defaults cannot silently change the publication contract.

## 0.1.35 - 2026-08-13

### Changed

- Strengthen OAuth, OIDC, FAPI, CIBA, OpenID4VC, operator-task, onboarding,
  storage, and key-management contract validation with behavior-focused
  regression coverage.
- Update reviewed Rust, Python, GitHub Actions, and container dependencies.

### Fixed

- Close fail-open and integrity gaps across management authentication,
  registration reservations, compact JWE parsing, runtime receipts, durable
  keyset writes, and protocol admission boundaries.

## 0.1.34 - 2026-08-12

- Remove the redundant supplementary keyless blob signature. The governed
  ReleaseManifest and standard build-provenance attestations already bind each
  immutable binary to public transparency evidence, while a third signature
  duplicated that proof and made retries dependent on cosign signing-config
  behavior.

## 0.1.33 - 2026-08-12

- Keep the supplementary keyless binary bundle offline because the public
  ReleaseManifest and build-provenance attestations already provide the
  transparency-log record; this makes immutable release retries idempotent.

## 0.1.0 - 2026-07-31

### Added

- Added the independently signed Rust `nazoauthctl` lifecycle binary with
  idempotent installation support for Podman, Docker,
  and Linux systemd deployments, with generated or operator-supplied
  PostgreSQL/Valkey connections, pre-migration backups, application-served
  signed UI assets, transactional host/container updates and rollback, and
  signed, replay-safe target-runtime delegation through the closed
  `nazoauth operator-task` entry point.
- Added RFC 9865 forward cursor pagination for SCIM user listing with index as
  the default, stateless AES-256-GCM actor/query-bound cursors, deterministic
  keyset traversal, exact pagination errors, and truthful capability metadata.
- Added a production deployment guide covering container deployment, reverse proxy boundaries, key rotation, database and Valkey operations, and live verification.
- Added `SECURITY.md` with reporting guidance, vulnerability classes, production boundaries, and disclosure expectations.
- Added `docs/project/roadmap.md` as the current scope record for implemented profiles, deployment controls, product boundaries, and evidence links.
- Added `docs/protocol/profile-matrix.md`, separating OAuth/OIDC, FAPI2 Security, FAPI2 Message Signing, deployment-security, and product-hardening requirements.
- Added `docs/security/threat-model.md` and `docs/protocol/refresh-token-rotation.md` for security boundaries and refresh-token state-machine behavior.
- Added `CHANGELOG.md`.
- Added token endpoint support for the standard RFC 8707 `resource` parameter as the normative single-resource input and removed the non-standard `audience` extension.
- Added supply-chain and release security gates with `cargo audit`, `cargo deny`, CycloneDX SBOM generation, Trivy image scanning, keyless artifact signing, and GitHub provenance attestations.
- Added README quality signals for CI quality gates, coverage, dependency review, CodeQL, conformance evidence, and release security controls.
- Added PostgreSQL and Valkey HA, backup, restore, timeout, and partial-outage operations guidance.
- Added bounded RFC 8693 Token Exchange support for locally issued access-token to access-token exchanges, including subject/actor token validation, target restrictions, scope downscoping, and `issued_token_type` responses.
- Added default-closed RFC 7591 Dynamic Client Registration behind the runtime-module policy, with optional initial access token enforcement.
- Added default-closed RFC 7592 Dynamic Client Registration Management for DCR-created clients, with hashed registration access tokens, GET/PUT credential rotation, full-replacement updates, and DELETE deactivation.
- Added dynamic-client lifecycle audit events and ecosystem onboarding documentation covering baseline, FAPI2, Message Signing, CIBA, Device Grant, DCR/DCRM, Token Exchange, and deferred third-party JWT bearer trust boundaries.
- Added modular third-party login provider registry with dynamic OIDC/OAuth2 social provider routes, QQ/WeChat social adapter presets, non-secret provider discovery, and admin onboarding metadata.

### Changed

- Replaced mutually exclusive global OAuth/FAPI message-signing selection for
  new clients with versioned composable client policy; stable server modules
  now default on for new databases while grants and elevated client authority
  remain deny-by-default. Existing inherited module and client behavior is
  preserved by an atomic compatibility migration.
- Completed the M8 emerging-protocol governance review with dated product,
  standards/conformance, local-test, and security-isolation decisions. This
  documentation change adds no candidate runtime capability or certification
  claim.
- Changed the project license metadata to AGPL-3.0-or-later and added the top-level
  license text.
- Reworked `README.md` and `README.zh-CN.md` into project-level entry points for scope,
  conformance, local setup, configuration, deployment, checks, and security
  boundaries.
- Sanitized generic OAuth JSON `error_description` values so protocol responses use ASCII-safe descriptions consistently.
- Made the Argon2 password hash policy explicit: Argon2id, version 19, 19456 KiB memory, time cost 2, parallelism 1.
- Tightened proxy-terminated mTLS handling so forwarded certificate evidence is accepted only from configured trusted proxy CIDRs and duplicate forwarded certificate headers must agree on the same SHA-256 thumbprint.
- Marked `client_secret_post` as a compatibility client authentication method in project documentation and recommended `private_key_jwt` or mTLS for high-security clients.
- Grouped GitHub Actions Dependabot updates, ignored `dtolnay/rust-toolchain` toolchain tags, and skipped Codecov upload when `CODECOV_TOKEN` is unavailable while retaining local coverage generation.
- Switched JWT signing and verification from the RustCrypto-backed `jsonwebtoken` provider to the AWS-LC-backed provider and removed the direct RustCrypto `rsa` dependency.

### Fixed

- Reject token requests that send conflicting `resource` and `audience` inputs.
- Reject token requests whose `resource` value is not an absolute URI or contains a fragment.
- Fixed refresh-token lost-response recovery to allow only a short post-rotation retry window instead of accepting old tokens only after the window had elapsed.
- Removed `session_id` from successful login JSON responses; the session identifier is carried only by the HTTPOnly session cookie.

### Ignored

- Added `.codex_remote_handoff/`, Python `__pycache__` directories, `code_review.md`, and `code_revioew.md` to `.gitignore`.

### Current Scope

- The current scope centers on the authorization-server surface: OAuth 2.1, OpenID Connect, PAR/JAR, FAPI2 Security, selected FAPI2 Message Signing behavior, DPoP, mTLS sender constraints, durable conformance evidence, and production deployment controls.
- Implemented product surfaces include TOTP MFA, WebAuthn/passkeys, external OIDC/SAML federation, default-tenant SCIM provisioning, tenant-aware schema boundaries, and Rust resource-server middleware.
- Dynamic Client Registration and Client Configuration Management are implemented behind an explicit feature gate; request-level dynamic tenant routing remains outside the default scope.
