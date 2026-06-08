# Changelog

All notable changes to this project are recorded here.

The format follows Keep a Changelog style, and this project uses semantic versioning once public releases are cut.

## Unreleased

### Added

- Added durable OpenID Foundation conformance evidence under `docs/conformance`, including the 2026-06-06 full 16-plan matrix result, workflow URLs, artifact metadata, plan IDs, profile combinations, pass counts, and exported artifact filenames.
- Added a production deployment guide covering container deployment, reverse proxy boundaries, key rotation, database and Valkey operations, live verification, and OIDF readiness.
- Added `SECURITY.md` with reporting guidance, vulnerability classes, production boundaries, and disclosure expectations.
- Added `docs/roadmap.md` as the version 1 scope record for implemented profiles, deployment controls, product boundaries, and evidence links.
- Added `docs/profile-matrix.md`, separating OAuth/OIDC, FAPI2 Security, FAPI2 Message Signing, deployment-security, and product-hardening requirements.
- Added `docs/threat-model.md` and `docs/refresh-token-rotation.md` for security boundaries and refresh-token state-machine behavior.
- Added `CHANGELOG.md`.
- Added token endpoint support for the standard RFC 8707 `resource` parameter as the normative single-resource input, while retaining the legacy `audience` parameter as an extension.
- Added supply-chain and release security gates with `cargo audit`, `cargo deny`, CycloneDX SBOM generation, Trivy image scanning, keyless artifact signing, and GitHub provenance attestations.
- Added PostgreSQL and Valkey HA, backup, restore, timeout, and partial-outage operations guidance.

### Changed

- Reworked `README.md` into a project-level entry point with status, feature scope, quick start, architecture, configuration, conformance, deployment, development, and security posture sections.
- Sanitized generic OAuth JSON `error_description` values so protocol responses use ASCII-safe descriptions consistently.
- Made the Argon2 password hash policy explicit: Argon2id, version 19, 19456 KiB memory, time cost 2, parallelism 1.
- Tightened proxy-terminated mTLS handling so forwarded certificate evidence is accepted only from configured trusted proxy CIDRs and duplicate forwarded certificate headers must agree on the same SHA-256 thumbprint.
- Marked `client_secret_post` as a compatibility client authentication method in project documentation and recommended `private_key_jwt` or mTLS for high-security clients.
- Switched JWT signing and verification from the RustCrypto-backed `jsonwebtoken` provider to the AWS-LC-backed provider and removed the direct RustCrypto `rsa` dependency.

### Fixed

- Reject token requests that send conflicting `resource` and `audience` inputs.
- Reject token requests whose `resource` value is not an absolute URI or contains a fragment.
- Fixed refresh-token lost-response recovery to allow only a short post-rotation retry window instead of accepting old tokens only after the window had elapsed.
- Removed `session_id` from successful login JSON responses; the session identifier is carried only by the HTTPOnly session cookie.

### Ignored

- Added `.codex_remote_handoff/`, Python `__pycache__` directories, `code_review.md`, and `code_revioew.md` to `.gitignore`.

### Version 1 Scope

- Version 1 centers on the authorization-server surface: OAuth 2.1, OpenID Connect, PAR/JAR, FAPI2 Security, selected FAPI2 Message Signing behavior, DPoP, mTLS sender constraints, durable conformance evidence, and production deployment controls.
- Implemented product surfaces include TOTP MFA, WebAuthn/passkeys, external OIDC/SAML federation, default-tenant SCIM provisioning, tenant-aware schema boundaries, and Rust resource-server middleware.
- Dynamic Client Registration, Client Configuration Management, Device Authorization Grant, Token Exchange, request-level dynamic tenant routing, and signed introspection responses remain outside the default version 1 scope.
