# Changelog

All notable changes to this project are recorded here.

The format follows Keep a Changelog style, and this project uses semantic versioning once public releases are cut.

## Unreleased

### Added

- Added durable OpenID Foundation conformance evidence under `docs/conformance`, including the 2026-06-06 full 16-plan matrix result, workflow URLs, artifact metadata, plan IDs, profile combinations, pass counts, and exported artifact filenames.
- Added a production deployment guide covering container deployment, reverse proxy boundaries, key rotation, database and Valkey operations, live verification, and OIDF readiness.
- Added `SECURITY.md` with reporting guidance, vulnerability classes, production boundaries, and disclosure expectations.
- Added `docs/roadmap.md`, converting the latest static review into a maintained checklist.
- Added `CHANGELOG.md`.
- Added token endpoint support for the standard RFC 8707 `resource` parameter as the normative single-resource input, while retaining the legacy `audience` parameter as an extension.

### Changed

- Reworked `README.md` into a project-level entry point with status, feature scope, quick start, architecture, configuration, conformance, deployment, development, and security posture sections.
- Sanitized generic OAuth JSON `error_description` values so protocol responses use ASCII-safe descriptions consistently.
- Made the Argon2 password hash policy explicit: Argon2id, version 19, 19456 KiB memory, time cost 2, parallelism 1.

### Fixed

- Reject token requests that send conflicting `resource` and `audience` inputs.
- Reject token requests whose `resource` value is not an absolute URI or contains a fragment.
- Removed `session_id` from successful login JSON responses; the session identifier is carried only by the HTTPOnly session cookie.

### Ignored

- Added `.codex_remote_handoff/`, Python `__pycache__` directories, `code_review.md`, and `code_revioew.md` to `.gitignore`.

### Roadmap

- Complete richer OIDC `claims` parameter semantics, including `essential`, `value`, and `values`.
- Add explicit ACR/AMR policy and real step-up authentication support.
- Expand RFC 8707 support from the current single-resource model to full multi-resource handling.
- Add Dynamic Client Registration, Client Configuration Management, Rich Authorization Requests, and broader security profile configuration.
- Add release signing, SBOM/provenance, and supply-chain verification flow.
