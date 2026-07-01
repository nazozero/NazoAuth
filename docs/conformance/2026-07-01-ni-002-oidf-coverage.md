# NI-002 RFC 8628 OIDF Coverage Check

Date: 2026-07-01

Implementation branch: `codex/ni-002-device-grant`

## Scope

This record checks whether the OpenID Foundation Conformance Suite has official
authorization-server tests for RFC 8628 Device Authorization Grant that should be
added to the repository OIDF execution matrix.

## Checked Sources

- OpenID Foundation Conformance Suite public source, master snapshot `076fbf4`
- Search terms: `RFC 8628`, `Device Authorization Grant`,
  `device_authorization_endpoint`,
  `urn:ietf:params:oauth:grant-type:device_code`,
  `authorization_pending`, `slow_down`

## Result

No AS-side RFC 8628 Device Authorization Grant official plan was found in the
checked suite snapshot. The search found RFC 8414 metadata schema support for
`device_authorization_endpoint`, Federation fixture metadata containing the
device grant value, and CIBA/client-side conditions that reuse
`authorization_pending` and `slow_down`. Those are not official RFC 8628 AS
behavior plans for this server.

## Repository Action

No OIDF matrix entry is added in this change. NI-002 is covered by local tests
for feature-gated metadata, request parsing, request validation, polling
interval/`slow_down`, expiration, denial, disabled endpoint behavior, and missing
`device_code` token requests. If OIDF publishes official RFC 8628 AS plans later,
the OIDF matrix and workflow inputs must be updated in the same change that
claims that coverage.
