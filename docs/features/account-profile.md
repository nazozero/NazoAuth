# Account profile endpoints

The first-party account surface uses the authenticated browser session and is
separate from OAuth bearer-token endpoints. Its current route contract is:

- `GET /auth/me` reads the current account projection.
- `PATCH /auth/me` replaces the submitted profile fields and requires the CSRF
  cookie/header pair.
- `GET /auth/me/applications` lists clients previously authorized by the
  current account.

There is no account-delete route and no user-facing application-revocation
route in this surface. Refactoring must not add either route implicitly.

## Authentication states

New local passwords, whether set through public registration, administrative
provisioning, or the CLI, must contain 12–1024 UTF-8 bytes. Public registration
rejects an invalid length with `400 invalid_request` before accessing the email
verification code, leaving that code available for a corrected request. This
creation rule does not change verification of existing passwords.

A fully authenticated session receives the public profile fields and
`mfa_required: false`. A password-authenticated session that still requires MFA
receives only `id`, `email`, `mfa_required: true`, and the CSRF token needed to
continue the challenge. The reduced pending-MFA projection prevents profile,
role, phone, address, and authorized-client data from being exposed before
step-up completes.

Missing, expired, inactive, or otherwise invalid sessions preserve the
`login_required` response and clear both session cookies. Repository and store
failures remain distinct service-unavailable protocol responses and fail
closed.

## Response caching and cross-origin access

Successful profile and authorized-application responses deliberately include
`Cache-Control: no-store` and `Pragma: no-cache`. This is a security hardening
for personally identifiable and authorization-history data. Error status,
body, content type, cookie clearing, and pre-existing error headers remain
unchanged.

The routes are statically registered under the credentialed `/auth/me` CORS
policy. Allowed origins may send `GET` and CSRF-bearing `PATCH` requests with
cookies. The unregistered `POST /auth/me` route continues to return not found,
and `OPTIONS` is handled by the CORS policy without invoking profile operations.

## Update consistency

The authorized-client count is read before profile or avatar mutation. A count
read failure therefore leaves the requested change unapplied. The response uses
the committed account result and that count; a later display-only query cannot
turn a successful write into a failure response. The count is a snapshot, not a
transactional guarantee about concurrent client grants.

The profile write is tenant-scoped and restricted to active users. A concurrent
account deactivation therefore causes the update to fail as login-required
instead of modifying an inactive account.

## Profile field syntax

`birthdate` accepts a four-digit year or a valid `YYYY-MM-DD` date; `0000`
represents an unspecified year. `locale` must be a syntactically valid BCP 47
language tag. `zoneinfo` must resolve in the IANA timezone database. Invalid
values are rejected before persistence.

## Session termination

Administrative account disable advances the existing authorization epoch and
revokes durable grants in the same transaction. Sessions retain the epoch from
login and compare it with the current account; re-enabling an account cannot
revive its earlier sessions. Client disable likewise revokes its durable grants.

Local logout with an existing session cookie requires the CSRF cookie/header
pair. Session-store failure returns service unavailable and retains the cookie
for retry; success is reported only after deletion. A request without a session
cookie is idempotent.
