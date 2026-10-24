# WebAuthn Passkeys

## Scope

The local identity profile supports WebAuthn/passkey registration and
email-first passkey login. Passkeys create normal server-side sessions and do
not bypass OAuth/OIDC authorization, consent, token, or tenant checks.

## Configuration

- `PASSKEY_RP_ID`: bare relying-party host name, without scheme, port, or path. Defaults to the host of `PASSKEY_ORIGIN`.
- `PASSKEY_RP_NAME`: display name shown by the browser during the WebAuthn ceremony.
- `PASSKEY_ORIGIN`: exact browser origin expected in `clientDataJSON.origin`. Defaults to the issuer derived from `PUBLIC_BASE_URL`.
- `PASSKEY_REQUIRE_USER_VERIFICATION`: requires authenticator user verification such as biometrics or PIN.
- `PASSKEY_REQUIRE_USER_HANDLE`: requires assertions to include the expected user handle for username-first login.
- `PASSKEY_STRICT_BASE64`: requires WebAuthn binary fields to use spec-compliant base64url without padding.

Production deployments keep user verification, user handle, and strict base64
enabled.

## Endpoints

User passkey management:

- `POST /auth/me/passkeys/registration/begin`
- `POST /auth/me/passkeys/registration/finish`
- `GET /auth/me/passkeys`
- `DELETE /auth/me/passkeys/{passkey_id}`

Passkey login:

- `POST /auth/passkey/begin`
- `POST /auth/passkey/finish`

Registration begin/finish and deletion require the existing HTTPOnly session
cookie, CSRF validation, and interactive authentication within five minutes.
Accounts requiring MFA must have recent verified MFA, including passkey user
verification. An old session receives `403 reauthentication_required`; listing
credentials does not require a fresh proof. Login uses an email-first flow so the
server can scope allowed credentials to one active tenant-bound user.

Email-first login exposes stable allowed credential identifiers for enrolled
accounts. Dummy challenges keep the response shape usable for absent accounts,
but do not guarantee account non-enumerability across repeated requests. This
profile does not implement discoverable, username-free login.

## Security Model

WebAuthn ceremonies use the `passkey-auth` verifier. The server verifies challenge freshness, exact origin, RP ID hash, authenticator signature, user verification policy, user-handle binding, and authenticator counter replay protection.

Ceremony state is stored only in Valkey with a five-minute TTL and is consumed with `GETDEL` at finish time. Persisted credentials are bound to `(tenant_id, user_id)` and credential ID uniqueness is enforced per tenant.

Successful passkey login with authenticator-verified UV creates a normal
HTTPOnly session with `amr=["passkey", "passkey_uv", "mfa"]`. That signed proof
satisfies the existing MFA requirement without an additional OTP. Assertions
without UV retain the existing pending-MFA or remembered-device flow; the
`passkey` method alone is not evidence of user verification.

The profile list selects only tenant/user-scoped display metadata. Registration
begin reads the scoped credential IDs for its exclusion list without loading
credential JSON. Login loads the complete credential needed for verification;
registration finish verifies and persists the new credential.

## Credential Persistence

Credential insertion and deletion commit with their Required `passkey_registered`
and `passkey_deleted` audit events in the same adapter-owned transaction. Each
mutation and its audit fact either both persist or neither persists.

Credential JSONB uses the existing WebAuthn Serde implementation. Identity
consumes the credential Value from its owned repository row when decoding,
avoiding a copy of the JSON tree. The persisted shape, malformed-record
consistency error, tenant/user binding and sign-counter checks are unchanged.
