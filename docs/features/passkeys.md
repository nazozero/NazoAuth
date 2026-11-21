# WebAuthn Passkeys

## Scope

The local identity profile supports WebAuthn/passkey registration and
email-first passkey login. Passkeys create normal server-side sessions and do
not bypass OAuth/OIDC authorization, consent, token, or tenant checks.

## Configuration

- `PASSKEY_RP_ID`: bare relying-party host name, without scheme, port, or path. The existing configuration admits DNS names and IPv4 hosts. Defaults to the host of `PASSKEY_ORIGIN`.
- `PASSKEY_RP_NAME`: display name shown by the browser during the WebAuthn ceremony.
- `PASSKEY_ORIGIN`: exact serialized browser origin expected in `clientDataJSON.origin`. Defaults to the origin of the issuer derived from `PUBLIC_BASE_URL`; an issuer path is not included. Explicit values must have no path, query, fragment, user information or trailing slash. HTTPS is required except for local development on localhost or a loopback IPv4 address. An IPv6 issuer can use a separately configured supported passkey origin.
- `PASSKEY_REQUIRE_USER_VERIFICATION`: requires authenticator user verification such as biometrics or PIN.
- `PASSKEY_REQUIRE_USER_HANDLE`: requires assertions to include the expected user handle for username-first login.

Production deployments keep user verification and user handle checks enabled.
WebAuthn binary fields always use canonical unpadded base64url. Remove the retired
`PASSKEY_STRICT_BASE64` setting from configuration.

The RP ID must match the origin host or a domain suffix at a label boundary.
The browser additionally enforces the public-suffix restriction. Configuration
errors fail at startup. Cross-origin embedding is not enabled by this profile;
Level 1 responses that omit `crossOrigin` remain compatible.

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
accounts. Dummy challenges preserve the response shape for absent accounts;
repeated requests can still distinguish enrollment through stable credential
identifiers. Discoverable, username-free login is unsupported.

### Browser response format

NazoAuth defines the HTTP envelope: finish requests contain `ceremony_id` and
`response`. The response uses the browser JSON representation defined by
[WebAuthn Level 3 §5.1](https://www.w3.org/TR/webauthn-3/#sctn-public-key-credential).
WebAuthn leaves delivery to the RP server to the application (§7); NazoAuth passes
this representation directly to its single `nazo-passkey` parser.

A browser client sends `PublicKeyCredential.toJSON()` as follows:

```javascript
await fetch("/auth/passkey/finish", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ ceremony_id, response: credential.toJSON() }),
});
```

Registration uses the same envelope at its finish endpoint and retains the
session cookie and CSRF header. The credential object contains matching `id` and
`rawId`, `type: "public-key"`, and its nested `response` dictionary with the
standard camelCase WebAuthn fields. The server decodes the credential ID once at
JSON admission; database lookup encodes that admitted ID to the existing textual
key. Signed `clientDataJSON`, authenticator data and attestation bytes retain their
original encoding through verification.

Registration explicitly requests `residentKey: "preferred"`,
`requireResidentKey: false` and `attestation: "none"`. Login remains email-first.
The library's optional attestation trust callback is not needed by this profile:
registration verifies statements without requiring manufacturer provenance.

## Security Model

`nazo-passkey` validates the challenge, origin, RP ID hash, authenticator
signature, signed user/backup flags and credential binding. NazoAuth selects the
RP policy and owns account/tenant lookup, ceremony lifetime and one-time
consumption, credential persistence, MFA decisions, sessions and audit.

Ceremony state is stored only in Valkey with a five-minute TTL and is consumed
with `GETDEL` before verification. NazoAuth treats missing, malformed, expired or
obsolete verifier-bound state as `400 invalid_request` with
`passkey ceremony expired.`. This includes a changed RP policy or verifier-state
format. An ordinary begin request creates current state; expired attempts need
no migration or manual cache cleanup. Persisted credentials remain bound to
`(tenant_id, user_id)` and retain their existing representation; credential ID
uniqueness is enforced per tenant.

Successful passkey login with authenticator-verified UV and a previously
initialized UV enrollment creates a normal HTTPOnly session with
`amr=["passkey", "passkey_uv", "mfa"]`. This satisfies the existing MFA
requirement without an additional OTP. Registration records whether UV was
established. An assertion with UV does not independently initialize a credential
that was registered without UV or whose historical UV state is unknown.
Assertions without eligible UV use the pending-MFA or remembered-device flow.

Existing credentials whose JSONB lacks UV history remain readable and usable as
a passkey factor; users do not need to register them again. To authorize UV for
future logins, complete an interactive TOTP or recovery-code verification and
then authenticate that passkey within five minutes while sending the existing
session cookie and matching `X-CSRF-Token`. The previous verified session must
belong to the same tenant and user. Remembered-device evidence and a historical
`passkey_uv` session cannot authorize this transition. The initializing assertion's
UV does not contribute `passkey_uv` or `mfa`; the existing remembered-device policy
still applies. A subsequent assertion can use the recorded UV enrollment.

For an MFA-enabled account, a user who can access only an older passkey and has
no usable TOTP, recovery code or valid remembered-device proof receives a pending
MFA session. The signature is valid, but that session cannot automatically
complete step-up, enroll a new TOTP factor or disable MFA. Normal MFA enrollment
confirms TOTP and returns recovery codes before enabling the account's MFA flag.
To recover access, use an existing independent factor or a separately authorized
account-recovery procedure. Missing UV history cannot be reconstructed from the
credential key, current UV bit or historical AMR.

Upgrading the verifier preserves sessions that were already issued. The new
credential history cannot retrospectively establish how an older session earned
its `passkey_uv` or `mfa` methods. Those sessions retain their existing lifetime
and, while fresh, their existing credential-management permissions. They cannot
directly initialize an older credential's UV history without independent OTP or
recovery-code evidence. The five-minute management window and configured session
TTL therefore also bound this transition for sessions issued before the upgrade.

The profile list selects only tenant/user-scoped display metadata. Registration
and login begin read scoped credential IDs without loading credential JSON.
Login finish loads and validates only the selected credential's complete material;
registration finish verifies and persists the new credential.

## Credential Persistence

Credential insertion and deletion commit with their Required `passkey_registered`
and `passkey_deleted` audit events in the same adapter-owned transaction. Each
mutation and its audit fact either both persist or neither persists.

Credential JSONB uses the WebAuthn Serde implementation. Identity consumes the
credential Value from its owned repository row when decoding, avoiding a copy of
the JSON tree. Existing full records and material-only records remain readable;
the relational credential ID and sign counter are authoritative, and historical
JSON copies must agree. New optional fields record the account handle, UV
initialization and backup state. Missing historical security facts remain
unknown; they are never inferred from the current configuration.

Authentication updates the sign counter and signed backup facts together before
creating a session. The protocol library returns `CredentialUpdate` and a
`CounterStatus` after signature verification. NazoAuth rejects `NonIncreasing`
under its counter-risk policy. Persistence commits the accepted update using a
compare-and-set on the prior counter, backup eligibility and backup state. UV initialization, when independently authorized, is part of that
same update and cannot be reverted by a concurrent authentication. A CAS conflict
fails login and retains the existing counter-conflict audit behavior. Zero-only
counters remain supported; one-use Valkey challenges provide replay protection
for such authenticators. Comparing the prior backup state also prevents a
zero-counter authentication from overwriting a concurrent backup-state change.
The stored credential format and database schema are unchanged.

Stored attestation evidence distinguishes no attestation, self attestation and
verified statements with an untrusted certificate. Manufacturer and hardware
trust require a trusted attestation chain in addition to signature verification.
