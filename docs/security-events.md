# Security Events

Nazo OAuth emits security audit events through structured `tracing` records with `target="audit"` and message `security audit event`.

Collectors should parse:

- `event`: stable event name.
- `fields`: JSON object containing `schema_version`, `event_category`, and event-specific fields.

The current schema version is `nazo.audit.v1`.

## SIEM Shape

Example collector-normalized record:

```json
{
  "timestamp": "2026-06-07T08:00:00Z",
  "service": "nazo-oauth-server",
  "target": "audit",
  "level": "INFO",
  "event": "token_issued",
  "fields": {
    "schema_version": "nazo.audit.v1",
    "event_category": "token_lifecycle",
    "client_id": "client-1",
    "user_id": "018f...",
    "subject_hash": "blake3-hex",
    "scope": "openid profile",
    "audience": "resource://default",
    "access_token_jti": "019...",
    "refresh_token_family_id": "019..."
  }
}
```

Raw credentials and bearer material must never appear in audit fields. The audit layer strips `access_token`, `refresh_token`, `authorization_code`, `client_secret`, `dpop_proof`, and `client_assertion`.

## Event Taxonomy

| Event | Category | Purpose |
| --- | --- | --- |
| `login_success` | `authentication` | Password login succeeded and a browser session was created. |
| `login_failure` | `authentication` | Password login failed without exposing the raw email or password. |
| `authorization_approved` | `authorization` | User approved an interactive authorization request. |
| `authorization_denied` | `authorization` | User denied an interactive authorization request. |
| `authorization_prompt_none_approved` | `authorization` | Silent authorization succeeded using an existing grant. |
| `token_issued` | `token_lifecycle` | Access token, and optionally refresh token or ID Token, was issued. |
| `refresh_rotated` | `token_lifecycle` | Refresh token rotation completed. |
| `token_revoked` | `token_lifecycle` | Token revocation endpoint accepted a revocation request. |
| `refresh_reuse_detected` | `token_replay` | Reuse of a revoked refresh token family was detected. |
| `dpop_replay_detected` | `credential_replay` | Duplicate DPoP proof `jti` was detected. |
| `client_assertion_replay_detected` | `credential_replay` | Duplicate `private_key_jwt` assertion `jti` was detected. |
| `client_created` | `client_lifecycle` | Client registration was created through admin or access-request flow. |
| `client_updated` | `client_lifecycle` | Client registration metadata was updated. |
| `admin_user_updated` | `administration` | Administrator changed user status, role, or admin level. |

Event names and categories use lowercase ASCII words separated by `_`; new events must be added to the implementation allowlist and this document in the same commit.
