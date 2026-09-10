# Security Events

## Evidence and durability boundaries

NazoAuth has several security-event producers. The shared ledger and its outbox
are owned by the [persistence port](../../crates/persistence/src/lib.rs);
the current [PostgreSQL adapter](../../crates/persistence-postgres/src/repositories/audit_ledger.rs)
implements their storage. A structured log line alone is not a durable receipt.

| Path | Guarantee |
| --- | --- |
| `audit_event` | Validates fields, logs `target="audit"`, then tries a bounded 4,096-entry in-process queue. The worker retries the oldest append from 100 ms up to 5 s indefinitely. Queue saturation/disconnection is reported as `target="audit.persistence"`, `persistence_status="not_queued"`. Queued events can be lost on process exit before persistence. |
| `audit_event_required` | Awaits ledger append before logging `persistence_status="durable"` and `event_id`; append failure propagates to the caller. This does not put a separate business mutation in the same transaction. |
| Transactional repository append | Token issuance, refresh rotation/reuse handling, and tenant directory/resource operations append their owned audit event with the corresponding durable mutation in one database transaction. |
| External anchor worker | Exports only committed ledger events through the durable outbox. Receiver acceptance, retry ordering, freshness, and remaining trust limits are specified in [audit anchoring](audit-anchor.md). |

`ensure_audit_storage` checks writer availability and required privileges before
high-impact work. Required anchor mode also checks exporter health. Where the
mutation and ledger do not share a transaction, the caller records a required
`*_intent` before changing state and emits an outcome afterward. An intent
proves admission to an attempt; it does not prove the mutation committed.

## Structured HTTP/application events

The [application audit adapter](../../crates/authorization-server/src/adapters/audit.rs)
owns the event allowlist below. Collectors parse `event` and the serialized JSON
`fields` on tracing records with target `audit` and message `security audit event`.
Fields contain `schema_version="nazo.audit.v1"`, `event_category`, and the
producer's event-specific values. For example:

```json
{
  "event": "login_success",
  "fields": {
    "schema_version": "nazo.audit.v1",
    "event_category": "authentication",
    "tenant_id": "<resolved-tenant-id>",
    "user_id": "<user-id>"
  }
}
```

The HTTP boundary supplies immutable tenant context. The adapter captures it
before queueing, adds `tenant_id`, and rejects conflicting caller-supplied
identity. Events outside a tenant request do not inherit an earlier request's
tenant. Payloads larger than 65,536 bytes are rejected.

The adapter removes only these **top-level** fields: `access_token`,
`refresh_token`, `authorization_code`, `client_secret`, `dpop_proof`, and
`client_assertion`. It does not recursively redact arbitrary JSON. Producers
must allowlist minimal fields and exclude credentials, passwords, private keys,
cookies, and nested or differently named bearer material. Subject identifiers
and token IDs still require access control and a retention policy.

## Application event taxonomy

Event names and categories use lowercase ASCII words separated by `_`. Keep
this table synchronized with `AUDIT_EVENT_DEFINITIONS` when changing a producer.
An allowed name is vocabulary, not proof that a particular operation emitted it.

| Category | Events |
| --- | --- |
| `administration` | `admin_mutation_intent`, `controller_identity_approval_issued`, `controller_slot_created`, `controller_slot_revoked`, `controller_slot_rotated`, `admin_user_created`, `admin_user_updated`, `admin_grant_revoked`, `admin_access_request_rejected` |
| `authentication` | `federation_login_success`, `login_failure`, `login_success`, `mfa_backup_codes_regenerated`, `mfa_challenge_failure`, `mfa_challenge_success`, `mfa_disabled`, `mfa_step_up_success`, `mfa_totp_enabled`, `passkey_login_failure`, `passkey_login_success`, `passkey_registered`, `passkey_registration_rejected` |
| `authorization` | `authorization_approved`, `authorization_denied`, `authorization_decision_intent`, `authorization_prompt_none_approved`, `ciba_authorization_approved`, `ciba_authorization_denied`, `ciba_authorization_started`, `ciba_authorization_intent`, `ciba_decision_intent`, `device_authorization_approved`, `device_authorization_denied`, `device_authorization_started`, `device_decision_intent` |
| `client_lifecycle` | `client_created`, `client_updated`, `dynamic_client_configuration_read`, `dynamic_client_configuration_updated`, `dynamic_client_deleted`, `dynamic_client_registered` |
| `credential_lifecycle` | `openid4vci_credential_dataset_deleted`, `openid4vci_credential_dataset_updated` |
| `credential_replay` | `client_assertion_replay_detected`, `dpop_replay_detected`, `federation_provider_mismatch_rejected`, `federation_saml_replay_rejected` |
| `identity_lifecycle` | `external_identity_linked`, `external_identity_relink_denied`, `external_identity_unlinked` |
| `provisioning` | `scim_token_denied`, `scim_token_used` |
| `session_lifecycle` | `oidc_logout` |
| `token_lifecycle` | `refresh_rotated`, `token_issued`, `token_issuance_intent`, `token_revoked` |
| `token_replay` | `refresh_reuse_detected` |
| `trust_lifecycle` | `mtls_trust_anchor_approved`, `mtls_trust_bundle_exported`, `mtls_trust_anchor_rejected`, `mtls_trust_anchor_requested`, `mtls_trust_anchor_revoked` |

## Repository-owned events and separate stores

The [token issuance repository](../../crates/persistence-postgres/src/repositories/token_issuance.rs)
writes `token_issued`, `refresh_rotated`, and `refresh_reuse_detected` with its
issuance/tenant identity. The [directory control repository](../../crates/persistence-postgres/src/repositories/directory_control.rs)
writes `tenant_directory_{operation}` with category `tenant_directory`; the
[tenant resource executor](../../crates/persistence-postgres/src/tenant_resource_executor.rs)
writes `tenant_resource_{operation}` with category `tenant_resource`. These
producers own their transactional payloads and operation vocabulary. They do
not pass through the application allowlist above; consumers must not assume
all ledger payloads share its additional `nazo.audit.v1` fields.

Identity `identity_security_events` (including `mfa_totp_attempt`,
`mfa_backup_code_attempt`, and `admin_user_update`), SCIM audit records and
Security Event Token outboxes, runtime-module events, and the controller's
filesystem journals have separate owners and schemas. They are not
automatically copied into this ledger or covered by its external anchor.

Monitor `audit.persistence` failures and `audit.anchor` retries alongside
business outcomes. A successful request, an intent record, a tracing line, a
committed ledger event, and an externally accepted checkpoint are distinct
observations and must not be reported interchangeably.
