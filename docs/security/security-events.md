# Security Events

## Evidence and durability boundaries

NazoAuth has several security-event producers. The shared ledger and its outbox
are owned by the [persistence port](../../crates/persistence/src/lib.rs);
the current [PostgreSQL adapter](../../crates/persistence-postgres/src/repositories/audit_ledger.rs)
implements their storage. A structured log line alone is not a durable receipt.

| Path | Guarantee |
| --- | --- |
| `audit_event` | Validates fields, logs `target="audit"`, then tries a bounded 4,096-entry in-process queue. Attempted batches retry intact from 100 ms up to 5 s. In Required anchor mode, explicit Telemetry that has never been submitted may instead be discarded before its first append, as specified below. Queue saturation/disconnection is reported as `target="audit.persistence"`, `persistence_status="not_queued"` — or `"dropped_required"` when the dropped event belongs to the required evidence class. Queued events can be lost on process exit before persistence. Required-class events emitted through this path additionally log `persistence_status="misrouted_required"` (once per event name per process): they should use `audit_event_required` or a transactional append instead. |
| `audit_event_required` | Awaits ledger append before logging `persistence_status="durable"` and `event_id`; append failure propagates to the caller. This does not put a separate business mutation in the same transaction. |
| Transactional repository append | Token issuance, refresh rotation/reuse handling, and tenant directory/resource operations append their owned audit event with the corresponding durable mutation in one database transaction. |
| External anchor worker | Exports only committed ledger events through the durable outbox. Receiver acceptance, retry ordering, freshness, and remaining trust limits are specified in [audit anchoring](audit-anchor.md). |

`ensure_audit_storage` checks writer availability and required privileges before
high-impact work. Required anchor mode also checks exporter health. A path whose
required append commits before the business mutation, or in the same transaction,
may use `ensure_transactional_ready`: it retains the dynamic exporter-health gate
and lets the append itself check writer capability. Authorization decisions,
Device decisions, and CIBA creation/decisions use this path; a readiness or
required-intent append failure prevents the business mutation. Silent
`prompt=none` authorization applies the same dynamic readiness gate before its
atomic decision commit. Fresh token
issuance without earlier authorization-code consumption or Native SSO persistence
also uses it for no-refresh, normal rotation, and `PreserveExisting` policies.
Other issuance shapes retain the full storage preflight.

Where the mutation and ledger do not share a transaction, the caller records a
required `*_intent` before changing state and emits an outcome afterward. An
intent proves admission to an attempt; it does not prove the mutation committed.

## Telemetry expiry and recovery admission

In Required anchor mode, the worker still checks live exporter health before
appending. If that check fails, it discards explicit, never-attempted Telemetry
instead of keeping best-effort work until it nearly reaches the lag limit.
Otherwise it removes explicit Telemetry whose original age exceeds
`AUDIT_ANCHOR_MAX_LAG_SECONDS`, using the same clock and seconds boundary as
Required admission. Expiry alone is insufficient: a nearly expired event can
become overdue between append and export, repeatedly closing Required admission.

Either discard is permitted only while the batch has **never** been submitted to the
repository and has no Required completion waiter. The event allowlist remains
the sole class authority: Required-class and unknown names survive even when
misrouted onto the Telemetry channel. An append attempt latches the batch as
non-discardable before entering the repository; every retry keeps its exact
members, IDs, timestamps and payloads because an error does not prove rollback.
Already persisted events and business retention are untouched. Empty filtered
batches issue no append. Future/unknown clock state is not treated as expiry.

Each discarded group emits `target="audit.persistence"`,
`discarded_events`, with `persistence_status="expired_unattempted_telemetry"`
for age expiry or `"unavailable_export_unattempted_telemetry"` for closed export
admission. The latter is best-effort rejection, not an expiry or durable receipt.
Collectors must count these reasons separately from queue-full rejection and
persistence success; no payload, tenant or credential is logged by the expiry
record. A successful read and its initial audit log do not promise that its
best-effort telemetry will eventually reach the ledger. Memory remains bounded
by the existing 4,096 queue entries and at most 64 entries in the active batch.

This does not relax Required freshness or promise instant recovery: existing
persistent evidence, uncertain batches, unavailable storage, invalid checkpoints
and receiver rejection still block the relevant operations. Recovery acceptance
must check that *unattempted stale Telemetry* does not repeatedly re-close the
gate after the mandatory backlog drains, not merely that a final drain succeeds.

Optional and Disabled retain their existing no-health-gate policy. They do not
guarantee bounded disk backlog during indefinite exporter failure or absence;
Required-mode fault results must not be generalized to them. Deployments needing
outage admission control must run the independent exporter with Required mode
and monitor accepted rate, pending age, disk headroom and recovery. An age gate
is not a universal byte quota, and no mode may discard Required evidence to
manufacture a flat storage curve.

The four independent cleanup count queries also consume their complete result
streams before using deletion counts or returning the guarded connection. A
late commit error, cancellation or disconnection cannot be reported as confirmed
cleanup success. Categories retain their separate commit boundaries: an earlier
category can already be committed when a later category fails. No new outer
transaction, SQL round trip, retention deadline or queue is introduced.

## Structured HTTP/application events

The [application audit adapter](../../crates/nazoauth/src/adapters/audit.rs)
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
Each definition also carries an evidence class: `required` marks security
evidence whose durable persistence must not silently fail (intents, decisions,
mutations, replay detections, issuance); `telemetry` marks best-effort
operational signal. The class governs routing checks and the
`misrouted_required`/`dropped_required` statuses above. Only explicit Telemetry
is eligible for the pre-persistence expiry below; Required and unknown names
are never expired by that policy. Only these events are telemetry:
`authorization_approved`, `authorization_denied`,
`authorization_prompt_none_approved`, `ciba_authorization_approved`,
`ciba_authorization_denied`, `ciba_authorization_started`,
`device_authorization_approved`, `device_authorization_denied`,
`device_authorization_started`, `dynamic_client_configuration_read`,
`federation_login_success`, `login_failure`, `login_success`,
`mfa_challenge_failure`, `mfa_challenge_success`, `mfa_step_up_success`,
`passkey_login_failure`, `passkey_login_success`, `scim_token_used`. An
unlisted or unknown event name is treated as required, never as telemetry.

| Category | Events |
| --- | --- |
| `administration` | `admin_mutation_intent`, `controller_identity_approval_issued`, `controller_slot_created`, `controller_slot_revoked`, `controller_slot_rotated`, `admin_user_created`, `admin_user_updated`, `admin_grant_revoked`, `admin_access_request_rejected` |
| `authentication` | `federation_login_success`, `login_failure`, `login_success`, `mfa_backup_codes_regenerated`, `mfa_challenge_failure`, `mfa_challenge_success`, `mfa_disabled`, `mfa_step_up_success`, `mfa_totp_enabled`, `passkey_login_failure`, `passkey_login_success`, `passkey_registered`, `passkey_registration_rejected` |
| `authorization` | `authorization_decision_committed`, `authorization_approved`, `authorization_denied`, `authorization_decision_intent`, `authorization_prompt_none_approved`, `ciba_authorization_approved`, `ciba_authorization_denied`, `ciba_authorization_started`, `ciba_authorization_intent`, `ciba_decision_intent`, `device_authorization_approved`, `device_authorization_denied`, `device_authorization_started`, `device_decision_intent` |
| `client_lifecycle` | `client_created`, `client_updated`, `dynamic_client_configuration_read`, `dynamic_client_configuration_updated`, `dynamic_client_deleted`, `dynamic_client_registered` |
| `credential_lifecycle` | `openid4vci_credential_dataset_deleted`, `openid4vci_credential_dataset_updated` |
| `credential_replay` | `client_assertion_replay_detected`, `dpop_replay_detected`, `federation_provider_mismatch_rejected`, `federation_saml_replay_rejected` |
| `identity_lifecycle` | `external_identity_linked`, `external_identity_relink_denied`, `external_identity_unlinked` |
| `provisioning` | `scim_token_denied`, `scim_token_used` |
| `session_lifecycle` | `oidc_logout` |
| `token_lifecycle` | `token_issued`, `token_issuance_intent`, `token_revoked`, `refresh_family_security_revoked` |
| `token_replay` | `refresh_reuse_detected` |
| `trust_lifecycle` | `mtls_trust_anchor_approved`, `mtls_trust_bundle_exported`, `mtls_trust_anchor_rejected`, `mtls_trust_anchor_requested`, `mtls_trust_anchor_revoked` |

## Repository-owned events and separate stores

New refresh-family creation executes its scope lock, family lock, capacity retirement,
contract reference fence and insertion in one invoker-rights database function inside
the caller's transaction. Each retired family still appends its own Required audit
fact. The transaction owner remains responsible for confirmed commit before success;
the function neither commits independently nor changes retention deadlines. The principal fence similarly sets the transaction-local lock timeout, then locks and rechecks the client followed by the user in one call; the timeout remains active for the later receipt and family locks.


The [token issuance repository](../../crates/persistence-postgres/src/repositories/token_issuance.rs)
writes `token_issued` and `refresh_reuse_detected` with its
issuance/tenant identity. One committed issuance produces exactly one durable
event: a rotation carries `rotated_from_id` and `refresh_token_family_id` on
`token_issued` rather than a separate event, so routine flows stay at one
ledger row per logical operation. Fresh issuance no longer creates a separate
per-token ownership row; its Required audit remains synchronous with the
principal-version check and any refresh-family mutation. The [directory control repository](../../crates/persistence-postgres/src/repositories/directory_control.rs)
writes `tenant_directory_{operation}` with category `tenant_directory`; the
[tenant resource executor](../../crates/persistence-postgres/src/tenant_resource_executor.rs)
writes `tenant_resource_{operation}` with category `tenant_resource`. These
producers own their transactional payloads and operation vocabulary. They do
not pass through the application allowlist above; consumers must not assume
all ledger payloads share its additional `nazo.audit.v1` fields.

Refresh replay-retention migration and client authentication-class downgrade
append `refresh_family_security_revoked` with category `token_lifecycle` in the
same transaction as family invalidation. The payload contains tenant/client/
family identities and a reason (`public_replay_retention_cutover` or
`client_authentication_class_downgrade`), never raw tokens or guessed reuse
facts. They reuse `nazo_persist_security_audit_event` and the existing canonical
payload, pending-set, exporter and ACK lifecycle. The downgrade trigger is an
invoker-rights adapter function; it adds no audit-table privileges or separate
worker. A failed Required append rolls back the class change and revocations.
The application registry also classifies this event as Required. Existing
management intent/completion events retain their original behavior.

Identity `identity_security_events` (including `mfa_totp_attempt`,
`mfa_backup_code_attempt`, and `admin_user_update`), SCIM audit records and
Security Event Token outboxes, runtime-module events, and the controller's
filesystem journals have separate owners and schemas. They are not
automatically copied into this ledger or covered by its external anchor.

Monitor `audit.persistence` failures and `audit.anchor` retries alongside
business outcomes. A successful request, an intent record, a tracing line, a
committed ledger event, and an externally accepted checkpoint are distinct
observations and must not be reported interchangeably.

## Committed browser authorization decisions

Explicit approval, explicit denial and prompt-none use one durable
`authorization_decision_committed` fact owned by the authorization decision
repository. The same fact is its tenant-scoped consent/PAR consumption fence;
necessary grant changes commit atomically with it. These flows no longer emit
a separate `authorization_decision_intent` or duplicate approval/denial
Telemetry outcome. Historical event names remain readable.

The fact means the decision committed, not that the browser received a code.
Code publication occurs only after affirmative commit. Code-store failure,
response loss, timeout or cancellation never frees a committed fence. Unknown
commit results fail closed. Cancelling a request before commit acknowledgement
prevents that request from publishing a code, but does not revoke a decision
already sent to storage: its atomic grant/fact/fence may still commit. This can
leave an approved-but-undelivered decision; retries must preserve the same
request/PAR identity and cannot consume a committed fence again. Cancellation
after acknowledgement may also leave a stored code whose response was lost.
This contract does not promise durable evidence
for pre-commit crash attempts that caused no effective authorization.

The event type is reserved: ordinary audit append cannot create a business
authority fact. Export and chain construction may happen later, but export
acknowledgement does not erase a still-needed business fence. The exporter
projects only audit-safe fact fields, not raw code or full code payload.


### DCR and endpoint revocation transaction ownership

Dynamic client registration creation, configuration replacement, and deletion
now pass the hashed source address through the existing purpose store. The
PostgreSQL owner obtains the actual client view and appends respectively
`dynamic_client_registered`, `dynamic_client_configuration_updated`, or
`dynamic_client_deleted` on the same connection inside its business transaction.
Replacement retains the current registration credential comparison; deletion
retains dependent grant/family invalidation. Lifecycle evidence is derived from
the actual changed row and contains no registration token, secret, or digest.
The application no longer appends a separate successful outcome after commit.

The authenticated revocation endpoint uses the audited revocation command.
Verified access tokens remain access-only revocation authority and retain a zero
refresh-member count. Refresh revocation retains the existing family lock and
client/tenant predicates. Both effects and the `token_revoked` event commit
together. An unknown token remains a successful, non-disclosing no-op with
attempt evidence; an audit event does not assert that a token existed.
Lower-level recovery revocation retains its separate existing contract.

Dynamic transactional readiness still checks current anchor health in required
mode. The transaction's own required append is the writer failure boundary;
preflight is not an atomicity proof. Complete result and transaction
acknowledgement precede success. The existing `DiscardOnDrop` guard discards the
physical connection on error or cancellation until a successful complete
transaction outcome is known. An unknown acknowledgement does not prove
rollback and does not authorize an automatic retry under a new operation.

Source regressions `dcr_required_event_failure_rolls_back_each_owned_effect` and
`required_revocation_event_failure_rolls_back_access_and_refresh_effects` inject
task-scoped PostgreSQL audit INSERT failures, compare actual business rollback
state, and read committed event counts. They have not been formatted, compiled,
or executed at this integrated candidate. Physical commit acknowledgement loss,
cancellation, process crashes, and pool behavior still need independent
execution. This change does not extend transaction ownership to remaining
administrative effect/outcome windows tracked separately as I07.


### Silent decision admission and preparation lifetime

The prompt-none application delegates live grant coverage to the accepting
decision owner. Its neutral contract requires current active tenant/client/user
and canonical scope/resource/authorization-detail coverage at commit. The
PostgreSQL owner retains principal-then-grant locks and the existing canonical
coverage policy; missing coverage retains `consent_required`, and unavailable
storage remains a dependency failure. The removed early read did not authorize
a later decision. Denied coverage can now reach code preparation; no measured
CPU or latency improvement is claimed.

Committed silent and interactive decisions discard their consent/PAR preparation
using the original admission snapshot's exact version. Cleanup runs only after
confirmed commit and code publication; failure cannot change the committed
response or release the durable request/PAR fence. Failed cleanup leaves the
original TTL as the recovery boundary. Expiry and durable retention deadlines
are unchanged. Cleanup adds no detached task or retry queue.
After successful disposal, a new request using the consumed PAR handle cannot
recover its former parameters, including `state`; it follows the existing
missing-request-URI rejection path. A concurrent request that already loaded
that snapshot still encounters the durable decision fence.
The real PG/Valkey regressions cover single-use code, durable decision counts,
cleanup failure and lost acknowledgements, snapshot replacement, concurrent
replay and final coverage storage failures. Performance and long-term storage
acceptance require separate measurements.


JWT bearer grant processing now evaluates pure scope/target admission after
signature/sender validation and before client-assertion and grant replay
consumption. Known-invalid admission does not burn either assertion role. This
changes only that pre-consumption failure ordering; both existing replay
namespaces and the durable JTI-plus-sender issuance identity remain. It does not
make an indeterminate consumption or issuance retryable, and it does not infer
durable equivalence from a cache marker. The real signed-JWT/Valkey regression
source proves the intended boundary when executed; current execution is pending.

Refresh preparation consumes its owned default scopes and terminal original
authentication-context fields into TokenIssue. The original context snapshot
still survives an eligible successor replacement, and the nested ID-token SID
Some/None representation is preserved. The existing consistency guard remains
because public mutable issuance fields still permit a contradictory input;
ownership moves do not establish a sealed refresh-issuance type.


Certificate facts now share the immutable DER-chain owner when transport facts
are cloned into authentication work. Builders finish the chain before
publication; test-only corruption uses copy-on-write so it cannot alter a second
request fact owner. Trusted-proxy admission, cached parse failures, current
tenant trust, client identity, token binding, and keepalive revocation checks
retain their existing owners. Sharing DER is not caching a trust or authorization
result. Existing real-certificate and live tenant-anchor tests are retained;
candidate formatting, compilation and execution remain pending.


## Administrative credential datasets and mTLS trust outcomes

The dataset put/delete and mTLS approve/reject/revoke repository owners append
their existing `credential_lifecycle` and `trust_lifecycle` Required events on
the accepting business connection. The source event and exact mutation effect
must agree before one fresh canonical outcome is appended. A real no-op emits
no accepting outcome; cardinality, projection or decode failure rolls back.
Dataset responses are decoded from the actual returned encrypted row before
COMMIT, and successful HTTP views require a confirmed ACK. Readiness preflight
does not write a separate intent, and HTTP does not append a second outcome.
Payloads contain effect identity and outcome metadata, never claims, ciphertext,
certificate PEM, private keys, client secrets or free-form review notes.


## Current administrator in the grant revocation owner

Grant revocation keeps the existing target-scope admission at its caller. Its
accepting repository transaction locks the admitted actor by identity and checks
the current active administrator role and positive level once, before effects,
holding that row until ACK. Actor home tenant is recorded separately from the
affected tenant; the current-role gate does not create a new cross-tenant
permission rule or require home/target equality. Missing or stale administrator
state returns unavailable without revocation counts, effects or a fresh outcome.
