# External audit-ledger anchoring

Committed security events enter the append-only `security_audit_events`
ledger and its durable outbox. Application emission is not always synchronous;
see [Security Events](security-events.md) for queue loss, required append, and
transactional producer boundaries. An independent `nazoauth audit-anchor-worker`
(or equivalent sidecar) claims that outbox in bounded batches and sends one
signed batch checkpoint per claim to `AUDIT_ANCHOR_URL` over HTTPS. The
exporter assigns sequence and BLAKE3 hashes to committed events in immutable
`security_audit_chain_entries`, atomically with its bounded batch claim (at
most 256 events and at most `AUDIT_ANCHOR_MAX_ENVELOPE_BYTES` wire bytes). A
business transaction writes the event and outbox without locking the global
chain head. Retries reuse the identical committed batch: the chain-state row
pins the sequence range, member content digest, generation, and lease. The
server process does not run this exporter and does not receive its database
role or sink secret.

The hash chain and its sequence belong to the deployment. HTTP security events
capture `payload.tenant_id` from the same immutable tenant context that routes
the request, before the event enters the shared writer queue. Concurrent
requests cannot exchange this context, and a conflicting tenant field is
rejected. Tenant-resource management events bind their tenant in the signed
operation and database transaction. Deployment events outside a tenant request
do not inherit the last request's identity.

Each request contains the checkpoint schema `nazo.audit.anchor.v2` and, for
`checkpoint_kind` of `batch`, these fields:

* `deployment_id`, `first_sequence`, `last_sequence`, `event_count`;
* `previous_hash` (the chain hash before the batch), `last_hash`, and
  `batch_digest` over the deployment, range, hashes, and every member event
  hash;
* `events`: an ordered array of `event_id`, `sequence`, `previous_hash`,
  `event_hash`, `event_type`, `event_category`, `payload_canonical`, and
  `occurred_at`.

The signed body is immutable for a claimed batch. The delivery timestamp is
carried separately in `X-Nazo-Audit-Sent-At`, so retries reuse the same body,
signature, and `Idempotency-Key` (`batch:<deployment>:<first>:<last>:<digest>`).
The empty ledger uses a stable `genesis:<deployment_id>:<hash>` idempotency
key and an explicit `checkpoint_kind` of `genesis`.

The receiver must recompute every BLAKE3 event hash and the batch digest
before accepting a checkpoint. The event hash input is `nazo.audit.v1\0`,
big-endian sequence, previous hash, UUID bytes, length-prefixed UTF-8 event
type and category, big-endian microsecond timestamp, and length-prefixed
PostgreSQL `jsonb::text` payload. Sequence and timestamp are signed 64-bit
integers; lengths are unsigned 64-bit byte counts, all big-endian. The batch
digest input is `nazo.audit.batch.v1\0`, deployment id, first and last
sequence, event count, previous hash, last hash, and each member event hash in
order. Hashes are 32 raw bytes and the event UUID is 16 raw bytes. The JSON
wire envelope encodes hashes as unpadded base64url. A receiver must reproduce
PostgreSQL `jsonb::text` representation, including whitespace and key
ordering; hashing arbitrary reserialized JSON is not equivalent. The
[persistence crate](../../crates/persistence/src/audit_chain.rs) owns this
encoding. The receiver independently validates deployment identity, sequence
continuity, previous hash, event content, batch digest, and duplicate
consistency.

The worker authenticates the exact JSON body with HMAC-SHA-256 in
`X-Nazo-Audit-Signature: sha256=<base64url>` (unpadded). The separate
`X-Nazo-Audit-Sent-At` header is not covered by this MAC. A bare HTTP success
never acknowledges a batch: only a signed `nazo.audit.anchor.receipt.v1` body
that verifies under `AUDIT_ANCHOR_RECEIPT_VERIFY_KEY` (Ed25519) and binds the
same schema, checkpoint kind, deployment, sequence range, event count, last
hash, and batch digest does so. Receipt status `accepted` records durable
acceptance; `duplicate` acknowledges an already-persisted identical batch; a
`rejected` receipt with `permanent=true` blocks the batch until an operator
runs `nazo_unblock_security_audit_batch()`, while a transient rejection or any
missing/invalid receipt reschedules it. Acknowledgement deletes the batch's
delivery rows in the same transaction that advances the anchor checkpoint —
the accepted checkpoint and the immutable event/chain records are the durable
evidence, so no delivered row is retained and no separate sweeper reclaims it.
Transport and transient failures are rescheduled with bounded backoff. Claim,
acknowledgement, and failure release are fenced by the batch generation, so an
expired or stale worker cannot mutate a newer claim. The response body is
never logged, and neither secret is ever included in logs or the checkpoint.

Request authentication is a shared secret, but acknowledgement is
non-repudiable: the receipt is an Ed25519 signature over the canonical receipt
fields, so the worker holds durable proof that this receiver persisted the
exact batch before acknowledgement. An idempotent receiver must persist before
returning `accepted` and must return `duplicate` for a replayed identical
batch rather than an ambiguous conflict. Empty-ledger genesis uses the nil
UUID, sequence zero, identical previous/event hashes, and Unix epoch time; it
is a checkpoint, not a fabricated security event.

The worker records its observation and every externally accepted checkpoint in the shared audit chain state. Event acknowledgement and checkpoint advancement are one database operation. In `AUDIT_ANCHOR_MODE=required`, high-impact management preflight requires a recent worker observation, a valid deployment checkpoint, and oldest pending event age within `AUDIT_ANCHOR_MAX_LAG_SECONDS`. A bounded backlog is allowed, including committed events not yet chained. With no backlog the checkpoint must equal the chain head; historical delivery latency does not keep a recovered deployment unavailable. An empty ledger records its signed, externally accepted genesis checkpoint before required mode becomes ready. No instance-local health file is used.
`optional` and `disabled` do not read exporter health on management admission;
the durable writer availability check still applies. `disabled` is an explicit
development setting and provides no protection against a privileged local
attacker.

Delivery is deliberately strict and ordered: a permanently rejected batch is
parked with `batch_blocked_reason` and blocks all later batches until an
operator reconciles the receiver contract and runs
`nazo_unblock_security_audit_batch()`. Operators must alert on `audit.anchor`
retries and on a non-empty blocked reason. There is no skip/DLQ operation
because skipping would make a later external chain look complete when it is
not.

Recommended production separation:

* pre-create distinct lifecycle, server-writer, and exporter database roles;
* for a source-managed deployment, run `nazoauth migrate` with the lifecycle database URL and
  `NAZOAUTH_MIGRATION_RUNTIME_ROLE` naming the server-writer role; migration
  resets that role's direct `public` schema/table/sequence privileges, grants
  application DML, and grants only ledger append/check-availability functions;
* give the worker exporter role only chain assignment and outbox claim/ack/health rights;
* provide the worker `AUDIT_ANCHOR_DATABASE_URL` and `AUDIT_ANCHOR_TOKEN` (or
  its secret-file form), while the server receives only the deployment identity;
* use the [ledger role provisioning runbook](../operations/security-audit-ledger-roles.md)
  for grants and the managed operator-task migration boundary;
* protect the HTTPS receiver with append-only/WORM retention and verify its
  idempotency behavior independently.

This repository contains the worker protocol and shared database preflight logic;
it does not prove a deployed receiver's WORM guarantees, cross-host
availability, or real external acceptance.  Those require a deployment-level
probe and an independent receiver audit.

Database provisioning remains responsible for database `CONNECT`, removal of
`PUBLIC` schema `CREATE` and database temporary-table rights, and the exporter
function grants. Those are database-wide trust decisions and are not silently
changed by an application migration.

## Configuration

The [configuration loader](../../crates/nazoauth/src/adapters/audit_anchor/config.rs)
is the authority for accepted values. Secret-file forms follow the normal
[configuration precedence](../operations/configuration.md).

| Setting | Default / requirement |
| --- | --- |
| `AUDIT_ANCHOR_MODE` | `disabled`; worker requires `optional` or `required`. |
| `DEPLOYMENT_ID` | Required in enabled modes; 1–255 ASCII letters, digits, `.`, `-`, or `_`. |
| `AUDIT_ANCHOR_FRESHNESS_SECONDS` | 120; positive in enabled modes. |
| `AUDIT_ANCHOR_MAX_LAG_SECONDS` | 300; positive in enabled modes. |
| `AUDIT_ANCHOR_URL` | Worker-only HTTPS URL without credentials, query, or fragment; redirects are disabled. |
| `AUDIT_ANCHOR_TOKEN` | Worker-only HMAC secret, at least 16 bytes. |
| `AUDIT_ANCHOR_RECEIPT_VERIFY_KEY` | Worker-only Ed25519 public key (base64url or hex, 32 bytes) that verifies receiver receipts. |
| `AUDIT_ANCHOR_CA_BUNDLE` | Optional worker-only PEM bundle path pinning the receiver certificate chain. |
| `AUDIT_ANCHOR_DATABASE_URL` | Worker-only exporter-role database URL. |
| `AUDIT_ANCHOR_DATABASE_MAX_CONNECTIONS` | 4; positive. |
| `AUDIT_ANCHOR_POLL_INTERVAL_SECONDS` | 5; positive. |
| `AUDIT_ANCHOR_REQUEST_TIMEOUT_SECONDS` | 10; positive. |
| `AUDIT_ANCHOR_BATCH_SIZE` | 64; range 1–256 events per batch. |
| `AUDIT_ANCHOR_MAX_ENVELOPE_BYTES` | 1048576; range 131072–1048576 wire bytes per batch envelope. |
| `AUDIT_ANCHOR_LOCK_TIMEOUT_SECONDS` | 60; range 1–3600 batch lease. |

The server receives the preflight settings and deployment identity, never the
worker database URL or sink token. Required mode rejects stale/future worker
observations, a mismatched deployment, invalid checkpoints, or excessive oldest
pending age. It gates callers of management preflight; it is not a promise that
every HTTP response waits for its own external checkpoint.

After database restore, reconcile the local chain and outbox with the receiver's
already accepted deployment sequence before resuming export. Do not erase the
receiver's history or reset deployment identity merely to make a fork appear
continuous. Database ownership can rewrite unanchored local state; only
independently protected receiver history survives that boundary.
