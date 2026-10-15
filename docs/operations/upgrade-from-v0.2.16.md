# Upgrade from v0.2.16

## Federated MFA session cutover

Deployments upgrading from a runtime that admitted federated logins without local
MFA must invalidate the affected pre-upgrade sessions. The new callback fixes new
sessions; stored `pending_mfa=false` records do not record whether local MFA was
incorrectly skipped. Without independent evidence identifying affected sessions,
invalidate all browser sessions for that deployment at the coordinated cutover.

Stop all old session writers, upgrade every serving node, and remove only the
browser-session keys under the deployment's existing
`nazo:state:v1:<deployment>:<epoch>:oauth:session:*` namespace before resuming traffic.
Use bounded `SCAN`/`UNLINK` batches with the exact configured namespace. Preserve
DPoP/client-assertion replay markers and the rest of transient state; do not flush
Valkey or rotate its entire state epoch for this session-only repair. Users sign
in again through the corrected MFA flow. This is an operator cutover, not an
additional authentication check on every request.

For the introspection permission cutover, follow the
[client policy upgrade order](../protocol/composable-capability-policy.md): all
readers must understand the new field before non-empty grants are stored.

## Schema cutover

Validate the complete migration chain against an isolated restore of the
current database before stopping the deployed writer. Fresh-database tests
cannot establish compatibility with an already-applied historical migration.
Keep a tested backup; the terminal receipt schema cutover requires restoring
that backup for downgrade rather than inventing discarded request metadata.

The released issuance schema is converted by
`20260913000000_released_issuance_cutover`, positioned after the last released
migration and before the first unreleased consumers of the compact schema.
Already compact schemas remain unchanged, including the later boolean cleanup
entry point. Issuance ids, tenant/client/user ownership, access-token ids and
expiry, and the bytes of every existing grant digest are retained. The new
retention deadline is the maximum of the original receipt deadline and the
access-token acceptance deadline. Existing receipts retain their legacy
contract version; conversion does not manufacture authorization-code holder
proof or mark them as new-contract receipts.

A legacy row without terminal access-token ownership/replay evidence fails
closed without changing its data. All live legacy receipts, including ordinary rows without ciphertext, must finish
their existing receipt window before conversion. Released rows do not record a
verified refresh-family identity, so accepting a live row would lose complete
post-upgrade replay revocation. Stop the old issuer and wait until the maximum
original `expires_at` has passed; this can include the original refresh-token
lifetime, not merely the authorization-code lifetime. Do not infer a family from
client/user identity or ciphertext absence; do not delete or shorten that
window to make upgrade pass. Already-applied cutovers do not replay this guard;
the original pre-upgrade snapshot is needed to assess such installations. Expired response bodies and superseded request/
response metadata are removed only by the guarded schema cutover. The cleanup
function replacement preserves its owner, EXECUTE grants, and grant options. If a prior failed upgrade already retired `oauth_tokens`,
conversion does not recreate that table or its obsolete index.

Stop the retired audit exporter before the batch protocol cutover. Its chained
pending events retain their facts without an invented batch lease. The first
normal claim enforces both configured count and wire-byte bounds; the remaining
events stay pending for subsequent delivery. Existing batch-protocol leases retain their
committed membership and digest. No pending audit event is acknowledged or
deleted by this conversion. See [audit anchoring](../security/audit-anchor.md).

Cached builds depend on the existing complete migration checksum manifest.
This covers new migration directories at any position, not only a changed
latest-version marker. Migration checksum changes must be reviewed explicitly.

## Receiver-owned audit confirmation

The receiver-authority migration is a coordinated cutover: stop Required
admission and old audit workers before applying
`20261011000100_receiver_owned_audit_ack`. Preserve the independent receiver
journal and existing pending batches. The migration revokes non-owner ACK/genesis
grants; provision a separately protected receiver login after migration, configure
its database connection and TLS, and upgrade receiver and worker together.
Verify receipt signature and committed checkpoint before restoring Required
traffic. Never grant receiver authority to the application/exporter, directly or
through an assumable role. Follow the
[role provisioning instructions](security-audit-ledger-roles.md) and
[audit protocol](../security/audit-anchor.md).

The historical tenant-scope migration now preserves explicit global module
policy when it first runs. An already-recorded migration does not replay. For
already-upgraded installations compare pre-upgrade policy and subsequent admin
events before reconciling current per-tenant settings. Do not infer historic
intent from defaults or automatically overwrite current policy.
