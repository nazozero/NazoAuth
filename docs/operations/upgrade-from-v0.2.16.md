# Upgrade from v0.2.16

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
closed without changing its data. Live encrypted legacy responses must finish
their existing receipt window before conversion; do not delete or shorten that
window to make upgrade pass. Expired response bodies and superseded request/
response metadata are removed only by the guarded schema cutover. The cleanup
function replacement preserves its owner, EXECUTE grants, and grant options. If a prior failed upgrade already retired `oauth_tokens`,
conversion does not recreate that table or its obsolete index.

Stop the retired audit exporter before the batch protocol cutover. Its first
bounded pending prefix becomes the initial batch; later chained events remain
pending for subsequent delivery. Existing batch-protocol leases retain their
committed membership and digest. No pending audit event is acknowledged or
deleted by this conversion. See [audit anchoring](../security/audit-anchor.md).

Cached builds depend on the existing complete migration checksum manifest.
This covers new migration directories at any position, not only a changed
latest-version marker. Migration checksum changes must be reviewed explicitly.
