# Token state reduction

The accepted capacity results remain pinned to their original source. This
follow-up changes the representation of security state; no throughput or WAL
improvement is claimed before a focused measurement.

The target is to remove per-token ownership writes from Fresh issuance.
Principal-wide invalidation is represented by a monotonic epoch on the client
and user. Non-public subject ownership is a reusable identity binding; public
subjects require no binding. SingleUse receipts, individual revocations,
refresh-family state and Required audit retain their own responsibilities.

The preparatory migration adds the two epochs and subject bindings. A shared
trigger advances the corresponding epoch on active-to-inactive transitions,
including SCIM and operator writers. Reactivation never resets it. Existing
issuance records are not deleted and existing token verification is unchanged
at this checkpoint. The subsequent application change must check signed epochs
at every online validation boundary and recheck them under principal locks at
issuance commit. No timestamp comparison substitutes for that ordering.

Bindings preserve existing pairwise subjects and internal-user confidentiality.
They are tenant scoped, immutable in ownership, and removed with their user.
The migration refuses downgrade because removing epochs or bindings after new
tokens have been issued could resurrect or strand live tokens.

## Application implementation

Fresh no longer inserts an issuance row, and its rotation-conflict path no
longer deletes a row it never created. SingleUse inserts an epoch-bound replay
receipt with no user ownership column. The receipt remains transactionally
coupled to refresh state and audit. Migration 20260929000300 distinguishes these
receipts from legacy per-token records during their remaining retention window.

Generic signing carries client/user epochs read from a narrow principal
snapshot. The existing client-then-user FOR SHARE checks compare both activity
and epochs before any commit-owned mutation. Signing stays outside the database
transaction. Each online validation surface (UserInfo, introspection, token
exchange, credential endpoints and the protected-resource service) passes
verified token context to the combined individual/principal revocation query.
Epoch-less pre-upgrade and separately owned VCI tokens retain their prior
revocation path. The standalone signature verifier remains an offline verifier.

A stable binding is inserted only when the snapshot found it missing. Concurrent
first issuances use the unique tenant/subject key and recheck the winning owner;
a different owner aborts the transaction. Repeated private-subject issuance does
not update that binding. Public subjects never create one.

The normal flow replaces a per-token INSERT with a narrow read before signing;
it does not claim a round-trip reduction for the entire request. Ordinary
public-subject refresh commit itself has 10 data statements instead of 11.
Required audit, refresh-family changes, individual revocations and SingleUse
receipts still generate legitimate database writes. No capacity/P99 or WAL-byte
improvement has been measured for this source yet.

Regression coverage checks no Fresh ownership rows, exactly one Required audit,
one reusable pairwise binding, tenant isolation, stale snapshots across
reactivation, old-token invalidation without per-JTI expansion, and the existing
concurrent issuance/deactivation and single-use rollback cases.

The Required token-issued audit event reuses the issuance operation UUID. Its
existing pending event key rejects a duplicate while present, without adding
another receipt or index for Fresh. After audit delivery the pending key is
reclaimed; it is not a permanent issuance-id fence or response replay contract.

Deployment is a coordinated upgrade of every online validator before reopening
issuance; old binaries do not enforce principal epochs. Mixed old/new serving
and rollback after new issuance are unsupported. See the HA operations guide.
The additive database columns are read through narrow SQL; the existing
64-column Diesel client projection is intentionally unchanged.

Local verification: workspace/all-targets/all-features type checking and Clippy,
formatting, static contracts and persistence dependency checks. Database-backed
regressions still require the PR CI PostgreSQL fixture; no missing local database
run is counted as a test pass. Accepted capacity data is unchanged.

## Audit claim follow-up

Static review of the stalled scale regression exposed a second unnecessary
read: selecting at most 256 event IDs and then joining the event table again
does not bound the join's index work. Migration 20260929000400 reads unchained
events directly through the pending-order index. Chained leftovers retain
sequence priority and use bounded, parameterized primary-key lookups. The
function's bounds, privileges, batch fencing and acknowledgement are unchanged.

The existing 0/10k/1M/15M-row regressions remain. Their EXPLAIN ANALYZE and real
claim statements now enforce the existing 30-second budget in PostgreSQL, so
an excessive execution fails instead of waiting until the entire CI job times
out. Plan assertions also count actual index rows across loops, rather than
accepting every plan merely because it avoids a sequential scan. The previous
CI logs ended after seeding the 15M fixture; those logs alone do not identify
the exact statement responsible for the job timeout. No capacity conclusion
is drawn from this regression fix.
