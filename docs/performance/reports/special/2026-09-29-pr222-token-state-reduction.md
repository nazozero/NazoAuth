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
