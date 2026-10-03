# Client-attestation PoP replay boundary

The supported OpenID4VC profile pins attestation-based client authentication to
draft-07. The application verifies the attester JWT, the instance-key signature,
issuer, audience, integer `iat` and bounded nonempty `jti` before carrying a typed
`ClientAttestationProofWindow` to the authorization state port. The core owns the
policy: `iat - 60 <= now < iat + 301`. This retains the inclusive age-300 second
and the permitted 60 seconds of future tolerance. Checked arithmetic rejects
unrepresentable bounds.

Both `/token` and `/par` call `consume_client_attestation_proof` with the verified
client ID, JTI and absolute window. The Valkey adapter reads its own `TIME`,
checks that interval, and performs `SET NX EXAT` in one Lua invocation. An
application node's clock cannot shorten the replay marker's deadline. Once the
owner reaches the exclusive expiry, the same proof cannot reinsert a marker,
even if another application node still accepts it locally. Token and PAR share
the same tenant/state-epoch-scoped production key; its spelling remains
compatible with the earlier client-attestation replay namespace.

A rejected interval or existing JTI is invalid client attestation. An unavailable
or unknown consumption result produces `503 server_error` before token or PAR
publication. The application does not authenticate on an unknown ACK or delete
a marker to retry. A real NX that committed before an ACK was lost remains a
replay when the same proof is subsequently presented to either endpoint.

## Clock, failover and upgrade requirements

The replay owner is the acceptance authority for this proof window. Application
clock synchronization still matters for preliminary JWT validation and
availability. The owner clock must progress consistently across failover, and
acknowledged, unexpired markers must survive eviction, failover and recovery.
The atomic script does not provide a durable fence outside Valkey, prevent a
backward owner-clock jump, or restore a lost marker.

Do not overlap old node-local-TTL consumers with these absolute-window
consumers. An old consumer can write a marker that expires too early, despite
using the same key. Quiesce token/PAR ingress, stop old consumers, and drain
their in-flight requests before enabling the new implementation. Keep ingress
closed until previously accepted proofs are outside the new owner's window,
using a verified upper bound on every old validating-node clock and on the last
possible acceptance. With such a bound `T`, `T + 361` is the exclusive upper
deadline for an old proof accepted no later than `T`; reopen only when the new
owner has reached that deadline and its clock continuity is established.

If that bound or the old acceptance history is unavailable, a fixed wait is
insufficient: use an operator-owned trust/credential invalidation boundary
before reopening ingress. A state-epoch change alone does not invalidate the
externally signed attestation PoP and must not be described as replay recovery.
The same security cutover is required after marker loss or uncertain failover.
These are deployment obligations, not operations automatically performed by
the application. See [HA operations](../operations/ha-operations.md).

## Regression evidence

Core and signed-validator fixtures cover future tolerance, inclusive expiry,
one-second node-clock disagreement and checked bounds. Real-Valkey fixtures
check token/PAR consumers racing on one marker and refusal to reinsert after
actual owner-clock expiry. The host fixture combines the same real signed proof,
validator and Valkey owner with a slow validating-node clock after marker expiry.

The host token/PAR fixture also hides the first successful real NX ACK at the
semantic port and verifies `503`, the retained physical marker, and cross-endpoint
replay rejection. This injection proves application behavior after a real state
effect; it is not driver packet-loss, replication-loss or failover evidence.
Fixture definitions require execution at the exact candidate SHA before being
counted as passing evidence.
