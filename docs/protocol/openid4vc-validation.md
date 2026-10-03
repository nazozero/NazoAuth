# OpenID4VC validation boundaries

The issuer uses [OpenID4VCI 1.0 Final Appendices D and F](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-proof-types).
JWT proofs require a scalar Credential Issuer audience. The credential
authorization retains explicit registered-client, anonymous pre-authorized or
legacy-unspecified proof provenance. A registered client may omit `iss`; if
present, it must be a string matching that client. Anonymous and legacy-unspecified
proofs omit `iss`. A placeholder client identifier is not provenance evidence,
including when a real registered client happens to use that same identifier.
Anonymous attestations use the issuer's global attestation trust, not a policy
accidentally attached to a registered client with the placeholder name.

The additive proof-origin migration preserves old rows as legacy-unspecified.
Their callers omit the optional issuer claim or restart issuance with a new
token. An epoch-less token without a retained live credential authorization is
rejected instead of guessing its origin. Epoch-bound ordinary access tokens can
establish their registered-client projection; pre-authorized issuance persists
the verified origin before returning the token. Projection refreshes preserve
that immutable origin. Drain old VCI consumers during the rollout; an old binary
does not acquire these validation guarantees merely by sharing the new schema.
The guarded down migration refuses to lose retained anonymous provenance.

An embedded key attestation must attest the actual JWT signing key even when
attestation is optional. Its algorithm must be in the selected configuration's
advertised list. This issuer advertises a Nonce Endpoint, so standalone and
embedded attestations both carry the issued nonce. Embedded attestations also
require expiration. Standalone `attestation` contains exactly one JWT; multiple
keys inside that JWT still produce a bounded credential batch.

Configuration identifiers and credential identifiers are separate selectors.
A credential identifier must exactly match an authorized identifier and map
to its authorized configuration. A scope-granted configuration cannot be used
as a credential identifier. The deferred wire request ignores unknown
extensions; known fields keep their type checks and management commands keep
their strict input contracts.

Immediate and deferred response status is selected from the issuance outcome
before encryption, persisted with the wire body, and restored on replay.
Encrypted initial deferred responses therefore retain HTTP 202. An unsupported
stored status fails closed with a server error. Historical encrypted deferred
records incorrectly stored as HTTP 200 cannot be repaired by inspecting opaque
ciphertext; their existing status is preserved and this fix applies to newly
recorded outcomes.

The presentation verifier classifies completion-store errors as HTTP 503;
invalid presentation/state responses retain HTTP 400. The current verifier
profile requires cryptographic holder binding and rejects DCQL requests that
explicitly waive it. Supporting that waiver requires a dedicated credential
verification profile; ordinary holder-signature verification remains required.

## Evidence and remaining work

Signed proof regressions use actual ES256 signatures and trusted attestation
keys. Encryption regressions encrypt and decrypt real compact JWE, retain
the status through storage/replay helpers, and assert the HTTP presenter uses
the semantic status for both encodings. The live deferred fixture also replays
the initial encrypted response through PostgreSQL. The completion-failure
fixture is a semantic store-port injection, not a PostgreSQL driver fault.
These source tests require designated CNB execution at an exact SHA before
acceptance. No conformance/certification or failover result follows from source
inspection alone.

Stable authorization identity across
refresh, authenticated certificate AKI matching,
individual invalid-presentation filtering and DCQL extensions remain separate
open findings. They are not closed by these wire/proof changes.

Credential and deferred requests that select response encryption must themselves
use the issuer's advertised request encryption. Plain requests with that parameter
are rejected before nonce consumption or deferred claim; a real JWE live regression
uses the advertised issuer request key, gets HTTP-202 semantics, and replays the
same persisted encrypted outcome. This check closes the previously permissive
wire contract rather than treating a plaintext encrypted-response request as a
Final-conformant happy path.

Profile validation also runs on retained create replay, request-object retrieval
and response transactions. An unexpired pre-upgrade transaction that explicitly
waives holder binding is rejected instead of republishing an unsupported request
object; it remains subject to the existing short TTL. Callers start a new supported
request. The live fixture commits/publishes a supported request, confirms that a
new waiver is not stored, and uses the real signing/store owners to inject an old
unsupported transaction whose GET, replay and response are rejected.

Proof-origin fixtures sign the whole outer proof (including a valid EdDSA outer
with an ES256 embedded attestation), distinguish anonymous grants from registered
clients sharing the placeholder name, and preserve immutable provenance through
the real PostgreSQL projection. The migration fixture copies the deployed table
inside a rollback-owned schema, applies the actual up/down SQL and verifies legacy
classification plus the anonymous downgrade guard. The expiration regression
supplies the correct nonce and omits only the embedded expiration claim.

The notification store accepts identical event/description retries for the same
live authorization and handle, including simultaneous requests, while retaining
the first occurrence time. A changed event or description, wrong authorization or
expired handle is rejected. The single atomic PostgreSQL update owns this decision;
retry success does not publish a second terminal outcome. Real PostgreSQL fixtures
cover concurrent duplicates and unchanged stored data; the live deferred endpoint
fixture retries the notification and rejects a conflicting terminal event.

Deferred claim classification is owned by one atomic PostgreSQL statement that
locks the same live transaction and authorization. Claimed alone confers signing
authority. Pending and Busy return HTTP202 with the original transaction identifier
and a positive retry interval, honoring each poll's response encryption parameters;
invalid/consumed/expired/wrong-owner transactions retain the protocol error. Waiting
polls are not cached as final issuance outcomes. Real PostgreSQL fixtures preserve
the active lease on Busy/wrong-owner attempts. The live fixture exercises encrypted
Pending, plain Busy, the same poll after readiness and final exact response replay.
Its controlled readiness/lease fields affect only fixture-owned rows.
