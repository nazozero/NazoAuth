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

The stable authorization implementation below and the DCQL changes have new
source regressions and require exact-candidate CNB validation. DCQL `aki` compares
decoded KeyIdentifier bytes from the authenticated credential issuer chain, never
the issuer URL/thumbprint, a holder chain or separately loaded anchors. Issuer
trust, revocation and format signatures still run in their original verifier;
metadata projection performs no second signature verification. Missing AKI
metadata, including retained legacy results, does not satisfy an AKI condition.

Individual invalid credentials or query mismatches are discarded before required
credential-set alternatives are evaluated. Every supplied presentation is still
verified even after a required alternative succeeds. An authenticated wrong or
missing SD-JWT holder nonce rejects the whole response. mdoc binds the transaction
inside its signed SessionTranscript: a failed current-session device proof is
also a whole-response failure because it cannot safely establish a nonce match.
Verifier/revocation dependency unavailability remains HTTP 503 and is not filtered
as an invalid credential. DCQL ignores unknown extension properties at every
object level while retaining known-field types and declared-reference checks.

Signed SD-JWT/mdoc fixtures cover issuer AKI projection; service-port fixtures
cover DCQL selection, discard and error disposition. These are distinct evidence
boundaries and no current execution pass is claimed.

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
expired handle is rejected. The PostgreSQL transaction validates the current grant and owns this decision;
retry success does not publish a second terminal outcome. Real PostgreSQL fixtures
cover concurrent duplicates and unchanged stored data; the live deferred endpoint
fixture retries the notification and rejects a conflicting terminal event.

Deferred claim classification is owned by one PostgreSQL transaction that locks
the live current grant and the same retained deferred intent. Claimed alone confers signing
authority. Pending and Busy return HTTP202 with the original transaction identifier
and a positive retry interval, honoring each poll's response encryption parameters;
invalid/consumed/expired/wrong-owner transactions retain the protocol error. Waiting
polls are not cached as final issuance outcomes. Real PostgreSQL fixtures preserve
the active lease on Busy/wrong-owner attempts. The live fixture exercises encrypted
Pending, plain Busy, the same poll after readiness and final exact response replay.
Its controlled readiness/lease fields affect only fixture-owned rows.


## Authorization continuity across refresh

New access tokens carry an issuer-owned `authorization_id`. A checked refresh
source retains its opaque refresh-family ID, including PreserveExisting when no
new refresh token is returned. A new grant chooses its family or independent
issuance UUID before signing the access token. Equal grant contents and refresh
contract hashes never identify the same authorization. Fresh token exchange and
anonymous pre-authorized grants choose independent roots.

Storage retains every access-token row, immutable authorization/proof provenance
and the signed sender binding. Deferred intents, exact response records and
notification handles retain the original configuration and optional exact
credential identifier. The current token must still pass signature, issuer,
audience, epoch, revocation, subject/client, scope and sender checks. Its live
projection must match the original authorization, tenant, subject, client and
sender, and still authorize that exact selector. Removing one identifier while
retaining its configuration does not authorize the original intent.

The deferred source token foreign key and encrypted payload identity remain
unchanged. Original dataset, holder bindings, credential timestamps and status
remain frozen. A new intent's deadline follows its credential business deadline,
so the original AT's expiry alone does not destroy it. The current AT must be
live; the borrowed family ID does not make family expiry/revocation an additional
AT validity rule. The lease records its exact current claimant token so a
different AT cannot finalize or release that in-flight signing attempt.

NULL lineage or missing retained selector evidence preserves exact original
token ownership and conservative legacy deadlines. Migration does not guess
identity from client, subject, authorization details or contract digest, and does
not rewrite old ciphertext. Drain old VCI consumers when enabling continuity;
sharing the additive schema does not grant an old binary this behavior.

The new host regression uses production mint and checked refresh services,
verifies their real signed JWTs against the stored family, separates two equal
fresh grants and covers an independent NoRefresh root. The existing concurrent
PreserveExisting case checks the signed reference without a new RT. The new real
PostgreSQL regression covers expired source ATs, wrong authorization, narrowed
configuration/identifier, sender mismatch, expired/revoked current ATs, exact
lease ownership, response and notification continuity, and conservative legacy
rows. These are source additions awaiting designated execution at an exact
candidate SHA; no current acceptance or performance result is claimed here.

Management dataset writes return their own committed view after the encrypted
mutation, its audit event, the complete result stream and transaction commit
acknowledgement. The claims value moves through the write owner; PUT does not
fetch and decrypt a second post-write view. Its returned `updated_at` comes from
the database mutation. A later update does not replace that response snapshot.
Current actor and subject gates stay in the write statement. The subject
precheck stays until rejection distinguishes subject, actor and source failures.
PostgreSQL regression assertions for the committed view are source additions;
their current-candidate execution remains pending.


### Independent V02/V03/V04 source corrections

Pre-authorized credential access persists the same verified mTLS certificate
fingerprint that is signed into its access token. A matching certificate must
pass the strict signed/retained sender comparison; an absent or different
certificate still fails with invalid_token. No null provenance fallback is added.

The existing SD-JWT and mdoc chain owners reject a presented configured anchor
unless it is the authenticated terminal certificate in that presented path.
Unused global or scoped anchors cannot contribute AKI or revocation facts.
Loaded anchors are not appended to trusted-authority projections, and no second
credential signature verification is introduced.

After issuer/path admission and issuer/holder signature verification, SD-JWT
checks the authenticated holder nonce before a discardable certificate
revocation disposition. A revoked optional credential remains excluded; its
signed wrong nonce still rejects the whole response. Missing or stale shared
revocation snapshots take the verifier dependency path (503), while known
revoked/unknown individual certificate status retains its policy disposition.

Signed service regressions and a live PostgreSQL/Valkey pre-authorized sender
regression are supplied in source. Formatting, compilation, and execution of
the integrated candidate remain pending; no dynamic or physical fault evidence
is claimed by these source corrections.


### DCQL known-shape admission

The existing DCQL validator rejects an explicitly empty credential_sets array,
missing/non-object meta, and malformed supplied vct_values/doctype_value
constraints. vct_values must be a non-empty array of non-empty strings;
doctype_value must be a non-empty string. Unknown properties remain ignored.
The retained request completion path invokes this same validation owner before
verifying any credentials or persisting a result, so historical malformed
queries cannot be accepted as unconstrained or as zero-evidence completions.

The existing empty-meta profile is retained as an explicit unconstrained
profile; this correction does not claim to implement every format-specific
mandatory type-identifier rule, ID charset, duplicate claim-path, claims.values,
or trusted-authorities cardinality requirement. See OpenID4VP 1.0 sections 6,
6.1 and appendices B.2.3/B.3.5 for the separate conformance boundaries.
Typed create, domain validation, and retained-service prevention regressions
are source only until the new isolated candidate is compiled and executed.


### Presentation completion deadline acceptance

Presentation completion is accepted at the owning database mutation predicate,
after acquiring its transaction record lock. PostgreSQL checks clock_timestamp()
at that point in addition to the caller's reported verification-time bound; a
pre-verification, transaction-start, or statement-start clock cannot extend the
transaction lifetime through pool/record waits. The same transaction retains
tenant/state/one-winner/current trust-policy predicates, persists the protected
result and erases the response key. It returns success only after commit ACK,
with the existing DiscardOnDrop guard armed on cancellation or incomplete ACK.

The reported result timestamp and existing response wire format are preserved.
This is a locked logical mutation acceptance deadline, not a promise that a
network commit ACK reaches the caller before expiry. No extra deadline check is
added at each await. Real PostgreSQL source regressions cover old caller time,
pool acquisition wait, an unchanged locked row crossing its deadline, response
key/result preservation, and one-winner success; they remain unexecuted here.
