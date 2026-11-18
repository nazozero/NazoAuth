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

Pre-authorized token issuance first verifies the offer and transaction code without
consuming them. Subject lookup and signing happen before the final store call.
The adapter atomically consumes the unchanged, unexpired offer and persists the
access grant while fencing subject/client deactivation. A failed transaction leaves
both unchanged; concurrent redemption has one winner. An unknown commit outcome
is not treated as a rollback or permission to reopen a consumed code.

The public nonce route shares the configured authentication request budget and
trusted source-IP resolution. Budget rejection occurs before nonce persistence.

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

## mdoc signing time and certificate validity

Issuance uses shared day-rounded time claims to avoid publishing a precise
per-request timestamp. For mdoc, that rounded time must also be within the
selected document signer certificate's validity: a certificate activated during
the day cannot authenticate an MSO claiming to have been signed at midnight.
The signer bounds `signed` and `validFrom` below by that pinned certificate's
public `notBefore` value. This is one shared boundary for that certificate,
not a new clock reading for each holder or credential. Later rounded times
remain unchanged. `validUntil` is never extended; an empty validity interval
or a signing time after `notAfter` rejects issuance. The verifier's historical
certificate-time and signature checks remain unchanged.

Locally generated mdoc DS and IACA certificates start at the beginning of their
creation day in UTC. Their end dates use that same boundary (457 days for DS,
3650 days for IACA), so this does not extend certificate lifetimes or credential
expiry. A new signer therefore covers the day-rounded MSO time without exposing
its creation second. Key creation, publication, rotation, revocation and signing
lease ownership remain unchanged; certificate time rounding does not make a key
available before it exists.

Existing and imported certificates retain their signed validity fields. They are
not silently regenerated, backdated or accepted outside their validity. Their
first partial day can still require the exact public certificate lower bound;
the general signer-validity guard remains necessary. A deployment importing such
material must assess that shared cohort boundary or provision certificates whose
validity covers its privacy rounding interval. Assess credential linkability across all disclosed fields.

The real COSE/MSO regression exercises a rounded claim preceding a newly active
certificate, a claim already within its interval, deadline preservation and
rejection of impossible intervals. The managed-certificate regression checks
midnight, one second later, midday, the last second and the next day's boundary;
keyctl lifecycle tests retain generation reuse, concurrent initialization,
rotation, historical CRLs and import preservation. Store external conformance results with their tested version outside the source tree.

## mdoc protocol and trust responsibilities

`nazo-mdoc` owns the mdoc/CBOR/COSE boundary. Its presentation verifier returns
`PendingTrustDocumentRef` only after issuer signature, disclosed-item digests,
MSO validity and holder authentication succeed. The type is not a final trust
decision. NazoAuth completes its existing certificate path, revocation and MSO
status checks before `CredentialVerifierPort` returns `VerifiedCredential`.
Authenticated claims are projected from borrowed CBOR directly into the final
owned JSON result. Signed envelopes, item salts and MSO digest maps remain in
the decoded presentation buffer. Only the holder key and certificate chain
retained across the existing status-verification boundary are materialized.
There is no assessment override or second device-signature calculation.

| Responsibility | Authority | Regression contract |
| --- | --- | --- |
| Bounded CBOR, duplicate keys, exact received Tag24 envelopes, COSE headers and algorithm/key binding | `nazo-mdoc` parser and protocol verifier | Core raw-CBOR/COSE regression corpus; NazoAuth signed credential fixtures |
| Final Redirect Handover request context | `nazo-openid4vp::PresentationService` passes the retained full client ID, nonce, optional encryption-key thumbprint and response URI to the core constructor | `final_mdoc_handover_binds_verifier_key_and_request_context` checks the official vector and changed request fields |
| Actual response-encryption key | Presentation endpoint compares the advertised JWK public members with the key used for JWE decryption | `encrypted_response_key_matches_the_key_bound_by_the_handover` |
| Holder authentication and current-session failure | Core consumes the validated borrowed transcript and original namespace bytes; NazoAuth treats holder or unsupported document-count failures as whole-response rejection | `signed_mdoc_rejects_an_unmatched_current_session_without_nonce_claim_guessing` |
| One document per DeviceResponse | NazoAuth selects the HAIP `max_documents = 1` profile at the parsing boundary | Multi-document response cannot hide a session mismatch or be accepted as an optional credential |
| Issuer X.509 trust and time | Core checks MSO `signed` within the DS validity interval; NazoAuth's AWS-LC-backed path owner uses the same current time as MSO validity and certificate revocation | `mdoc_verification_rejects_expired_ds_even_when_mso_is_current`, certificate-path and historical whole-leap-second regressions |
| Document Signer certificate profile | Shared `nazo-digital-credentials::mdoc_certificate` checks additional Annex B fields at signing, verification and native material admission; the existing path engine and core retain their own checks | `mdoc_verification_requires_document_signer_profile`, `mdoc_issuance_rejects_invalid_ds_purpose_and_issuer_binding` and keyctl material regressions |
| IACA root profile | Signing and verification check the actual authenticated root through the same shared profile; material admission also checks self-signature, current time, tenant and publication address | `mdoc_issuance_and_verification_require_authenticated_iaca_profile`, `mdoc_verification_checks_root_profile_beyond_an_iaca_link`, `mdoc_import_binds_the_active_root_and_enforces_its_profile` |
| mDL issuer attributes | Disclosed `issuing_country` matches DS country; disclosed `issuing_jurisdiction` matches DS state when that state exists | `authenticated_mdl_disclosures_match_the_document_signer_country`, `mdl_jurisdiction_binds_only_when_the_document_signer_has_a_state` |
| Certificate revocation | Existing `CertificateRevocationPolicy` and authenticated path anchor | Missing/stale snapshots, known revocation and scoped-unknown status regressions |
| MSO status presence and mechanism policy | Core preserves the complete authenticated CBOR status; NazoAuth accepts only the exact supported `status_list` shape | Unsupported, tagged, duplicate or additional mechanisms fail closed; status presence is never inferred from a lossy JSON conversion |
| Credential status verification | Existing bounded HTTPS resolver and draft-21 JWT/CWT validator | Revoked, suspended, unknown, unreachable, wrong-signature and wrong-IACA regressions |
| External signing and certificate chain | Core prepare/finish plus one NazoAuth key-generation lease; the complete authenticated non-root chain is retained | `credential_execution_uses_completed_builder_and_pinned_lease_without_native_runtime` |
| mDL date and binary element encoding | NazoAuth applies ISO field types only to `org.iso.18013.5.1` within `org.iso.18013.5.1.mDL` | `mdoc_date_tags_are_scoped_to_the_iso_mdl_schema`, `mdoc_issuance_authenticates_explicit_date_tags_and_preserves_custom_values` and binary-element tests |

The issuer delegates digest-ID generation to the pinned `nazo-mdoc` builder,
which selects random identifiers below `2^31`. The core verifier enforces this
bound in every authenticated MSO digest map and disclosed item, as required by
[ISO/IEC 18013-5:2021 §9.1.2.4](https://law.resource.org/pub/us/cfr/ibr/inc/iec/iec.18013-5.2021.pdf).
NazoAuth does not generate a second set of IDs or relax the verifier's bound.
An already signed credential with an out-of-range ID requires new authorized
issuance: changing the identifier changes an item's digest and the signed MSO.
Omitting a disclosure does not remove its authenticated MSO digest entry.

The mDL JSON adapter encodes `birth_date` as Tag 1004; `issue_date` and
`expiry_date` accept either a full calendar date with Tag 1004 or a complete
UTC timestamp with Tag 0. `portrait_capture_date` requires Tag 0. Dates inside
`driving_privileges` require Tag 1004. Dates are validated before signing;
timestamps use whole seconds and the `Z` UTC suffix. This follows
[ISO/IEC 18013-5:2021 §§7.2.1 and 7.2.4](https://law.resource.org/pub/us/cfr/ibr/inc/iec/iec.18013-5.2021.pdf)
and [RFC 8943](https://www.rfc-editor.org/rfc/rfc8943.html).
Custom namespaces and document types retain their supplied JSON value types.
When projecting authenticated CBOR claims to JSON, the adapter accepts only
validated date tags 0 and 1004. Unknown tags, nested tags and malformed tagged
dates are rejected instead of losing their meaning during conversion. Other
CBOR extensions need an explicit application mapping before they can be used
as JSON claims.
The core keeps its own protocol `Timestamp` representation, including
authenticated whole-leap-second wire values. NazoAuth uses POSIX Jiff
`Timestamp` values and converts them only at the mdoc boundary. Conversion into
an application timestamp requires the protocol value's `unix_nanos()`; a value
without a POSIX representation is rejected as invalid validity. No signed
instant is rounded into a neighboring instant. Certificate-path validation
uses the current POSIX presentation time, independently of the MSO's historical
signing time. Fractional leap seconds are outside the supported time profile.
See [native Jiff time boundaries](../integration/jiff-migration.md).
Configuration owners remain responsible for complete credential schemas,
required elements and the authority to issue their claims.

The shared DS profile requires a positive nonzero serial of at most 20 octets,
an ECDSA certificate signature, a validity interval of at most 457 days, a
non-CA subject with CN and correctly encoded country, critical
`digitalSignature`-only KU and critical mDL DS EKU. It checks SHA-1-derived SKI,
AKI binding to the actual issuing CA, noncritical issuer contact and CRL URI
extensions, and the profile's prohibited extensions. Extra noncritical
extensions remain supported; unknown critical or duplicate extensions fail
closed. These checks do not establish serial-generation entropy or contact URI
reachability. The existing X.509 path engine checks version, matching signature
identifiers and exact issuer/subject names; the core checks SPKI encoding and
algorithm/key compatibility. There is no second path validator.

IACA roots used for issuance, verification or material admission share the
serial, name, identifier, contact and extension checks.
[ISO/IEC 18013-5:2021 Annex B.1.1 and B.1.2](https://law.resource.org/pub/us/cfr/ibr/inc/iec/iec.18013-5.2021.pdf)
apply the certificate profiles to readers and issuing infrastructures and
specify the IACA root profile. These field checks complement the existing
RFC 5280 path validation; they do not repeat it or establish trust. The root profile
additionally requires version 3, equal issuer/subject
DER names and signature identifiers, critical CA constraints with path length
zero, and critical KU containing only `keyCertSign` and `cRLSign`. Supported
root keys use uncompressed P-256/P-384/P-521 with named-curve parameters;
Brainpool is outside this implementation. Root validity is bounded to 20
calendar years, with February 29 clamped to the target month's last day.
Issuance uses the root selected by the captured signing lease's authenticated
path. Verification uses the root returned by the current presentation's path
validation, including for client-scoped trust. A different valid configured
root cannot satisfy this check. A missing root CRL distribution point or issuer
contact rejects issuance and verification, even when the DS signature and path
are otherwise valid. The common direct-issuer/root certificate is parsed once
for these profile and binding checks. The native material owner separately
authenticates the self-signature and binds the material to its tenant and actual
publication route. See
[managed mdoc state](../operations/mdoc-shared-state.md) for historical CRL
address retention and explicit rotation.

The issuer omits configured trust anchors from the emitted `x5chain` by exact
certificate identity. For interoperability, the receiving path owner still
accepts an otherwise valid chain that explicitly ends in its authenticated
configured anchor; that compatibility does not authorize using an IACA as the
Document Signer. Country and state comparisons use the actual authenticated
issuer, including an IACA link when present. Selective disclosure does not
require revealing country or jurisdiction. A DS without a state attribute may
sign a jurisdiction, as permitted by ISO 18013-5 §7.2.1.

The mdoc core also defines the separate Final DC API Handover. NazoAuth exposes
`direct_post` and `direct_post.jwt`; it does not advertise DC API, proximity
transport, wallet, DeviceMAC or transaction-data support. The redirect binding
follows [OpenID4VP 1.0 Final B.2.6.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#section-b.2.6.1).
The one-document constraint belongs to
[HAIP 1.0 Final 5.3.1](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html#section-5.3.1),
not to every possible ISO mdoc profile. Retained certification records describe
their tested implementation versions; they do not certify this dependency
migration or unsupported profiles.

## Regression coverage

SD-JWT VC issuance with no subject claims omits `_sd` and emits exactly one
trailing `~`, as required by SD-JWT VC draft-26 section 2.2.2.5. Holder
KB-JWT audiences must be a single string matching the transaction's audience
(RFC 9901 section 4.3); arrays, including single-element arrays, are rejected.

The credential verifier validates `aka_vcts` before returning a verified
credential: it must be a nonempty string array, with no empty string or primary
`vct` value. This applies even without a DCQL type constraint. DCQL only matches
the authenticated primary type and aliases; it does not repeat format validation.
The issuer rejects subject-claim names reserved for non-disclosable VC control
claims and SD-JWT encoding, rather than issuing a credential its verifier rejects.

Signed proof regressions use actual ES256 signatures and trusted attestation
keys. Encryption regressions encrypt and decrypt real compact JWE, retain
the status through storage/replay helpers, and assert the HTTP presenter uses
the semantic status for both encodings. The live deferred fixture also replays
the initial encrypted response through PostgreSQL. The completion-failure
fixture is a semantic store-port injection, not a PostgreSQL driver fault.

DCQL `aki` compares
decoded KeyIdentifier bytes from the authenticated credential issuer chain, never
the issuer URL/thumbprint, a holder chain or separately loaded anchors. Issuer
trust, revocation and format signatures still run in their original verifier;
metadata projection performs no second signature verification. Missing AKI
metadata, including retained legacy results, does not satisfy an AKI condition.

Individual invalid credentials or query mismatches are discarded before required
credential-set alternatives are evaluated. Every supplied presentation is still
verified even after a required alternative succeeds. An authenticated wrong or
missing SD-JWT holder nonce rejects the whole response. Issuer signature,
algorithm, certificate path and issuer trust are authenticated once before that
nonce decision; issuer expiration presence/type/time policy runs afterward,
alongside the remaining individual-credential policies. Missing, malformed or
expired issuer `exp` with the correct nonce is still excluded. Its authenticated
wrong nonce cannot be hidden by that policy, revocation, audience, holder time,
disclosure or query mismatch. The existing JWT NumericDate rounding and 60-second
leeway remain. mdoc binds the transaction
inside its signed SessionTranscript: a failed current-session device proof is
also a whole-response failure because it cannot safely establish a nonce match.
Verifier/revocation dependency unavailability remains HTTP 503 and is not filtered
as an invalid credential. DCQL ignores unknown extension properties at every
object level while retaining known-field types and declared-reference checks.

Signed SD-JWT/mdoc fixtures cover issuer AKI projection; service-port fixtures
cover DCQL selection, discard and error disposition. Run both fixture groups when changing these checks.

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

A projection write succeeds only when PostgreSQL acknowledges its write or a
fresh locked read proves the exact existing projection. An identical retry leaves
the row version unchanged; rejected identity, lineage, provenance or sender
bindings return `InvalidTransition`. Registered retries also recheck the active
client under a row lock. Writes use one statement; no-write retries require a
second statement because a conflicting insert may commit after the first
statement's snapshot. Explicitly corrupt stored ciphertext and response metadata
return `InvalidTransition`; connection, query and commit failures remain
`Unavailable`. Neither result publishes credential data after failed validation.

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

Validated proofs carry `HolderBinding` directly into immediate signing and
deferred intents. The storage adapter alone decodes retained binding JSON:
`null` still denotes an intentionally unbound credential, and `{"jwk": ...}`
keeps its existing stored shape. Malformed binding records fail at that boundary
instead of being silently treated as unbound during signing.

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
rows.

Management dataset writes return their own committed view after the encrypted
mutation, its audit event, the complete result stream and transaction commit
acknowledgement. The claims value moves through the write owner; PUT does not
fetch and decrypt a second post-write view. Its returned `updated_at` comes from
the database mutation. A later update does not replace that response snapshot.
Current actor and subject gates stay in the write statement. The subject
precheck stays until rejection distinguishes subject, actor and source failures.

### Credential sender and trust checks

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
regression are supplied in source.

### SD-JWT processed claims and credential status

Managed SD-JWT VC datasets reject `vct#integrity`, `aka_vcts`, and `...`
as subject claim names: these names belong to credential control or SD-JWT
processing and cannot be emitted as selectively disclosed subject claims.
The signer also supports an empty subject-claims object: an SD-JWT with no
Disclosures is serialized as the issuer JWT followed by one `~`.

The verifier reconstructs the RFC 9901 processed payload from the authenticated
issuer payload. Signed plaintext claims remain present; disclosures may populate
nested object properties and array elements. Undisclosed array placeholders are
removed. Malformed disclosures, reserved names, duplicate digest references,
unused disclosures and collisions with existing object properties are rejected.
The returned claims omit `_sd` and `_sd_alg` processing metadata. The composed
payload is limited to 128 nesting levels, matching the JSON parser's depth bound.

After holder nonce authentication, issuer `exp` is required and an included
`nbf` is enforced with the JWT verifier's 60-second clock tolerance. Both checks
apply to the processed payload. SD-JWT VC control claims (`iss`, `nbf`, `exp`,
`cnf`, `vct`, `vct#integrity`, `aka_vcts`, `status`) and their subclaims must
remain plaintext; disclosure references within them are rejected. `iat` and
`sub` may be selectively disclosed, as specified in
[SD-JWT VC section 2.2.2.3](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-26#section-2.2.2.3).
DCQL type selection accepts the signed `vct` and valid signed `aka_vcts`
values. The primary `vct` must be a non-empty string, even when an alias
matches the query. An empty or malformed `aka_vcts`, or one containing the primary
`vct`, is rejected.
The verifier does not retrieve or process Type Metadata. It does not verify
`vct#integrity` against a referenced document and cannot enforce policies that
require Type Metadata processing.

The verifier accepts credentials without individual status references. When a
signed credential carries `status.status_list`, it retrieves and verifies the
list according to [Token Status List draft-21](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21).
SD-JWT VC uses an ES256 `statuslist+jwt` with an authenticated `x5c` chain and
the same public key as the credential issuer. mdoc uses an ES256/ESP256
COSE_Sign1 CWT with protected `application/statuslist+cwt` type and `x5chain`;
its signer must be issued directly by the credential's authenticated IACA.
Embedded JWKs do not create trust. Certificate revocation remains a separate check.
The CWT decoder retains the received protected-header byte string for signature
verification and preserves CBOR tags when validating labels and integer fields.
Bignum tags cannot become ordinary header labels, list bit widths or TTL values.
Unsupported critical headers and duplicate labels across header buckets are
rejected before trust evaluation.

The verifier binds `sub` to the exact status URI, validates required `iat`,
optional `exp`/`nbf` and positive `ttl` (mdoc requires `exp`), and accepts only
status zero. Revoked, suspended, unknown, missing, out-of-range and malformed
states fail closed. Lists use zlib and 1/2/4/8 bits per entry, least significant
bits first. Unsupported status mechanisms and explicit delegated-certificate
references remain rejected; status-list allocation and publication are not implemented
by the shipped NazoAuth endpoints.

mdoc issuance defaults to `MdocStatusIssuancePolicy::Disabled`. A nonempty
`CredentialSignInput.status` is rejected under that policy instead of being
silently omitted. An embedding with its own durable allocator and publisher may
explicitly select `PublishedTokenStatusList` and configure the existing resolver.
The signer first retrieves a real list, then selects its signing lease and
verifies that list against the exact credential signer/IACA, URI, time and index.
Only a valid status-zero entry is embedded in the signed MSO. Missing lists,
unsupported mechanisms, invalid signatures and out-of-range entries
reject issuance. The embedding remains responsible for assigning that index to
the credential, maintaining publication availability and updating status; list
retrieval does not allocate or reserve an entry. The ordinary endpoints supply
`status: None` and do not enable this policy. Credentials without status do not
trigger a fetch.

Fetching uses the existing bounded HTTPS resolver: validated TLS and DNS-pinned
addresses, no redirects or ambient proxy, 10-second deadline, shared 16-request
limit, and 128 KiB response bound. Decompression streams at most 16 MiB without
allocating the complete list. Each verification fetches a fresh complete list;
there is no status cache or stale fallback. The request sends no credential,
index, authorization token or cookie, but its timing and the verifier's network
address remain observable to the list host. Private origins require the existing
explicit `REMOTE_CLIENT_DOCUMENT_PRIVATE_ORIGINS` allowlist.

### DCQL known-shape admission

The existing DCQL validator rejects an explicitly empty credential_sets array,
missing/non-object meta, and malformed supplied vct_values/doctype_value
constraints. vct_values must be a non-empty array of non-empty strings;
doctype_value must be a non-empty string. Unknown properties remain ignored.
The retained request completion path invokes this same validation owner before
verifying any credentials or persisting a result, so historical malformed
queries cannot be accepted as unconstrained or as zero-evidence completions.

The empty-meta profile accepts unconstrained queries. Format-specific type identifiers, ID character sets, duplicate claim paths, claims.values and trusted-authorities cardinality require separate validation. See OpenID4VP 1.0 sections 6,
6.1 and appendices B.2.3/B.3.5 for the separate conformance boundaries.
Regression tests cover typed creation, domain validation and retained-query rejection.

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
The deadline applies when the locked mutation is accepted. The commit ACK may arrive later. No extra deadline check is
added at each await. Real PostgreSQL source regressions cover old caller time,
pool acquisition wait, an unchanged locked row crossing its deadline, response
key/result preservation, and one-winner success; run them against the isolated test database.

Deferred claiming locks the original and current grant rows in token-ID order
and consumes their complete projection before locking the retained intent.
The PostgreSQL adapter then invokes the existing Rust continuation policy once,
using a database clock sampled after those lock waits. Caller timestamps cannot
advance readiness, hide current-grant or intent expiry, or reclaim a live lease.
Denied, Pending and Busy results write no lease. An authorized ready claim uses
a second data statement to recheck temporal expiry and install the five-minute
lease; the response becomes Claimed only after full COMMIT acknowledgement.
Cancellation or unknown transaction completion discards the physical pooled
connection. The query contract is two statements, including authorization
projection, with no separate intent lookup or tentative unauthorized lease.

## Certificate paths

VC certificate validation checks the complete supplied path to an explicit
trust anchor, including validity, basic constraints/path length, CA key usage,
name constraints and unknown critical extensions. The caller's document/profile
EKU policy is applied separately; a TLS-server EKU is not substituted for a
credential-signing purpose. An empty or unrelated chain is rejected.
