# Managed OpenID4VC state

The tenant signing-key record owns the ES256 signing key, matching certificate
chain, historical trust anchors, IACA private material and local DS revocation
facts. The existing persistence adapter commits the complete encrypted record
with compare-and-swap. No new database table or object-storage adapter is used.
IACA private material is excluded from public keyset metadata.

A signing operation captures one key generation. Its x5c, mdoc non-root certificate chain,
OpenID4VP certificate-derived client_id and signature use that same generation.
A pending signed-post VP request bound to an old certificate hash is rejected
if explicit certificate rotation occurs before nonce retrieval; the wallet must
start a new request. No JWT is returned with mismatched outer/inner identity.
Rotation retains old IACA records and roots for previously issued credentials
and their CRL URLs. It does not delete historical authority material.

The existing key lifecycle refreshes managed OpenID4VC generations at most every
30 seconds. Local revocation facts are authoritative database state; a successful
read establishes a new observation window, without writing a new revision.
Verification rejects an observation older than 60 seconds. CRL requests read the
database directly and use a persisted publication valid for 24 hours. Its first
publication, changed revocation facts or expiry allocate a new publication
through the same keyset compare-and-swap. A revoked active DS cannot
be selected for new signing; rotate it to resume issuance.

Client-scoped external trust continues to use tenant TrustPolicy resources.
Managed issuer state does not use external trust resources as a private-key
store. The former managed certificate/trust/revocation file settings and file
reload interval have been removed.

## Issuer verification

ISO/IEC 18013-5:2021 section 9.3.1, step 5 requires the MSO
`validityInfo.signed` time to fall within the document signer certificate's
validity period. The mdoc core checks this bound independently of current
credential validity. NazoAuth performs RFC 5280 certificate path validation
and certificate revocation checks at the same captured current time used for
the MSO validity check. An expired DS is not made acceptable by an earlier
MSO signing time. The authenticated signing time retains a whole leap second;
it is not forced through a Unix-time conversion that would lose that value.

Signing and verification use `nazo-mdoc`'s supported Annex B DS and IACA profiles.
The protocol core validates DS fields once and returns a borrowed leaf view.
NazoAuth supplies the authenticated path and verifies root self-signatures with
its existing X.509 engine. The actual selected root must
carry its required issuer contact and CRL distribution point; a trusted key or
a valid unrelated root does not replace those fields. This also applies when
an existing database generation is loaded directly for signing. Credential
status when present and holder authentication remain separate checks. A
successful COSE signature alone does not complete these responsibilities.

An imported rollover chain requires the corresponding old and new self-signed
IACA certificates in the existing trust-anchor set. Retain intermediate root
generations as evidence when validating link relationships. The core checks each link's exact issuer,
subject, SPKI, AKI, old-root expiry and conditional new-name SAN. Missing root
evidence rejects the chain. An authenticated root transmitted in `x5chain` is
rejected under Annex B.1.1; signing continues to emit only non-root certificates.
The current X.509 engine accepts direct-root paths and paths with one IACA link;
it rejects multiple self-issued links with `pathLenConstraint=0`. Configure the
newer root directly for later rollovers; Profile checks do not bypass that path
validation limit.

The standard is identified in the [HAIP normative references](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html#ISO.18013-5).
Freshly issued test certificates and backdated MSO signing times can violate
this requirement even when both signatures verify. The issuer must choose a
signing time within the certificate's validity; verifiers must preserve the
check for ordinary credentials and external conformance fixtures alike.

## Import complete certificate material

An administrator can import externally prepared certificates into an existing
tenant database keyset using the deployment's normal configuration:

```sh
nazoauth mdoc-import --tenant <tenant-uuid> --from <certificate-material-directory>
```

The directory contains `certificate-bundle.pem`. An mdoc profile also requires
`revocation-snapshot.json` and `iaca-keys/<CRL-publication-id>.pem` for each IACA.
Each IACA file contains its private key, DS certificate, and IACA certificate.
The selected signing key must already exist in the tenant database keyset and
match the supplied leaf certificate. Non-mdoc profiles can import a certificate
chain without IACA material.

Import checks these relationships and preserves the existing signing kid.
Every revoked entry must carry its own revocation timestamp. Missing timestamps
are rejected; the snapshot observation time is not a substitute for the event.
It imports only locally owned DS revocation facts; mixed external status input
must not be promoted to authoritative local state. Missing IACA records, a
mismatched chain or an existing managed aggregate cause an error. No automatic
regeneration or file fallback occurs. A failed commit leaves the prior keyset
unchanged. A repeated import after success reports that material already exists.
The filename and both certificates' CRL URLs must agree with the publication
identifier. One IACA key may own only one certificate record in this native
profile, so importing multiple records with the same key is rejected. Otherwise
the separate endpoints could publish incomplete lists for one issuer.
New IACA records also pass the supported root certificate profile. The maximum
lifetime is computed as 20 calendar years, with February month-end clamping,
using the existing date library. Fractional certificate times are rejected
before conversion to whole seconds. The self-signature, current validity, tenant
configuration and complete active certificate pair are checked separately;
sharing a publication key does not permit replacing the recorded root DER.

An imported historical record may retain the old DER-hash URL when its root
omits CRLDistributionPoints and its DS contains that exact legacy URL. This
exception preserves an existing revocation endpoint; it does not qualify the
legacy root as the active issuing generation. The active imported pair must
contain the new root and DS publication address.

Fresh installations initialize the complete aggregate through tenant bootstrap
or the existing tenant key-generation operation. Normal server startup reads
it and does not create certificate files. Tenant key-generation results carry
the kid, revision and certificate chain from their selected or applied generation,
including an existing concurrent winner. A later rotation may supersede that
generation but cannot mix its fields into the completed generation result.

Before 0.5.0, historical release formats are not supported or converted.
Retaining prior IACA records during normal key rotation serves credentials
already issued by the current lifecycle; it is not a file-format upgrade path.

## Rotation and revocation

With the deployment's normal configuration available to the administrator:

```sh
nazoauth mdoc-rotate --tenant <tenant-uuid>
nazoauth mdoc-revoke --tenant <tenant-uuid> --issuer-id <CRL-publication-id>
```

The identifier is the 64-character lowercase hexadecimal value already present
in that DS certificate's CRL URL. For newly generated material it is
`SHA-256("NazoAuth mdoc CRL publication v1\0" || IACA subjectPublicKey bytes)`.
The prefix ends in one zero byte; the key bytes are the raw BIT STRING payload,
not SubjectPublicKeyInfo DER. This value is available before the root is signed,
so both root and DS can include the same
`<issuer>/.well-known/mdoc/<CRL-publication-id>.crl` address without a circular
hash of the root certificate. This publication identifier is separate from the
certificate fingerprints used for trust and revocation identities.

Previously published DER-hash addresses remain attached to their original
records across rotation. No second copy of an IACA private key is created under
an alias. Signing rejects an active root without CRLDistributionPoints.
`mdoc-rotate` atomically creates a new compliant IACA and DS generation while
retaining the original authority record and DS CRL endpoint. Issuance does not
replace trust anchors as a side effect of a credential request. Certificate
bytes already distributed to holders remain unchanged; retaining their CRL
endpoint does not waive the issuer or verifier's current certificate profile.

Each current IACA record owns one DS; revocation
marks that DS revoked, not every historical DS. Concurrent updates use the
record revision to prevent lost writes. A conflict fails explicitly and must be
reviewed before repeating the operation. Neither command modifies other tenants.

Back up the database and wrapping root together. Restarting an instance requires
no local mdoc directory. Deployment validation must still exercise cross-instance
issuance, verification, rotation, and recovery against the actual shared stores.

CRL issuance reads one fresh, authenticated tenant generation and extracts only
the selected IACA bundle and revocation snapshot. It retains schema, seal and
public/private projection binding and revocation structure validation, without
preparing unrelated JWT signers or request-object RSA keys. The selected DS,
publication address/contact, status, serial and revocation time remain checked;
the crypto signer matches the IACA private key to the certificate and signs
using that same prepared key. Historical IACA records remain available.

The encrypted keyset also records the publication's source hash, allocation
revision, `thisUpdate` and `nextUpdate`. The hash binds the selected certificate
DER and persisted revocation snapshot, not private-key bytes. An unchanged,
unexpired publication reuses the complete to-be-signed CRL content and number.
A successful compare-and-swap allocates the next number as `2^64 + revision`,
which is greater than all numbers emitted by the former `u64` wall-clock scheme.
Concurrent conflicts re-read the winning facts before publishing. A clock
earlier than the previous publication's `thisUpdate` is rejected. Publication
monotonicity relies on preserving the authoritative database revision during
recovery; restoring an older database is not a safe way to reset CRL state.

Every instance serving the same CRL endpoint uses this persisted allocation.
A published number is issuer state: once a number above `2^64` has been served,
the former `u64` clock-based publisher cannot produce a valid later number for
that endpoint. Recovery retains a database revision at least as high as every
publication already served; restoring an older snapshot does not reset the
sequence.

The root's CRL endpoint publishes the IACA-signed list for its owned DS. It does
not independently establish trust in that IACA or make a compromised root key
safe. Removing a compromised trust anchor and updating its trusted distribution
remain explicit authority and deployment responsibilities. The applicable
[ISO/IEC 18013-5:2021 Annex B](https://law.resource.org/pub/us/cfr/ibr/inc/iec/iec.18013-5.2021.pdf)
and [RFC 5280 CRL-number rules](https://www.rfc-editor.org/rfc/rfc5280.html#section-5.2.3)
do not replace those operational controls.
