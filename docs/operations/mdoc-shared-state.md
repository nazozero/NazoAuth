# Managed OpenID4VC state

The tenant signing-key record owns the ES256 signing key, matching certificate
chain, historical trust anchors, IACA private material and local DS revocation
facts. The existing persistence adapter commits the complete encrypted record
with compare-and-swap. No new database table or object-storage adapter is used.
IACA private material is excluded from public keyset metadata.

A signing operation captures one key generation. Its x5c, mdoc leaf certificate,
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
database directly and issue a CRL valid for 24 hours. A revoked active DS cannot
be selected for new signing; rotate it to resume issuance.

Client-scoped external trust continues to use tenant TrustPolicy resources.
Managed issuer state does not use external trust resources as a private-key
store. The former managed certificate/trust/revocation file settings and file
reload interval have been removed.

## Import complete certificate material

An administrator can import externally prepared certificates into an existing
tenant database keyset using the deployment's normal configuration:

```sh
nazoauth mdoc-import --tenant <tenant-uuid> --from <certificate-material-directory>
```

The directory contains `certificate-bundle.pem`. An mdoc profile also requires
`revocation-snapshot.json` and `iaca-keys/<IACA-fingerprint>.pem` for each IACA.
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

Fresh installations initialize the complete aggregate through tenant bootstrap
or the existing tenant key-generation operation. Normal server startup reads
it and does not create certificate files.

Before 0.5.0, historical release formats are not supported or converted.
Retaining prior IACA records during normal key rotation serves credentials
already issued by the current lifecycle; it is not a file-format upgrade path.

## Rotation and revocation

With the deployment's normal configuration available to the administrator:

```sh
nazoauth mdoc-rotate --tenant <tenant-uuid>
nazoauth mdoc-revoke --tenant <tenant-uuid> --issuer-id <IACA-fingerprint>
```

The fingerprint is the 64-character SHA-256 IACA identifier already present in
that DS certificate's CRL URL. Each current IACA record owns one DS; revocation
marks that DS revoked, not every historical DS. Concurrent updates use the
record revision to prevent lost writes. A conflict fails explicitly and must be
reviewed before repeating the operation. Neither command modifies other tenants.

Back up the database and wrapping root together. Restarting an instance requires
no local mdoc directory. These storage properties do not by themselves prove
whole-system multi-instance acceptance or authorize closing issue #108.
