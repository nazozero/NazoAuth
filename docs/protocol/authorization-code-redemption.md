# Authorization-code redemption and upgrade

An authorization code has one durable consumption identity, independent of the
token request's resource subset, scope text, optional redirect representation,
sender key or attestation key. The commit owner fences this identity within its
tenant and client, atomically commits the refresh family and Required issuance
audit, and acknowledges success only after commit. An unknown commit result
returns a dependency error without tokens. A retry never chooses another identity.

Original possession requirements are immutable checked values behind private
fields, constructed after validation or restored through a strict persisted
requirements reader. They are distinct from the application's private fresh
request facts; a receipt cannot deserialize into fresh authentication evidence.
The constructor closes the structural contract and does not itself authenticate
an HTTP request. Original possession requirements are a separate versioned receipt: authenticated
client status, S256 verifier commitment, and any actually verified DPoP, mTLS or
client-attestation binding. These requirements come from the validated first
issuance. After cache expiry, replay still performs fresh client and presented
sender/attestation verification, then compares the candidate verifier and proof
bindings with the receipt. Code identity alone never authorizes revocation.
Public-client empty evidence is rejected. A wrong or absent original proof cannot
revoke another holder's access token or refresh family; the code stays consumed.
An extra valid optional proof does not erase the original requirements.

Pending parameter errors do not consume the code. The existing state-store begin
lease is retained for this repair, including Native SSO's preparation behavior.
Busy, Failed, Missing and cached Consumed states all consult the durable receipt.
An expired cached Pending is also replay evidence, not new issuance eligibility:
it consults the receipt after fresh holder validation without beginning another
redemption. Wrong/missing proofs never revoke, and expiry is never bypassed to
issue again. The receipt's original mask also selects the already verified
certificate facts even if current client policy has disabled mTLS binding;
current flags do not erase original possession requirements. Thus

cache markers alone cannot authorize revocation or a second issuance. An unknown
receipt read fails closed and does not fall back to historical lookup.

The receipt retains the original access-token acceptance horizon plus skew and
the grant deadline, whichever ends later. It does not retain the entire refresh
family lifetime. A replay after receipt reclamation is denied, but can no longer
locate that original family for directed revocation. Audit exporter ACK and cache
expiry do not reclaim a still-live receipt.

## Coordinated upgrade

Migration `20261003000100_authorization_code_identity` preserves historical
request-digest receipts byte for byte, with contract version zero and no guessed
holder or code identity. New writes explicitly carry contract version two. The
new constraint rejects old single-use insert shapes, including other single-use
grant writers, so mixed-version issuance is deliberately unavailable. Historical
exact-request keys remain lookup-only for safe replay revocation. They cannot
identify a code from their one-way digest and are never used for new issuance.

1. Close ingress to authorization and token issuance and isolate old instances.
   Drain in-flight old writers before applying the migration. Preserve the durable
   receipt/audit database and a recoverable backup.
2. Expire or explicitly invalidate old pending authorization codes and replace the
   transient-state epoch/namespace. The new issuer independently rejects payloads
   missing contract version two; a payload's version is not silently upgraded.
3. Apply the migration and deploy only the matching issuer version. Reopen ingress
   after migration, state-epoch and old-instance isolation checks pass. Users with
   invalidated codes restart authorization. Existing tokens keep their existing
   acceptance and revocation policy.

Do not reopen an isolated old primary or old issuer against a new state epoch.
Database rollback is refused while any version-two receipt remains; dropping the
new fence would admit duplicate issuance. A coordinated rollback must again close
ingress, drain/isolate all issuers and invalidate pending codes under a new epoch.
Only after all version-two receipts have safely drained under retention may the
guarded down migration run. A coherent pre-upgrade restore is a separate recovery
operation; restoring a database or cache snapshot alone is not a safe rollback.

## Evidence boundaries

The application regression delegates effects to real PostgreSQL and Valkey and
uses freshly signed DPoP requests. Its one-shot wrapper hides a successful commit
ACK at the semantic port boundary; it is not a physical driver/network fault test.
The migration test applies actual up/down SQL to a transaction-owned table copied
from the complete migrated schema. It tests the old insert shape and rollback
guard, not execution of an old binary. Both require isolated CNB fixtures and an
exact source SHA before any acceptance claim.

## Historical mTLS policy boundary

Version-zero receipts are found through their original exact-request digest.
That digest uses the sender binding selected by current client policy. Keep
`require_mtls_bound_tokens` enabled for a client while its historical mTLS
receipts remain eligible for replay-directed revocation. Disabling that flag
can prevent the legacy lookup from locating an otherwise valid original mTLS
holder's target; it does not reopen issuance or authorize another holder.
The raw verified certificate projection described above applies to version-two
receipts and does not remove this historical lookup limitation.
