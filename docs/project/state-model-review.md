# Storage placement and large model review

This review separates a model's responsibility from its top-level field count. The inventory scans named production Rust structs with at least 20 direct fields (excluding tests and generated schema). It is a triage inventory, not a proof that every field of every smaller type or enum has been exhaustively audited. The storage catalogue is in [state-storage-lifecycle.md](state-storage-lifecycle.md).

## Implemented corrections

- `RefreshToken` now composes the existing `RefreshContract` instead of flattening its five original-grant fields into the current-token projection. Current audiences, generation SID and expiry remain separate. The database decoder retains the contract it decoded instead of destructuring and reconstructing it. No table split, SQL call, serialization change or new allocation is introduced by this grouping; field-count reduction is not claimed as a storage saving.
- `PreparedDynamicClientRegistration` directly owns `CreateClientRequest` plus negotiated `response_types`. The 47-field carrier and its nearly one-to-one conversion are removed. Dynamic-registration-only defaults are set at negotiation. Wire registration metadata, unsupported-choice rejection, mTLS and CIBA checks, remote JWKS resolution and subsequent create validation remain in their existing boundaries.
- A redeemed VCI offer clears the unread encrypted grant body and TX-code verifier in the same conditional consume update. It retains the consumption fact, original expiry, code digest and authorization metadata. A stale snapshot in a weaker store must not revive a one-use credential; no KV move is made without that guarantee.
- Timestamp validity and physical retention are independent. Single-use receipts are filtered by their safety deadline at read. Exported decision payload is compacted only by the existing authenticated acknowledgement transaction; structured replay fences and business retention survive. SCIM history with 180-day retention is reclaimed hourly, while the existing bounded protocol-state worker retains its 60-second cadence.

- Used backup verifiers leave in the original consumption/audit transaction. The unused `used_at`/`created_at` fields disappear; missing candidates already reject reuse. TOTP removes its write-only label and generic timestamps; the label stays in the enrollment response, while secret protection, confirmation and replay state remain.
- Remembered MFA devices use their existing tenant/token identity; unused UUID/creation-time fields are removed. Expired devices and controller approvals have an hourly reclamation owner. Original security deadlines, MFA-generation transactions and independent audit evidence remain intact.
- Refresh issuance no longer stores a second copy of the original ID Token SID. The source authority already distinguishes a non-refresh issuance from a refresh whose original SID was absent. This removes a possible contradictory representation without a new wrapper or query.

## Large models and decisions

Counts below describe the pre-change direct fields, not bytes or database columns.

| Model | Fields | Ownership and decision |
|---|---:|---|
| `DynamicClientRegistrationRequest` | 68 | Untrusted protocol input, including alternate negotiation choices. Keep the flat wire contract; choices and selected values must be checked for consistency, then discarded or normalized. Do not persist the raw request as another client. |
| `PreparedDynamicClientRegistration` | 47 | Repeated normalized metadata carrier. Replace its field list with the existing create request and the separate response choices. |
| `CreateClientRequest` / `PatchClientRequest` | 51 / 46 | Commands with distinct create/default and patch/absence semantics. Keep those distinct semantics; merging them would confuse absence with resetting a field. |
| `ValidatedClientRegistration` | 51 | One normalized client registration. Presentation and security policy already have explicit owners. Endpoint-specific signing/encryption algorithms are independent protocol choices, not duplicate copies of one algorithm. No new tables or shared generic policy object solely to lower the count. |
| `ClientMetadata` | 31 | Borrowed view shared by create/patch validation, not an independently stored authority. mTLS selection already has a focused validator. Splitting the borrow list has no proven storage benefit. |
| `OAuthClientRecord` | 59 | Adapter-only SQL projection. It decodes into client registration plus tenant/runtime identity. Projection width does not require multiple queries or tables. Credentials are not added to the runtime metadata boundary. |
| `RefreshToken` | 20 | Original grant and mutable current generation were flattened together. Compose `RefreshContract`; preserve original vs current audience, sender binding and SID distinctions. |
| `TokenIssue` | 28 | Request-local candidate signing input plus its durable refresh source. The signed result and original authority are different responsibilities, checked by `refresh_issue_matches_source`. Keep that comparison: a narrower AT audience or stronger AT binding must not rewrite the original RT authority. The redundant `refresh_id_token_sid` copy is removed: signing and persistence read `refresh_authority.id_token_sid` directly, including original omission. Remaining output/source comparisons still protect the distinct signed AT and durable RT facts. No field is removed merely because its value often equals the source. This review does not claim this input is a fully unrepresentable-state API. |
| `ConsentPayload` | 27 | One expiring consent continuation, with client policy snapshots and PAR linkage. Consent decision and authorization-code redemption are separate phases; code state must not retain all consent UI fields. Existing separate `CodePayload` is retained. |
| `CodePayload` | 20 | One expiring redeemable grant, PKCE, sender and authentication constraints. KV owns the preparation/consumption lifecycle; a separate minimal durable receipt links the completed issuance for replay handling. |
| `Claims` | 20 | Access-token wire claims. Issuer, tenant, user identity, external subject and revocation epochs have different consumers. Do not remove signed security context to reduce struct size. |
| `TokenForm` | 21 | Untrusted input for multiple grant types. Normalize into the existing grant-specific admissions; it is not a database model. |
| `AccountProfileView` | 26 | Stable browser response projection. Domain account/profile/address are already composed; changing JSON nesting would be an API change without changing stored state. |
| `SubjectClaims` | 20 | Read-only OIDC claim selection input with an existing `PostalAddress`. It is not a second user-write authority. |
| `PublicAccountRow` / `SubjectClaimsRow` | 33 / 31 | Adapter projections for different read consumers. Keep decoding boundaries and tenant predicates; do not introduce joins merely to make each Rust struct smaller. |
| `UserInsert` | 25 | Adapter insert shape for account creation, not a universal mutable user aggregate. Domain identity/profile structures remain separate. |
| `UserProfileFields` | 20 | Desired resource profile command; keep desired-state reconciliation distinct from the observed user projection and preserve address/verification semantics. No duplicate runtime cache is added. |
| `SecurityAuditAnchorHealthRow` | 21 | One query projection of chain/checkpoint and in-flight lease. Domain already composes a separate `SecurityAuditBatchLease`. Splitting the query can lose the single-observation relationship and add round trips. |
| `ProviderConfig` | 22 | Startup input only. It is immediately converted into typed OIDC/social provider variants; the broad optional configuration is not used during request execution. |
| `CoreServices` / `IdentityServices` | 23 / 35 | Bootstrap dependency bundles, not persisted business records. Do not apply database normalization or TTL rules to service handles. |

These decisions reject mechanical splitting, not future changes supported by a concrete independent lifecycle or invalid-state defect. In particular, the presence of many optional protocol fields is not evidence of unbounded persistent growth.

## Storage and failure semantics

The normal form is one authority per fact, not one database for every short-lived object. Independently expiring browser/protocol preparation already resides in Valkey. Request-local normalized values remain memory-only. Completed issuance, revocation, rotation ancestry, Required evidence and recoverable business results retain their required durable ownership.

Offer consumption precedes grant issuance in separate commits; it was incorrectly described as one transaction in the earlier catalogue. Nevertheless, current access-grant identity is newly generated and does not durably fence an offer identity. Moving the offer alone to a store that can restore an earlier unconsumed value would permit another valid redemption. A short TTL does not solve that failure mode. Retaining its compact consumed state is the shorter correct change here.

Required evidence is never replaced by Telemetry HTTP success. Acknowledgement compaction does not reduce safety TTLs or imply that physical PostgreSQL files shrink immediately. Logical retained rows, expired eligible backlog, dead tuples and reusable high-water allocation must be reported separately in performance evidence.

MFA's single-use boundary is not a storage-history requirement: deletion and audit
remain atomic for backup codes. TOTP still records and rejects a previously accepted
step, as required by [RFC 6238 section 5.2](https://www.rfc-editor.org/rfc/rfc6238.html#section-5.2).

## Normative references

The specifications define protocol behavior rather than a required database product:

- [RFC 7591 client metadata](https://www.rfc-editor.org/rfc/rfc7591.html#section-2) and [OIDC registration metadata](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata) explain why the external registration shape has many distinct fields.
- [OAuth authorization-code reuse](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2), [refresh-token protection](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14.2), and [OpenID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) constrain consumption and replay semantics.
- [Valkey replication](https://valkey.io/topics/replication/) does not promise strong consistency merely from acknowledgements to replicas. TTL is not a substitute for the acknowledged-write failure contract.

Test commands and measured results belong to the accompanying acceptance evidence; this design document alone is not a performance or storage PASS.


## Follow-up review boundaries

A compact field encoding is different from deleting a security fact. Replay marker
keys currently use hexadecimal digests. Changing the key derivation while accepted
markers remain live makes old markers invisible; mixed-version writers compound
that problem. This review retains the existing namespace and TTL rather than
adding a permanent dual-write/read mechanism solely to save key bytes. It does
not call that representation a proven byte-minimum. Replay bodies already contain
only a presence marker; their required receiving window must not be shortened to
make a memory graph look smaller.

Controller recovery allocation proofs have no independent expiring replay identity:
removing their old challenge records can make a captured allocation proof reusable.
Completed challenges additionally carry an idempotent recovery result. These are
actual callers of retained state, unlike expired random approval tokens, whose
absence always rejects. Reworking that protocol would require the independently
owned controller contract and cannot be inferred from the shared word “challenge”.
