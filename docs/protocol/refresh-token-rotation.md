# Refresh Token Rotation

## Scope

Non-FAPI compatibility profiles use the refresh-token behavior below. FAPI2
Security deployments do not use routine refresh-token rotation by default.
Refresh grants still require confidential client authentication and the
configured DPoP or mTLS proof. Newly issued access tokens remain
sender-constrained.

## Original Grant and Current Resource Selection

The immutable family contract holds the original subject, scope/resource grant,
authorization details and authentication/claim context. Each current member has
its own audience selection and ID-token SID. A refresh request may select a
subset of the current member's resources; rotation preserves the original
contract and narrows only the successor's `current_audience`. Resource order is
not a privilege change. Omitting `resource` on refresh retains the current
persisted audience, never today's configured default or a wider client list.
PreserveExisting changes no refresh member: selecting a narrower AT therefore
does not change the stable RT's resource grant.

RFC 8707 section 2.2 requires a refresh token returned from an authorization-code
redemption to retain the full original grant even if that redemption selects a
smaller AT audience. The first family contract **and** initial current RT audience
therefore retain the code's original resources. When the code contains no explicit
resources, the existing code-redemption resource/default policy resolves its
initial binding once. Monotonic narrowing on subsequent rotating refreshes is
NazoAuth policy; RFC 8707 permits resource selection according to local policy,
while RFC 9700 section 4.14.2 prohibits exceeding consented scope/resource grants.
RFC 8707's authorization-request default-resource option is not permission to
replace a persisted refresh grant with a newly configured default.

OIDC Core section 12.2 separately preserves the original ID-token issuer,
subject, audience and authentication time. Resource audiences are not the OIDC
client audience. NazoAuth also retains its original claim-request contract.

## Commit-Owned Source Authority

Both rotation and PreserveExisting carry the source family/member, presented
token digest, stable contract key, original contract, owner and sender bindings
into the final token-issuance transaction. The signing input is checked against
that source before signing. After principal locks, rotation takes grant-scope
then family locks; PreserveExisting takes only the family lock. The locked
family query joins the original contract and takes an actual family row lock,
which also fences direct family UPDATE writers. It rechecks member/digest,
owner, contract key and content, current audience/SID, sender bindings, and
expiry using the current clock after lock acquisition. Locks are held through
Required audit and commit; no response is published before commit succeeds.

A revocation or capacity retirement that wins the source lock prevents issuance.
If issuance wins and passes the locked source check while unexpired, it may
commit before the waiting invalidation. Missing, revoked, compromised or expired
sources are unavailable grants and do not create another reuse marker. An active
rotation with a conflicting member or changed authority still commits the
existing family-compromise and reuse audit. Concurrent valid PreserveExisting
requests remain valid, issue no replacement RT and add no spent proof.

Contract keys identify durable references. New contracts use BLAKE3 deduplication;
legacy SQL content keys remain unchanged through rotation. Content equality is
checked independently, not by comparing a legacy key with newly serialized
BLAKE3 bytes. A key is not an authentication MAC. The contract ensure operation
locks an existing key and rejects different JSON content; its create/reclaim
retry behavior is unchanged. No migration rewrites existing contracts or keys.

Primary references: [RFC 8707 §2.2](https://www.rfc-editor.org/rfc/rfc8707.html#section-2.2),
[RFC 9700 §4.14.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14.2),
[OIDC Core §12.2](https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse).

## State Machine

| State | Meaning | Accepted action |
| --- | --- | --- |
| Active | Refresh token is not expired and `revoked_at` is null. | A valid refresh request rotates it to a new active successor. |
| Rotated | A spent proof names this member and its direct successor; the family still names that successor as current. | A retry with the old token is accepted only during the lost-response retry window. |
| Reused | A revoked token is presented outside the retry window, has no active successor, has multiple successors, or the family already has `reuse_detected_at`. | Mark the token family as reused and revoke any remaining active family tokens. |
| Expired | Token expiry is in the past. | Reject with `invalid_grant`; do not issue a successor. |

## Lost-Response Retry

If a client successfully rotates a refresh token but loses the HTTP response before storing the successor, it may retry the same old refresh token briefly. The server accepts this only when all conditions are true:

- the old token belongs to the authenticated client
- the old token is within `LOST_REFRESH_TOKEN_RETRY_SECONDS` after its spent proof's `spent_at`
- the token family has no recorded reuse
- exactly one non-expired, non-revoked successor exists for the old token
- the sender constraint on the old token still validates

The retry continues from the active successor and rotates again. Any ambiguous or late reuse is treated as replay, not compatibility recovery.

## Sender Constraints

DPoP-bound refresh tokens require a valid DPoP proof for refresh. mTLS-bound
refresh tokens require a verified certificate thumbprint from Direct TLS or
trusted RFC 9440 forwarding and constant-time match against the stored certificate
thumbprint. A refresh token issued through `attest_jwt_client_auth` is bound to
the RFC 7638 thumbprint of the Client Instance public key in the attestation
`cnf.jwk`. Every refresh request must use Client Attestation with that same key;
the binding is retained by every rotated successor and by lost-response
recovery.

## Family Capacity and Contract Reclamation

Fresh user-bound authorizations retain at most ten active refresh families per
`(tenant_id, user_id, client_id)`. The issuing transaction retires the oldest
family, cascades its spent proofs and records the Required retirement audit.
Rotation does not consume another family slot.

Contract payloads are immutable and may be shared by surviving families.
Capacity retirement leaves their reclamation to the maintenance worker:
a contract is removed only when no family references it and its creation is
at least one hour old. The `(tenant_id, contract_blake3)` family index supports
that reference check. Removing an expired contract remains coordinated with
the existing contract ensure/retry and foreign-key protection.

## Tests

Unit coverage:

- the lost-response retry window boundary
- rejection of `revoked_at` timestamps later than the current clock
- DPoP-bound refresh proof requirements
- mTLS-bound refresh proof requirements
- OIDC refresh issuance requiring both `offline_access` and the client `refresh_token` grant
- OpenID4VCI credential refresh issuance requiring a configured credential authorization
  and the client `refresh_token` grant, without inventing an OIDC `offline_access` scope
- OpenID4VCI refresh scope narrowing using the original credential authorization as the
  rotation signal while rejecting any scope expansion
- RFC 6749 scope narrowing for the newly issued access token while preserving
  the original authorization scope on a rotated refresh token
- Client Attestation refresh-token issuance, persistence, same-instance-key
  enforcement, and binding preservation across rotation

Real PostgreSQL coverage in `tests/refresh_authority.rs` includes resource narrowing
and reordering, expansion rejection, Preserve/revoke and Preserve/capacity races
in both orders, post-lock expiry, content/binding drift, and rotation after the
actual legacy migration chain. `auth_repositories` retains Active -> Rotated ->
Reused and lost-response coverage. These tests must pass against the final
migration head before production guarantees are claimed.
