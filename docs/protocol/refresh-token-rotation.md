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

Grants which neither create nor redeem a refresh token (client credentials,
JWT bearer and token exchange) explicitly use NoRefresh. They require no source
family or refresh authentication context and never return a refresh token.
NoRefresh cannot carry a source authority or enable a refresh-token response;
PreserveExisting always requires an existing source even when no RT is returned.

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
| Reused | A retained, unexpired spent token fails the authenticated lost-response rule. | Mark an otherwise active family as reused and revoke its current refresh token; already terminal families remain unavailable. |
| Expired | Token expiry is in the past. | Reject with `invalid_grant`; do not issue a successor. |

## Lost-Response Retry

If a client successfully rotates a refresh token but loses the HTTP response before storing the successor, it may retry the same old refresh token briefly. The server accepts this only when all conditions are true:

- the old token belongs to the authenticated client
- the old token is within `LOST_REFRESH_TOKEN_RETRY_SECONDS` after its spent proof's `spent_at`
- the token family has no recorded reuse
- exactly one non-expired, non-revoked successor exists for the old token
- the sender constraint on the old token still validates

The retry continues from the active successor and rotates again. It requires an
actual persisted DPoP or mTLS binding. An authenticated, retained, unexpired
spent token outside this rule is replay, not compatibility recovery. An
unknown or expired token returns `invalid_grant` without attributing it to a
family or creating a compromise marker.

## Sender Constraints

DPoP-bound refresh tokens require a valid DPoP proof for refresh. mTLS-bound
refresh tokens require a verified certificate thumbprint from Direct TLS or
trusted RFC 9440 forwarding and constant-time match against the stored certificate
thumbprint. A refresh token issued through `attest_jwt_client_auth` is bound to
the RFC 7638 thumbprint of the Client Instance public key in the attestation
`cnf.jwk`. Every refresh request must use Client Attestation with that same key;
the binding is retained by every rotated successor and by lost-response
recovery.

A confidential client's current mTLS requirement can bind the newly issued AT
while preserving an existing unbound RT. The AT's verified certificate does not
rewrite the RT's persisted binding. Existing RT bindings remain mandatory for
the AT and are preserved exactly for retained members and rotated successors.

## Replay-Proof Retention

[RFC 9700 section 4.14.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14.2)
requires public clients to use sender-constrained refresh tokens or rotation
with replay detection. For an unbound public family, every spent proof is
retained until that token's original expiry or the family's retirement. A
replay at generation 65 or later therefore still identifies and revokes the
active family. Proofs contain no duplicated authorization contract.

Confidential clients are authenticated and their refresh tokens remain bound
to that client under [RFC 6749 section 6](https://www.rfc-editor.org/rfc/rfc6749.html#section-6).
The public-client rotation requirement does not require complete historical
reuse detection for confidential clients. Confidential families, and families
with a persisted DPoP or mTLS binding, retain at most the newest 64 proofs as
an additional bounded reuse/lost-response signal. Beyond that window a spent
presentation is unknown and does not trigger family compromise. This is an
explicit local limit, not an all-history security guarantee. Client-instance
attestation alone does not select the sender-bound retention exception.

The Core policy uses the client type read under the existing principal lock
and the actual family binding checked under the family lock. Configuration
flags and a newly requested access-token binding are not substitutes. A
confidential-to-public authentication-class change must atomically revoke
existing refresh families: past proofs discarded under the confidential
policy cannot become public rotation authority. The PostgreSQL adapter uses
the client UPDATE's old/new values and the existing client-first lock order;
management audit behavior is preserved and the revocation evidence commits
with the mutation.

Rotation sets the new current member's expiry to `now + REFRESH_TOKEN_TTL_SECONDS`
(default 30 days); it does not extend any spent proof's original expiry.
Unbound public proof volume is consequently proportional to rotations during
the token lifetime, plus cleanup lag, rather than bounded to 64 per family.
Expired proofs use the existing indexed, bounded maintenance sweep. This is
not a promise to detect replay of tokens after their original expiry.

### Upgrade and Rollback Boundary

Migration `20261001000500_refresh_replay_retention` revokes existing unbound
public refresh families once, preserving their rows and writing a Required
`refresh_family_security_revoked` event with reason
`public_replay_retention_cutover`. Old opaque-token associations already
trimmed by previous releases cannot be reconstructed, and a small or empty
proof set does not establish that none were lost. Affected clients must obtain
a fresh authorization grant after upgrade. Existing confidential and DPoP/mTLS-
bound families are unaffected by this one-time cutover.

Stop old token issuers before applying the transactional migration, then admit
traffic only through the new writer. Mixed-version writers could delete
proofs the new writer must retain. An alternative gradual, no-forced-reauthorization
transition would leave the old exposure until affected original tokens expire
(up to the configured TTL); this release chooses an immediate guarantee instead.
No token lifetime or benchmark workload is shortened to obtain it.

The down migration removes the added downgrade guard only. It never restores
`revoked_at`, reconstructs missing proofs, or deletes revocation evidence.
Rolling code back loses the new public retention guarantee; do not resume
public refresh traffic on the old writer without a separate security decision.
Ordinary audit events follow the existing exporter-ACK lifecycle, so durable
retention after ACK is the configured audit receiver's responsibility.

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

Additional real PostgreSQL regressions in `tests/refresh_authority.rs` cover
unbound public reuse after 65 rotations, confidential and DPoP/mTLS 64-proof
limits, original-expiry cleanup, unknown-token non-attribution, downgrade and
rotation in both lock orders, genuine pre-005 migration data, restricted-role
audit append, and rollback that cannot revive revoked credentials. Existing
lost-response and HTTP proof-validation tests remain required.
