# Cross-device decision preparation

Device and CIBA browser decisions use a request-local, handle-bound state
snapshot to prepare their required audit intent. The intent must receive its
durable acknowledgement before any decision mutation. Preparation is not
permission to commit: the core rechecks the current clock, authenticated user,
request identity and state transition, then uses the original storage revision
for compare-and-swap. A conflict reloads and revalidates state; an unavailable
or unknown write outcome stops the request without claiming success.

Prepared values must be consumed by their originating tenant-scoped service;
their opaque handles do not authorize transferring them across stores or tenants.

## Deployment risk assessment

[RFC 10027](https://www.rfc-editor.org/rfc/rfc10027.html) requires a risk
assessment and mitigations appropriate to each cross-device deployment. The
client grant allowlist and `allow_cross_device_flows` control authorization.
Before enabling these flows, assess consent and session phishing and select
deployment-specific mitigations, including device proximity where possible.
Device/CIBA provide expiry, polling limits, user decisions and client or sender
binding. The relying application supplies the user-facing transaction context
and any proximity check. Apply the same assessment to Native SSO deployments
that transfer authority across devices.

## Device approval

`DeviceGrantService::prepare_decision` returns `PreparedDeviceDecision<V>`.
Its private fields bind the user code, resolved device hash and exact storage
snapshot. The application may inspect its payload for audit and client lookup,
but cannot change or construct its storage identity. `approve` and `deny`
consume this preparation instead of resolving the user code again.

The approval sequence is:

1. Atomically compare the state revision **and the live user-code mapping**,
   then claim the approval
2. Reload after a successful claim or stale-claim takeover before writing the
   durable grant, so a paused worker observes an already transferred owner
   or completed decision
3. Persist the grant and CAS `grant_recorded=true`
4. Reuse the adapter's acknowledged written snapshot for the final CAS; check
   the current authorization expiry again, and atomically verify the mapping
   before removing it

Step 4 reuses the acknowledged snapshot. The read before the grant write checks
ownership again because a later CAS conflict cannot undo that durable write.
The persistence adapter records a unique decision receipt
for `(tenant_id, device_code_hash)` in the same transaction as the grant. It
checks the authorization deadline after acquiring the grant/revocation lock.
A retry of that decision never writes the grant again, including after a newer
worker completes and the user revokes it. Expired receipts are removed by the
existing security-state maintenance worker; expired decisions cannot write.
`Approving` recovery states and the claim timeout allow another request to
complete an interrupted decision.

The native Valkey adapter serializes a replacement once. On an acknowledged recorded
CAS, it returns that exact written JSON as the opaque revision. It preserves
the key's existing absolute `PEXPIRETIME`; no locally recomputed TTL or
core-generated storage version substitutes for it. Mapping replacement or
removal makes the claim fail before the grant side effect.

## CIBA decisions and polling

`CibaService::prepare_decision` returns a validated `PreparedCibaDecision<V>`
bound to `auth_req_id`. The application retains it across the required audit
intent and calls `decide_prepared`. Conflict retries may observe changed poll
timing, but cannot retarget the already audited decision to another client,
user, scope, audience, request lifetime or notification destination.

`decide` and `decide_with_authorization_deadline` prepare their own snapshot.
The latter enforces the caller-owned atomic expiry fence. Authorization and
retention have separate deadlines; the decision CAS also updates ping delivery.

CIBA and Device approved polling retain their state and delegate one-use
issuance to the durable token transaction. CIBA returns an owned approved
snapshot; an explicit authorization deadline adds a store-clock CAS that
preserves the state and its original TTL. Precommit failures can retry. After
successful issuance, the durable consumption fence rejects another redemption.

## Rust port contract

- `DeviceGrantService::approve` and `deny` accept `PreparedDeviceDecision`
- `DeviceStateStorePort::claim_decision` must atomically check the supplied
  state revision and live user-code-to-device mapping before applying a claim
- `replace_by_device_hash` returns `DeviceStateReplacement<V>`; only its
  `Applied` variant contains the adapter's acknowledged written snapshot
- CIBA exposes `prepare_decision` / `decide_prepared` alongside the convenience
  decision and polling methods

If a Device user-code mapping disappears or is replaced while the old state
remains live, the decision CAS rejects it. Exhausting conflict retries returns
HTTP 503. The durable approval receipt binds the decision independently of
transient-state cleanup.

## Tests

The focused tests are `ciba_decision_preparation` in `nazo-auth`, the Device
application unit tests and `cross_device_application` in `nazo-oauth-server`,
and `ciba_device_contract` in `nazo-valkey`. They cover normal call order,
audit-before-write, preparation expiry, identity/CAS conflicts, changed or
missing user-code mapping, owner handover, unknown writes, exact persisted
versions and absolute deadlines. The Valkey target requires an explicitly
configured isolated `VALKEY_URL`.
