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

## Device approval

`DeviceGrantService::prepare_decision` returns `PreparedDeviceDecision<V>`.
Its private fields bind the user code, resolved device hash and exact storage
snapshot. The application may inspect its payload for audit and client lookup,
but cannot change or construct its storage identity. `approve` and `deny`
consume this preparation instead of resolving the user code again.

The approval sequence remains:

1. Atomically compare the state revision **and the live user-code mapping**,
   then claim the approval
2. Reload after a successful claim or stale-claim takeover before writing the
   PostgreSQL grant, so a paused worker observes an already transferred owner
   or completed decision
3. Persist the grant and CAS `grant_recorded=true`
4. Reuse the adapter's acknowledged written snapshot for the final CAS; check
   the current authorization expiry again, and atomically verify the mapping
   before removing it

Only step 4 avoids the read after a successful write. The claim-to-database
read is deliberately retained: a later failed CAS cannot undo a stale worker's
PostgreSQL grant write. The existing `Approving` recovery states and bounded
claim timeout are unchanged. This does not introduce a cross-store transaction
or claim that the existing load-to-grant race has been eliminated.

The Valkey adapter serializes a replacement once. On an acknowledged recorded
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

Existing `decide` and `decide_with_authorization_deadline` entry points still
prepare their own snapshot. The latter retains the caller-owned atomic
expiry fence. This change does not alter the separate authorization and
retention deadlines, or the ping-queue update performed with the decision CAS.

CIBA Approved polling still atomically consumes state before downstream token
issuance. Device Approved polling still retains state and delegates one-time
issuance to the durable token boundary. These existing, different failure and
retry contracts are not changed by decision preparation.

## Rust port/API changes

- `DeviceGrantService::approve` and `deny` now accept `PreparedDeviceDecision`
- `DeviceStateStorePort::claim_decision` must atomically check the supplied
  state revision and live user-code-to-device mapping before applying a claim
- `replace_by_device_hash` returns `DeviceStateReplacement<V>`; only its
  `Applied` variant contains the adapter's acknowledged written snapshot
- Unused `DeviceStateStorePort::consume_by_device_code` and
  `DeviceGrantRepositoryPort::client_by_id` were removed; no production caller
  used them. Token consumption and application client lookup retain their
  existing owners
- CIBA adds `prepare_decision` / `decide_prepared`; its previous decision and
  polling APIs remain available

These are source-level Rust port changes. The persisted Device/CIBA JSON
formats and normal HTTP request/response flows are unchanged. If a Device
user-code mapping disappears or is replaced while the old state remains live,
the decision CAS fails closed; exhausting conflict retries may now return
HTTP 503 instead of the previous missing-mapping HTTP 400. Adapter and test
implementations must be updated together; no database migration is required.

## Targeted evidence

The focused tests are `ciba_decision_preparation` in `nazo-auth`, the Device
application unit tests and `cross_device_application` in `nazo-oauth-server`,
and `ciba_device_contract` in `nazo-valkey`. They cover normal call order,
audit-before-write, preparation expiry, identity/CAS conflicts, changed or
missing user-code mapping, owner handover, unknown writes, exact persisted
versions and absolute deadlines. The Valkey target requires an explicitly
configured isolated `VALKEY_URL`; a skipped live-store fixture is not passing
storage evidence. Source-level command counts are not measured latency or
throughput results.
