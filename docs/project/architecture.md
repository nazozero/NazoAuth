# Workspace Architecture

## Design Rule

NazoAuth is a Cargo Workspace deployed as one modular-monolith server. Crates
exist to enforce a domain, infrastructure, transport, or security boundary;
they are not divided one crate per RFC. Calls between crates remain ordinary
in-process Rust calls. The design does not use a dynamic-library plugin ABI,
RPC, an event bus, a command bus, or layers whose only job is forwarding.

The root manifest is a virtual workspace with resolver 3. This repository releases the `nazoauth` application composition root.
Its CLI includes the version-coupled server and operator-task work; the
independently released host lifecycle controller lives in
[`nazozero/NazoAuthCtl`](https://github.com/nazozero/NazoAuthCtl) and consumes
the exact versioned `nazo-operator-protocol` contract from this repository.

Every direct child of `crates/` is named for its bounded responsibility.
Technology names appear only where the crate is a concrete adapter. Cargo
package names retain the `nazo-` namespace and do not determine directory names.

## Crate Responsibilities

| Directory | Cargo package | Responsibility |
| --- | --- | --- |
| `authorization-server-core` | `nazo-auth` | Framework-independent OAuth, OIDC, FAPI and CIBA authorization-server policy, protocol types, grants, claims, metadata capability projection, sender constraints, and security profiles. It does not depend on Actix, Diesel, Fred, database rows, or configuration loading. |
| `digital-credentials` | `nazo-digital-credentials` | Framework-independent credential and mdoc data, cryptographic, certificate, compression, and validation primitives shared by OpenID4VC issuance, verification, and key management. |
| `identity` | `nazo-identity` | Framework-independent users, tenants, organizations, login, sessions, MFA, passkeys, verification, federation, external identities, subject claims, and authentication context. It depends on `nazo-scim-events` for SCIM event types, not on `nazo-auth`, Actix, Diesel, Fred, or database rows. |
| `resource-server` | `nazo-resource-server` | Standalone JWT access-token and sender-constraint verification. It is independent of the authorization server, identity, and every Web framework. |
| `http-signatures` | `nazo-http-signatures` | Reusable HTTP Message Signatures, structured-field, content-digest, signing, and verification primitives. Authorization-server FAPI policy remains in `nazo-auth`. |
| `key-management` | `nazo-key-management` | Key generation, purpose-specific lifecycle, rotation, JWKS material, signing implementations, an external-signer port, and OpenID4VC signing material. The native host owns external-command execution and refresh scheduling. |
| `operator-protocol` | `nazo-operator-protocol` | Versioned signed control-operation requests, receipts, identity and recovery contracts shared by the runtime and NazoAuthCtl. It contains no host-execution adapter. |
| `scim-events` | `nazo-scim-events` | Framework-neutral SCIM security-event and delivery data types used by identity, persistence, and HTTP presentation. |
| `openid4vci` | `nazo-openid4vci` | Framework-independent OpenID4VCI issuance protocol types, validation, and transaction behavior. |
| `openid4vp` | `nazo-openid4vp` | Framework-independent OpenID4VP verifier protocol types, validation, and presentation behavior. |
| `persistence` | `nazo-persistence` | Database-neutral semantic persistence contracts and application-facing records, including tenant directory and protocol/credential stores. It contains no SQL, connection, transaction, or driver API. |
| `persistence-postgres` | `nazo-postgres` | Durable PostgreSQL adapter: Diesel schema and rows, pool, queries, repository implementations, explicit row/domain conversion, migrations, and transaction boundaries. Rows never leave this crate. |
| `state-store-valkey` | `nazo-valkey` | Atomic state-store adapter: Fred connection handling, stable keys and payloads, TTL, Lua operations, replay/session/short-lived protocol state, and rate-limit storage. It owns storage mechanics, not protocol or identity policy. |
| `runtime-capabilities` | `nazo-runtime-modules` | Runtime-controllable protocol capability identifiers, desired and actual lifecycle state, revision rules, immutable active snapshots, dependency checks, disable policy, request leases, and audit event types. It is not a generic plugin or miscellaneous-module crate. |
| `http-actix` | `nazo-http-actix` | Actix extraction, request context, CORS, middleware, security headers, protocol response presentation, and Actix-specific integration over application capabilities. It depends on `nazo-oauth-server`, does not query Diesel or Fred, and does not construct token claims. |
| `openid4vc-http-actix` | `nazo-openid4vc-http-actix` | Actix transport adapters for the OpenID4VCI and OpenID4VP cores, including their controller-protocol protected management surface. |
| `authorization-server` | `nazo-oauth-server` | Host-independent application capabilities: authorization and token flows, domain operations, typed contracts, semantic ports, and worker operations. It does not load process configuration, register Actix routes, open connections, or schedule native background tasks. |
| `authorization-server-postgres` | `nazo-oauth-server-postgres` | PostgreSQL provider: binds an existing pool and repositories to application persistence ports. Native startup, migration/operator execution, and pool construction belong to `nazoauth`. It has no Valkey dependency. |
| `authorization-server-valkey` | `nazo-oauth-server-valkey` | Valkey provider: composes tenant-scoped transient-state ports and namespace bindings from a supplied client, with no persistent-database dependency. The native launcher owns configuration and connection startup. |
| `authorization-server-object-store` | `nazo-oauth-server-object-store` | Concrete S3-compatible avatar storage, including credentials and request signing. The native host selects local or S3 storage and constructs the tenant binding. |
| `nazoauth` | `nazoauth` | Native host and production executable: configuration, launchers, tenant/bootstrap composition, HTTP wiring, CLI/operator tasks, TLS, process adapters, local storage, and background scheduling. It calls application capabilities and concrete infrastructure adapters. |

The historical Axum/Tower and tonic adapters are removed. Only Actix transport
integration is maintained. The generic resource-server core may use the
framework-neutral `http` types without becoming a Web-framework adapter.

## Dependency Direction

Dependencies point from policy consumers to stable domain APIs and from
infrastructure adapters to the ports they implement. The composition root is
the only package expected to see every concrete launch adapter. The manifests are the authority for individual direct dependencies. The main
ownership direction is:

```text
native host (nazoauth) -> application, HTTP adapters, infrastructure adapters
HTTP adapters         -> application capabilities and domain APIs
application           -> domain APIs and semantic ports
driver adapters       -> the ports they implement
```

`authorization-server` owns the application layer; `nazoauth` owns native
composition. A type using framework-neutral `http`, futures, or `Arc` does not
by itself create a native-host dependency. See each crate's `Cargo.toml` for
the current dependency edges rather than copying an exhaustive graph here.

The enforced prohibitions are more important than a broad graph:

- `identity` does not depend on `authorization-server-core`.
- `resource-server` does not depend on `authorization-server-core`, `identity`, or Actix.
- `authorization-server-core` does not depend on Actix, PostgreSQL, Diesel,
  Valkey, Fred, or rows.
- `authorization-server` does not depend on Actix, native launchers, or database/state drivers.
- `http-actix` does not depend on Diesel or Fred.
- no crate cycle, workspace-wide prelude, or cross-crate glob re-export is
  allowed.

The normal request path is deliberately short:

```text
Actix request -> canonical Host (and direct-TLS SNI) validation
              -> immutable TenantHostIndex -> tenant app-data container
              -> handler -> domain service / repository / store / signer
              -> typed result -> Actix presenter
```

The host index is published as a complete immutable snapshot. A request has no
second directory lookup and no default-tenant fallback; an unknown Host is
rejected before a tenant graph is injected. There is no controller/facade/
manager/orchestrator layer between the handler and its focused services. Traits
are reserved for a real dependency inversion: infrastructure, external
providers, clocks/test substitutes, or multiple genuine implementations.

## Runtime Modules

Optional protocol and product capabilities are compiled into the single
binary. Runtime enablement is capability selection, not dynamic code loading.
Routes remain statically registered so route shape and CORS/security middleware
cannot drift during a transition.

Each `ModuleId` declares:

- dependencies;
- an explicit persisted `desired_state`: `enabled` or `disabled`;
- actual state: `Disabled`, `Starting`, `Enabled`, `Draining`, or `Failed`;
- a `DisablePolicy`: immediate, finish executing requests, drain stored
  transactions with a bound, or not runtime-disableable.

An administrator PATCH changes only desired state and returns `202 Accepted`.
The UI must show the request as pending until actual state and revision confirm
completion. Desired state is durable; actual state is reconciled by each
server instance. Each one-second reconciliation pass reads the tenant's desired
state and this instance's actual state in one PostgreSQL snapshot. The snapshot
only skips already-settled modules whose dependency and admission checks still
hold; modules requiring action retain fresh reads and the revision-fenced state
machine. No durable snapshot is cached between passes.

Every asynchronous transition carries the desired-state revision. The worker
revalidates that revision before publishing an active snapshot, before
completing drain, and before persisting final state. A stale worker discards its
result rather than overwriting a newer administrator decision.

The audit stream distinguishes the management request from execution:

- `DesiredStateChanged`
- `TransitionStarted`
- `TransitionCompleted`
- `TransitionFailed`
- `DrainStarted`
- `DrainCompleted`
- `StaleTransitionDiscarded`

Enablement publishes capability and discovery metadata atomically only after
configuration, dependencies, storage, tasks, and health are ready. Disablement
first withdraws capability from metadata, rejects new work, and then follows
the module's declared drain policy. Existing transactions may continue only
where that policy explicitly allows it. Discovery is generated from one typed,
immutable active-capability snapshot; modules never mutate shared JSON.

## Configuration and State Injection

Configuration keys and environment precedence are validated at startup. The
composition root derives small immutable configuration values for each
consumer. A handler must not receive the complete settings object, PostgreSQL
pool, Valkey connection, key manager, or a global application state merely
because another handler needs it.

Top-level composition aggregates may exist while the process is assembled, but
they are not request dependencies. Focused injection is a compiler-enforced
boundary: metadata handlers receive metadata configuration, keys, and the
capability snapshot; session handlers receive session policy and session
storage; repositories are injected only into flows that query them.

## Token Issuance and Security State

Token issuance commits through `TokenIssuanceRepository`. Its two modes retain
only state required by their semantics:

- `Fresh` creates no `oauth_token_issuances` row. Refresh rotation/family
  changes, a first non-public subject binding when needed, and Required audit
  commit together. PreserveExisting also carries and locks its source family
  through commit, even though it writes no new refresh member. The refresh
  commit enum owns one original contract: new-family creation or an existing
  source with an optional replacement. Current AT/RT selections never rebuild
  that immutable contract. A client-credentials issuance ordinarily writes only audit.
- `SingleUse` retains a compact receipt under the 32-byte BLAKE3 grant fence,
  with the issued JTI, acceptance deadline and optional refresh family needed
  for replay handling. New receipts do not store user ownership. Grant expiry
  is rechecked in the transaction; expiry rolls it back and returns the healthy
  connection to the pool.

Every issuance reuses the access-token epoch read in the request's client
authentication snapshot; a later subject read never replaces that version. Its fixed salt/epoch projection preserves prepared-query
reuse while reading current values on every request. OIDC issuance with a public
subject also reuses the user epoch returned with the active subject claims in
`PreparedTokenSubject`. This
request-local snapshot belongs to the authorization core; its security version
is not serialized into the public subject claims. Non-OIDC user issuance reads only its user epoch and exact subject binding
in one narrow snapshot before signing. The commit
locks client then user and rechecks activity and these exact epochs. A
concurrent deactivate/reactivate cycle cannot admit an older signed snapshot.
Principal deactivation increments its epoch in the same database row update;
reactivation never resets it. Online token validation combines individual JTI
revocation with current principal activity and signed epoch checks in one read.
The offline signature verifier retains its existing offline-only guarantee.

`DbPool` records its creating runtime as the connection I/O owner. The issuance
transaction executes on that same runtime, so its sequential statements do not
repeatedly wake the HTTP worker runtime. Pure contract preparation still happens
before checkout. The request owns the transaction task through `JoinSet`:
cancellation aborts it, and `DiscardOnDrop` removes the physical connection unless
commit or rollback was confirmed. This preserves the transaction's lock order,
atomic audit append and rollback behavior without creating another runtime.

The audit adapter batches up to 64 events for at most 10 ms from the first
arrival; full batches and closed channels flush immediately. Standalone
Required records have a separate bounded channel and wait for the batch's
successful durable commit before callers continue. Queue saturation, channel
closure, worker termination and append failure return errors. Failed Required
batches report their first error without retrying or blocking subsequent
batches; caller cancellation never turns an unconfirmed append into success.
Other cross-store Required intents still precede their destructive mutations.
System tenant administrator changes register Required evidence and commit the
canonical `system_tenant_admin_updated` ledger event in the same PostgreSQL
transaction as the target role change. Its target tenant and explicit actor
source come from locked account facts; the HTTP adapter supplies only the
source IP hash. Tenant-local identity events omit a cross-tenant actor, while
the atomic ledger retains the complete actor and target attribution. The HTTP
handler preserves the audit preflight and does not append the outcome again.
Recovery Root approval and rotation retain their registered Required evidence
paths; their separate transactions are not made atomic by event registration.

PAR and consent are immutable preparation material. Their cache deletion is
post-commit cleanup, not authorization or cancellation authority. Explicit
approval, denial, and prompt-none compete for the same durable consumption
identities; prompt-none does not increment explicit approval counters. The
code and its payload are prepared in memory and bound to the fact. Only an
affirmative durable result permits code storage/publication. An unknown result
fails closed. A later code-store or response failure leaves a committed,
possibly undelivered decision; it never frees the fence or compensates the
grant, and retries do not promise recovery of the original response.

The audit guarantee covers committed decisions, including committed denials.
A crash before a decision takes effect need not preserve an attempted-decision
record. Chain construction and export derive from the same immutable fact;
export ACK cannot delete a fact before its business retention closes. No new
outbox or second audit copy is introduced. The concrete adapter's pending
indexes, retention cleanup, and chain entry checks own this lifecycle.

Telemetry retains its independent queue, FIFO whole-batch retry and overflow
behavior. Its counters exclude Required records. Both channels reuse the same
batch worker implementation, existing runtime, pool and ledger transaction;
a retrying Telemetry batch cannot block the Required channel. Bootstrap installs
their senders and readiness repository together in one process-lifetime owner.

Public subjects carry their existing user identity. Pairwise/non-public
subjects resolve through `oauth_subject_bindings`, keyed by tenant and subject;
repeated issuance reuses the relation without writing it again. Existing `sub`
values and internal-user confidentiality are unchanged. Bindings end with their
owning user, not with individual token expiry. Epoch-less tokens retain legacy
JTI revocation and issuance-based ownership during the remaining acceptance
window. Old records drain under their existing retention policy. Principal-wide
revocation enumerates only these legacy records and the separately owned
OpenID4VC preauthorized grants; new SingleUse receipts are excluded.

OIDC token preparation reads the active subject claims, their user epoch and
ownership of the exact token subject in one snapshot. The request-local
`PreparedTokenSubject` carries that checked subject and binding result; shared
issuance validates tenant, user and token-subject identity before reusing it.
It retains the authenticated client epoch and the claims snapshot's user epoch,
never refreshing an epoch independently of the claims it endorses. The final
principal locks, epoch checks and first-binding collision check remain mandatory.
Public subjects require no binding lookup; non-OIDC issuance retains its narrow
principal snapshot without reading a profile.

Device and CIBA SingleUse identities depend only on the immutable device code
or `auth_req_id`; tenant and client fences remain PostgreSQL-owned. Sender
proofs are still validated and constrain the issued tokens, but cannot create
another consumption identity. CIBA Approved polling returns an owned snapshot
and preserves the original TTL. Precommit failures remain retryable; only the
successful issuance transaction consumes the grant. An explicit authorization
deadline still uses the store-clock CAS before returning Approved. Healthy
postcommit replay returns `invalid_grant` without recovering the original
response or revoking another holder's tokens. A dependency outage can still
return 503 before replay detection.

This change alters the persisted Device/CIBA fence key format. Deployments
must drain old token requests and expire or invalidate pending old Device/CIBA
authorizations before switching to the new implementation. Old sender-derived
receipts must not be mixed with the new code-only identities. No compatibility
recovery layer or production state cleanup is performed by this change.

CIBA's retry boundary follows [CIBA Core §10.1 and §10.1.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0-final.html):
503 permits retry; an `auth_req_id` becomes invalid after successful redemption.

The generic path accepts no `Idempotency-Key`, stores no request digest or
response envelope, and implements no generic response recovery. Authorization
code, device, JWT Bearer and CIBA atomic consumption, refresh-family reuse and
bounded lost-response recovery, DPoP/mTLS binding, tenant isolation and Required
audit remain mandatory. OpenID4VC preauthorized issuance keeps its own storage.

OpenID4VC preauthorized transaction-code verification uses the host's shared,
bounded password verifier. The repository releases its read connection before
waiting for Argon2, then conditionally consumes the unchanged offer in one
statement. That write rechecks the database clock, tenant, code, verifier and
authorization snapshot; concurrent requests still have exactly one winner.
Verifier saturation returns storage unavailable rather than an invalid code.

Expired security state is reclaimed by a bounded host-owned worker: each
server process runs one maintenance worker, each batch is capped per
category, and refresh-token families are processed under the same advisory
locks writers use. Operational detail lives in
[ha-operations.md](../operations/ha-operations.md#security-state-maintenance).
Databases are created by the current migrations; pre-refactor schemas and
envelope-encrypted response rows have no read-back or upgrade path.

## Frontend Repository Discovery

The administration UI lives in a separate sibling repository named
`NazoAuthWeb`. Automation must discover it relative to the resolved backend
repository root, unless an explicit worktree path is supplied. Documentation
and scripts must never embed a workstation-specific absolute path.

Before a coordinated candidate build or deployment, resolve both worktrees:

1. Resolve each repository with `git rev-parse --show-toplevel` and reject a
   path that is not a Git worktree.
2. Verify the normalized `origin` URL is the expected NazoAuth or NazoAuthWeb
   repository; do not accept a same-named unrelated directory.
3. Build the current working-tree contents, including intentional uncommitted
   changes, and identify the produced server/UI artifacts by their content
   digests. Candidate validation must not require a commit or a clean worktree.
4. Select the frontend package manager from its lockfile and execute
   the scripts that actually exist in `package.json`. Do not assume an
   `npm test` script. Missing required lint, unit, browser-security, delivery,
   or build coverage is a repository defect to fix, not a check to silently
   skip.

Official release tagging and CI happen only after this candidate has passed the
real deployment and functional matrix. The live deployment wrapper consumes
released artifacts and never builds source; see
[deployment.md](../operations/deployment.md).

## Compatibility and Verification

Within an implementation refactor, preserve the selected current contracts:
routes, configuration, migration history, persisted data, transient-state
keys/payloads/TTL, token claims, protocol errors, discovery, and profile behavior.
Contract tests must be in place before moving an implementation across a
boundary. This does not promise compatibility with historical releases: before
0.5.0, unsupported configuration, state, and control-message formats are rejected
rather than implicitly converted. See the [update and recovery contract](../operations/one-click-update.md).

Production/test source boundaries, private-unit mounts, support seams, and
integration-test placement are normative in [testing.md](testing.md). The
static-contract gate enforces that structure across every workspace crate.

Use the commands and isolated service prerequisites in
[testing.md](testing.md#verification). Choose validation for the changed
boundary; source checks do not establish deployment, conformance, or load-test
results. Historical reports apply only to their recorded revisions.

The new refresh-family collision probe deliberately uses an uncached parameterized query: a named plan selected for an empty family table can retain a sequential scan after rapid growth. It still checks only the tenant/family primary key before any retirement or insertion; collision compromise and audit semantics are unchanged. Other typed principal and lock queries retain prepared-plan reuse.

### Shared session authority

Identity `SessionService` owns browser-session resolution, invalidation and
version-checked RP membership updates. The authorization-server resolver adapts
its result without maintaining a second storage/validation algorithm. Both
interactive and successful silent OIDC authorization bind the RP to the current
OP session before returning an authorization code; a missing session or failed
binding cannot return the code. A committed decision is not undone by a later
session-binding or response failure.

High-impact administration uses one identity-owned interactive-MFA predicate:
`mfa` plus `otp` or `recovery_code`, with an authentication age from zero through
300 seconds inclusive. Future authentication times do not count as completed
step-ups. The separate 30-second clock allowance for ordinary session metadata
is unchanged; endpoint-specific administrator levels remain separate policy.

Token-management authentication rejects an inactive requesting client immediately
after its authentication snapshot, before key resolution, cryptographic proof
validation or assertion consumption. Introspection and revocation share this
requester gate; the token issuer's own activity checks remain separate.


Native SSO exchange carries a separate family-level source fence into the
final destination issuance transaction. After destination writes and capacity
retirement, a source `FOR SHARE NOWAIT` lock rechecks tenant, user, source client,
revocation, reuse and both family/device-secret expiry using a fresh clock, and
holds through required audit and commit. Normal source member rotation remains
valid. Busy source locks return retryable dependency failure; invalid sources
roll back every destination write. Same-client capacity transfer accepts only
the exact active source retired by this transaction's successful UPDATE
RETURNING, with its original expiry and owner preserved under the row lock.
A device secret prepared before a failed commit cannot authorize an exchange
without its committed refresh family; its existing expiry bounds cache residue.

Host binding selects one immutable tenant runtime graph for request data and
CORS policy. Dynamic CORS uses that request's selected settings, including
synchronous preflight admission; missing selection denies the origin. Runtime
replacement affects subsequent requests without changing an in-flight policy.

Profile updates retain phone verification only when the current database row
is verified and its phone equals the newly stored phone, with nullable equality.
A stale profile snapshot cannot restore verification after a concurrent change.

Registration sends use one attempt owner for the email and peer cooldowns and
stored code. Code publication atomically checks the current email reservation
owner before SET EX, so a delayed hash cannot overwrite a later sender's code.
Cleanup compares that owner atomically, so a late SMTP failure
cannot remove a later sender's state. Cooldown durations and code expiry are
unchanged. This changes transient email-code records from raw hashes to owned
records: drain pending registration sends/codes before switching writers; old
unbound records fail closed without a compatibility fallback.

Tenant graph retirement synchronously aborts both module reconciliation and
CIBA ping loops before awaiting either join. Dropping the final lifecycle owner
also aborts still-owned loops; retained snapshots delay that final drop. Signing
key refresh uses its existing cooperative shutdown and completes current writes.

Credential issuance enforces the batch limit on validated holder bindings after
proof expansion and before nonce claiming. A configuration without proof types
and holder-binding methods issues its unbound credential without a proof nonce;
stray proofs remain invalid. The same rules apply to deferred preparation.

### Federation browser ownership

OIDC/social HTTP owns canonical browser-seed cookies and their secure/dev
attributes. Identity owns domain-separated tenant-and-seed hashing and passes
the expected digest through `FederationStatePort`. The Valkey adapter owns
atomic matching take: nonowners preserve raw state and expiry; only the matching
browser removes it before the existing typed and protocol checks. Callback
never rotates or clears the seed, so established-cookie flows can run in
parallel. Deployment cutover and the cold-start race are documented in
[external federation](../features/federation.md#browser-binding-and-callback-state).

### Short authentication validity boundaries

Passkey login uses the configured pending MFA session TTL until MFA is satisfied; remembered MFA and users without MFA retain the full session TTL. The login cookie and response presentation remain consistent with password login.

CIBA request validity starts after the mandatory audit intent and replay reservations complete. Creation and approval or denial enforce the original authorization expiry in the state-store atomic command, independently of the longer retention TTL. Expired-state cleanup retains its existing deletion semantics.

### Runtime construction and independent transitions

VCI and VP availability is immutable for each constructed tenant graph. Their desired history is retained, but an absent service has Disabled actual state, no request admission or advertisement, and cannot be enabled without constructing a new graph. Unavailable children do not block their dependencies. VP drain duration is the configured transaction TTL clamped to at least 30 seconds, independent of browser session TTL.

The tenant reconciler owns at most one transition future per module. A retained planning future reads joined desired and instance facts once per tick while other transitions continue, so a long stored-transaction drain does not hold up unrelated modules. Dropping the tenant worker drops all its owned planning and transition futures. Closing admission drains leases from every retained generation of that module, and SCIM remains enabled while its security-event child is draining.

### Resource token presentation

The shared Actix extractor rejects multiple physical Authorization headers, repeated decoded form token fields including blank values, and a selected header or form token combined with a query token. Query-only tokens remain unsupported. Invalid form input cannot be hidden by a valid header. UserInfo Bearer presentation rejects a token carrying a DPoP `jkt` even if it also carries an mTLS thumbprint; the generic resource verifier likewise requires `jkt` for DPoP presentation and compares proof HTTP methods exactly. Introspection and revocation metadata derive their supported authentication methods from the token endpoint policy with each management endpoint's exclusions.

MFA verification retains the confirmed TOTP credential row UUID as the generation proof. Remembered-device insertion takes a key-share lock on that exact row; backup-code regeneration takes an update lock on it after hashing. A retired generation cannot publish a remember cookie or replace a new generation’s codes. Clearing MFA uses READ COMMITTED and orders writes TOTP → backup codes → remembered devices → user; enrollment confirmation follows the same order.

Credential revocation’s scoped unknown-status exemption follows the successfully authenticated path anchor DER. Scoped anchors are considered before global anchors during the same path validation; an unrelated loaded or attached scoped certificate supplies no exemption. Known revocation and missing/stale required snapshots remain failures.

Local avatar upload synchronizes the candidate and its directory lineage through the configured storage root only. Deployment must precreate and durably provision that root and its parent entry before serving uploads; per-upload code does not claim durability or read permissions for unrelated OS ancestors.

MFA profile operations classify active or pending MFA state from one validated
session snapshot and check the account once. An active session with no pending
challenge returns the existing challenge-missing response without clearing
cookies; inactive or corrupt sessions are invalidated, while dependency failures
retain the browser session and return its unavailable response.
