# Workspace Architecture

## Design Rule

NazoAuth is a Cargo Workspace deployed as one modular-monolith server. Crates
exist to enforce a domain, infrastructure, transport, or security boundary;
they are not divided one crate per RFC. Calls between crates remain ordinary
in-process Rust calls. The design does not use a dynamic-library plugin ABI,
RPC, an event bus, a command bus, or layers whose only job is forwarding.

The root manifest is a virtual workspace with resolver 3 and currently has 21
members. This repository releases the `nazoauth` application composition root.
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
- `authorization-server` does not depend on Actix, native launchers, or database/state drivers.
  Valkey, Fred, or rows.
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
- a default inherited state;
- `desired_state`: `inherit`, `enabled`, or `disabled`;
- actual state: `Disabled`, `Starting`, `Enabled`, `Draining`, or `Failed`;
- a `DisablePolicy`: immediate, finish executing requests, drain stored
  transactions with a bound, or not runtime-disableable.

An administrator PATCH changes only desired state and returns `202 Accepted`.
The UI must show the request as pending until actual state and revision confirm
completion. Desired state is durable; actual state is reconciled by each
server instance.

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
