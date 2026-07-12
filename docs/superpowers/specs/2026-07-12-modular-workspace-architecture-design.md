# NazoAuth Modular Workspace Architecture Design

**Date:** 2026-07-12  
**Status:** Revised after final architecture review  
**Backend branch:** `codex/modular-workspace-architecture`  
**Frontend branch:** `codex/runtime-module-admin`  
**Baseline:** `413e18f`

## 1. Objective

Rebuild NazoAuth as a Cargo Workspace modular monolith with compiler-enforced
domain, infrastructure, security, and failure boundaries while keeping the
normal request path short and directly auditable.

The result must support continued OAuth, OpenID Connect, FAPI, CIBA, and RFC
work without introducing dynamic libraries, RPC, a message bus, a command bus,
or forwarding-only facade, manager, controller, bridge, or orchestrator layers.
Non-core protocol capabilities are compiled into the one server binary and may
be activated or drained at runtime when their state semantics permit.

The architecture changes in one coordinated backend/frontend cutover using one
branch and Draft PR per repository. Internal commits remain small enough to
verify and review. No old/new compatibility facade or duplicate production
runtime remains in the final trees.

The project has not been formally released, so internal Rust APIs may change.
Runtime protocol and data compatibility remain mandatory except for deliberate,
tested, documented additions such as runtime module control.

## 2. Verified Baseline and Review Decisions

- The root package currently owns almost all protocol, identity, Actix,
  PostgreSQL, Valkey, key-management, and deployment dependencies.
- `support::prelude` re-exports Actix, Diesel, Fred, rows, schema, settings,
  cryptography, and helpers through a single global namespace.
- `AppState` exposes the full database pool, Fred client, complete settings, and
  key store to ordinary handlers. `Settings` spans roughly sixty unrelated
  values.
- Protocol decisions, persistence, and HTTP presentation coexist in endpoint
  files, several of which exceed one thousand lines.
- Resource-server core already has its own token and confirmation wire types.
  Its Actix/Tower/Tonic adapter module is the only framework coupling. Tower and
  Tonic are otherwise used only by adapter tests, so those historical adapters
  and direct dependencies can be deleted.
- `nazo-fapi-http-signatures` depends only on framework-neutral
  `httpsig`, `sfv`, `sha2`, `subtle`, `thiserror`, and `url`. It is a real,
  independently testable HTTP protocol primitive and will be retained under
  the neutral name `nazo-http-signatures`; FAPI policy remains in auth.
- Key generation, lifecycle, prepublication, activation, rotation, JWKS,
  external-command signing, file persistence, and the lifecycle background task
  already form a real key-security boundary and will move to a dedicated crate.
- Existing feature flags are scattered between configuration, metadata,
  routes, and handlers. There is no persisted desired-state or actual-state
  model for runtime activation.
- Several CI path filters omit `crates/**`.
- CI and the builder container pin Rust 1.96 while the locally verified current
  stable toolchain is Rust 1.97.0.
- On stable 1.97.0 the baseline passes format, workspace check, Clippy with
  warnings denied, and 1,977 tests. `cargo audit` reports no known
  vulnerability. `cargo deny` passes with duplicate-version warnings.

## 3. Design Rule

Every new crate, trait, registry, service, DTO, or adapter must satisfy at least
one current, demonstrable need:

1. isolate an external technology dependency;
2. establish a domain, security, or failure boundary;
3. prevent an invalid dependency;
4. provide actual reuse or independent testability;
5. support necessary runtime capability selection.

It must also avoid an unnecessary hop on the normal request path. Field-for-
field duplicate DTOs, one-implementation traits without an isolation purpose,
workspace-wide preludes, and `common`, `shared`, or `utils` dumping grounds are
forbidden. A small explicit wire-type duplicate is preferable to coupling an
independent crate to an authorization-server domain.

## 4. Compatibility Invariants

The refactor must not unintentionally change:

- HTTP methods, routes, endpoint URLs, or initial route/capability conditions;
- configuration keys, environment variables, defaults, precedence, validation,
  or unknown-key rejection;
- PostgreSQL schema content, stored formats, existing migration files, or
  migration order;
- Valkey keys, payloads, TTLs, Lua behavior, atomicity, or fail-closed behavior;
- access-token, ID-token, logout-token, JARM, introspection, or other claims;
- OAuth/OIDC error codes, status codes, headers, JSON, redirects, or browser
  responses;
- discovery, authorization-server, protected-resource, or JWKS metadata;
- OIDC, FAPI, CIBA, Device, DCR, SCIM, identity, session, or admin behavior.

Existing migration files are immutable. New additive migrations may support an
explicit new requirement only when code, rollback, upgrade, documentation, and
tests ship together. Runtime module control is such an explicit addition.

Contract tests must capture the existing observable behavior before the owning
implementation moves.

## 5. Target Workspace

```text
Cargo.toml
Cargo.lock
rust-toolchain.toml
crates/
  auth/
  identity/
  resource-server/
  http-signatures/
  key-management/
  postgres/
  valkey/
  http-actix/
  server/
migrations/
tests/
docs/
```

The root manifest becomes a virtual workspace using resolver 3. Workspace
package metadata, dependencies, lints, and release profiles are centralized.
`nazo-server` is the default member. The primary deployed binary remains
`nazo-oauth-server`.

Migration, keyctl, and OIDF seed binaries remain in the server package unless
dependency measurements prove that one materially pollutes the service build.
No separate tools crate is planned.

No target crate is created empty. Each appears in the commit that moves or adds
its production responsibility and tests.

## 6. Crate Responsibilities

### 6.1 `nazo-identity`

Owns users, tenants, organizations, login, sessions, MFA, passkeys, email
verification, federation, external identity links, subject claims,
authentication context, and SCIM identity application logic.

It has no dependency on `nazo-auth`, Actix, Diesel, Fred, or database rows. It
defines only the infrastructure ports needed to isolate identity persistence,
session storage, email delivery, and external federation providers. Protocol
callers receive minimal principal, subject-claim, and authentication-context
types rather than complete user records.

### 6.2 `nazo-auth`

Owns OAuth 2.x, OAuth 2.1-aligned behavior, OIDC, FAPI 2.0, FAPI-CIBA,
authorization, token issuance, grants, client policy, claims, metadata,
authorization details, sender constraints, security profiles, protocol errors,
and application policy.

It directly depends on the minimal public API of `nazo-identity`. The dependency
is one-way: `nazo-auth -> nazo-identity`. Auth services may directly call an
identity service where the protocol flow needs it; no application, bridge,
facade, or orchestrator crate is inserted.

It must not depend on Actix, Diesel, diesel-async, Fred, PostgreSQL schema or
rows, server configuration loading, `HttpRequest`, or `HttpResponse`.

Auth also owns the concrete runtime RFC module registry because module
dependencies, draining rules, and metadata capabilities are protocol policy.
The server constructs it; HTTP reads its immutable snapshots.

### 6.3 `nazo-resource-server`

Owns framework-independent JWT access-token verification, issuer, audience,
scope, confirmation claims, DPoP, sender constraints, authorization results,
and resource-server errors.

It depends on neither `nazo-auth` nor `nazo-identity` and on no web framework.
Its small wire types remain local even when structurally similar to auth token
types. Actix integration moves to `nazo-http-actix`.

The historical Tower/Axum and Tonic adapters, tests, documentation, exports,
and direct `tower`/`tonic` dependencies are deleted. No compatibility feature
flag is retained.

### 6.4 `nazo-http-signatures`

Owns reusable, framework-neutral HTTP Message Signatures, Structured Fields,
Content-Digest, canonicalization, signing-base construction, and verification
primitives. It is the renamed existing package, not a new abstraction.

It contains no Authorization Server/FAPI profile policy. `nazo-auth` selects
when and how the primitive is required. `nazo-key-management` supplies the
actual signing implementation where a message signature uses managed keys.

### 6.5 `nazo-key-management`

Owns key generation, lifecycle states, prepublish/active/grace/retired
transitions, rotation, JWKS material, local signing and verification, external-
command signing, future KMS/HSM adapters, key persistence/loading, and lifecycle
background tasks.

`nazo-auth` defines the minimal signing contract and purpose-specific signing
requests it needs. `nazo-key-management` implements that contract and therefore
depends on auth. ID tokens, access tokens, JARM, logout tokens, and HTTP message
signatures use explicit signing purposes; a generic unscoped key handle may not
silently authorize every use.

### 6.6 `nazo-postgres`

Owns Diesel schema, pool, rows, SQL, repository implementations, migrations,
transactions, and explicit row-to-domain conversion. Database rows never leave
this crate.

Required multi-write atomicity uses one PostgreSQL transaction. Existing
migrations remain byte-for-byte unchanged. The runtime-module desired-state
addition receives a new migration rather than editing history.

### 6.7 `nazo-valkey`

Owns Fred, connection management, key construction, serialization records,
TTLs, Lua, replay/session/short-lived-state storage, rate-limit counters, and
atomic compare/set/delete mechanisms. It implements auth and identity store
ports and never constructs an OAuth error or HTTP response.

Business policy remains outside this crate: thresholds, rejection decisions,
nonce consumption timing, session rotation permission, and RFC activation are
owned by auth or identity. Valkey executes storage operations requested by
those policies.

### 6.8 `nazo-http-actix`

Owns routes, extractors, form/query/header/cookie parsing, CORS, middleware,
proxy-derived context, domain/application-error presentation, Actix resource-
server integration, and the existing protocol-level response when a capability
is disabled or draining.

It contains no Diesel query, Fred command, token-claim construction, protocol
policy, identity persistence, or key lifecycle logic. A normal handler is:

```text
parse request
-> load one immutable active-module snapshot or focused service
-> call AuthService or IdentityService directly
-> map the result
```

It does not depend directly on Diesel or Fred.

### 6.9 `nazo-server`

Is only the composition root: configuration loading/validation, focused
settings construction, concrete adapter initialization, identity/auth/resource
service construction, runtime registry construction, background tasks,
observability, HTTP startup, and operational binaries.

One top-level composition aggregate is allowed here:

```rust
struct AppModules {
    auth: AuthServices,
    identity: IdentityServices,
    runtime_modules: RuntimeModuleRegistry,
}
```

The aggregate, full configuration, PostgreSQL pool, and Fred client are never
injected into an ordinary handler or domain service. Handlers receive only a
focused service and, when required, the runtime snapshot handle.

## 7. Exact Cargo Dependency Direction

```text
nazo-auth            -> nazo-identity, nazo-http-signatures
nazo-postgres        -> nazo-auth, nazo-identity
nazo-valkey          -> nazo-auth, nazo-identity
nazo-key-management  -> nazo-auth
nazo-http-actix      -> nazo-auth, nazo-identity, nazo-resource-server
nazo-server          -> all concrete crates required for composition
```

`nazo-http-signatures` is used only by crates that need its primitive. The
resource-server has no auth or identity edge.

Forbidden edges include identity to auth, resource-server to auth/identity,
auth to Actix/PostgreSQL/Valkey, and http-actix to Diesel/Fred. Circular
dependencies, cross-crate glob re-exports, and workspace-wide preludes are
forbidden.

## 8. Shortest Request and Error Flow

The standard path is:

```text
Actix handler
-> AuthService or IdentityService
-> Repository, Store, or Signer
-> typed result
-> Actix presenter
```

A combined authentication/authorization flow may call directly:

```text
Actix handler
-> AuthService
-> IdentityService
-> IdentityRepository
-> AuthService result
-> Actix presenter
```

No Controller, Facade, Manager, UseCase wrapper, application orchestrator,
command bus, event bus, or repository service is added.

Transport errors, OAuth/OIDC protocol errors, identity policy errors, storage
availability errors, consistency conflicts, and internal defects remain
distinct. Core and adapter crates never return `HttpResponse`. The Actix
presenter preserves the exact public status, error code, headers, JSON,
redirect, and browser response. Internal errors retain sources for redacted
logs and tracing.

## 9. Trait, Dispatch, and Capability Rules

Traits are limited to real dependency inversion: repositories, Valkey stores,
signers, email delivery, external federation providers, clocks, and test
substitutes. A trait must isolate infrastructure, cross a required dependency
direction, have multiple real implementations, or be replaceable in tests.

Protocol design defaults to static, auditable forms:

- grants use a typed enum and exhaustive match;
- security profiles use enums and static policy;
- built-in client authentication uses a fixed ordered chain;
- authorization details use a registry keyed by the actual `type` extension
  point because multiple independently validated types already exist;
- metadata is built from one typed capability snapshot, not contributor traits
  mutating shared JSON;
- sender constraints use an explicit static policy composition;
- concrete structs and static dispatch are preferred over `Arc<dyn Trait>`.

Future RFC work may extend these enums or the authorization-details registry.
No general plugin framework is created in advance. A new registry is permitted
only when a second real runtime-selected implementation proves the need.

## 10. Runtime RFC Module Activation

“Hot activation” means compiled into the same binary and activated, drained, or
disabled at runtime. It never means loading or unloading a Rust dynamic library.

### 10.1 Core and Optional Capabilities

Core services are never hot-disabled: the Authorization Server and Token
Endpoint frameworks, client-authentication mechanism, identity/session base,
key resolution/signing base, metadata construction, PostgreSQL, Valkey, and the
Actix server.

The first concrete `ModuleId` enum covers existing optional behavior and
independently controllable grants:

```text
DeviceAuthorization
TokenExchange
JwtBearerGrant
Ciba
DynamicClientRegistration
RequestObjects
Jarm
AuthorizationDetails
HttpMessageSignatures
Scim
NativeSso
FrontchannelLogout
SessionManagement
```

PAR remains a core endpoint because current FAPI and authorization behavior
already relies on it broadly. Legacy audience compatibility is policy, not a
module. Authorization-server FAPI profiles remain startup security policy in
this cutover: hot-downgrading a profile could invalidate in-flight authorization
and client policy. Optional capabilities required by a profile cannot be
disabled while that profile is active.

### 10.2 Concrete Registry, Not a Plugin Platform

`nazo-auth` contains one concrete `RuntimeModuleRegistry` with:

```text
ModuleId
ModuleState: Disabled | Starting | Enabled | Draining | Failed
ModuleDependencies
ActiveModuleSnapshot
```

It uses explicit enum matches. Stateless modules use an atomic capability bit
and service handle; they do not implement a lifecycle trait. Only a module with
an owned background task or resource lifecycle may gain a small lifecycle
implementation. There is no plugin manager, capability manager, module facade,
event bus, or command bus.

An `ArcSwap`-style immutable snapshot lets requests load one snapshot without a
long-held lock. A started request safely retains its old snapshot; new requests
observe the newly published state.

### 10.3 Desired State, Actual State, and Management API

Desired state is durable PostgreSQL data. A new additive migration creates:

- `runtime_module_desired_states`, keyed by `module_id`, with desired enabled
  state, optimistic revision, actor, reason, and update time;
- `runtime_module_state_events`, an append-only audit trail containing actor,
  reason, previous state, requested state, revision, and timestamp.

When no persisted override exists, existing configuration flags determine the
desired state, preserving current startup behavior. An override wins until an
administrator explicitly resets it to configuration default.

The existing same-origin management frontend controls modules through these
new backend routes:

```text
GET   /admin/runtime-modules
GET   /admin/runtime-modules/events
PATCH /admin/runtime-modules/{module_id}
POST  /auth/me/mfa/step-up
```

Read routes require an active administrator with `admin_level >= 2`. The PATCH
route additionally requires the existing CSRF protection and a session whose
`amr` contains `mfa` with `auth_time` no more than five minutes old. The step-up
route verifies the administrator's configured TOTP or backup code through the
identity service, atomically rotates the session/CSRF token, and updates
`auth_time`/`amr`; it never receives or returns module state.

The PATCH body is explicit and concurrency safe:

```json
{
  "desired_state": "enabled",
  "expected_revision": 7,
  "reason": "Enable CIBA after production readiness validation",
  "cascade": false
}
```

The authenticated user identity supplies the audit actor; the client cannot
choose it. Reason is required and bounded. The auth service validates module
identity, dependency/cascade rules, and transition legality, then the
PostgreSQL adapter applies desired state and the audit event in one compare-
and-swap transaction. Repeating the same desired state is idempotent; a stale
revision returns a typed conflict mapped to HTTP 409.

The list response exposes only operational state needed by the UI: module id,
description, desired source/state, actual state, revision, dependencies,
dependents, allowed actions, transition time, drain deadline, and redacted
failure status. The events response is paginated and contains actor identity,
reason, before/after state, revision, and timestamp, never secrets or raw
configuration.

Existing administrator-level mutation is hardened with an explicit hierarchy:
an administrator cannot grant a level at or above their own, alter an
administrator at or above their own level, or lower/disable their own account.
Without this rule a level-1 administrator could self-elevate and bypass the
module-control boundary. The behavior change is security-motivated and receives
negative authorization tests and documentation.

Each server instance periodically reconciles desired state in dependency order
and records its actual in-memory state and revision in metrics/logs. The current
deployment is single-instance. In a future multi-instance deployment, rollout
verification must wait until every instance reports the same desired revision;
within each instance, metadata and behavior switch atomically.

### 10.4 Enable and Disable Semantics

Enable flow:

```text
Disabled
-> validate configuration and dependencies
-> validate schema/storage readiness
-> initialize owned resources
-> start owned background task, if any
-> health check
-> atomically publish service handle and metadata capability
-> Enabled
```

Support is never advertised before the service is ready.

Disable flow:

```text
Enabled
-> atomically remove metadata and admission of new work
-> Draining
-> allow defined existing work to complete or expire
-> stop owned background task/resource
-> Disabled
```

Static Actix routes remain registered. A handler loads the snapshot and returns
the same protocol-level disabled response captured from the current feature-
flag behavior. The router is never rebuilt at runtime.

Stateful rules are explicit:

- CIBA and Device stop new authorization requests while existing identifiers
  may be verified/polled until their recorded TTL expires;
- DCR stops new registrations while management of already issued registration
  access tokens drains according to their existing validity;
- JARM and authorization details stop new authorization transactions while
  stored in-flight transactions complete with the policy recorded at creation;
- SCIM, Token Exchange, JWT Bearer, Native SSO, session management, and HTTP
  signatures allow already executing requests to finish but reject new work;
- cleanup needed by legacy state remains active until that state expires.

Enabling fails if a dependency is unavailable. Disabling a module required by
an enabled module or active security profile fails unless an explicit,
dependency-checked cascade is requested. No unknown dependency is implicitly
enabled.

### 10.5 NazoAuthWeb Management Experience

`D:\self\NazoAuthWeb` is part of this delivery. Work starts from the latest
`origin/main`, which already contains the merged Device, CIBA, and browser-
credential-boundary work. It receives its own branch and coordinated Draft PR,
cross-linked to the NazoAuth PR.

The existing `/admin` console gains a Runtime Modules section visible only to
`admin_level >= 2`. It calls the backend routes directly through the existing
same-origin `apiFetch`, cookie, and CSRF mechanism. It does not persist session,
MFA, desired-state, or audit material in browser storage.

The page displays desired versus actual state, revision, dependencies,
dependents, transition/drain status, and redacted failures. Every change
requires a reason, dependency impact preview, explicit confirmation, and current
revision. The UI never reports success optimistically; it reloads authoritative
state. HTTP 409 triggers a visible refresh/conflict flow. A step-up-required
response opens an MFA dialog, calls the step-up endpoint, then requires a fresh
confirmation rather than replaying the mutation automatically.

While a module is Starting or Draining the panel polls with bounded backoff and
stops when stable or when the page is hidden. Failed state is visible without
leaking configuration or stack traces. Cascade is default-off and requires a
second explicit dependency summary.

The current `src/pages/Admin.tsx` exceeds 2,500 lines. Adding another inline
tab would deepen an existing maintainability problem, so it is split by real UI
responsibility into focused admin panels (users, clients, access requests,
grants, and runtime modules) with shared layout primitives only where existing
duplication proves them. Panels call `apiFetch` directly; no frontend service,
manager, command bus, or field-for-field duplicate model layer is added.

## 11. Metadata Consistency

Discovery and metadata are pure functions of one typed
`ActiveModuleSnapshot` plus immutable server/profile configuration:

```text
RuntimeModuleRegistry snapshot
-> ActiveCapabilities
-> typed MetadataDocument
-> serialized HTTP response
```

Modules never mutate shared JSON. Grant types, endpoints, authorization-details
types, algorithms, CIBA, Device, DCR, and profile capabilities change in the
same atomic snapshot as request admission. Conflicting capability construction
is a startup/reconciliation error, not last-write-wins behavior.

## 12. Transactions, Concurrency, and Failure Semantics

PostgreSQL atomicity remains PostgreSQL transactions. Valkey atomicity remains
single commands or reviewed Lua. The design does not claim a distributed
transaction.

Every cross-system operation documents and tests ordering, partial-success
windows, compensation, retry/idempotency, and fail-closed behavior. Existing
authorization-code, refresh-token, MFA session rotation, replay, logout outbox,
DPoP, CIBA/Device, and signing invariants receive targeted concurrent and fault
tests before and after their move.

Newly found concurrency, transaction, or partial-success defects are reproduced
and fixed in this branch. Blocking password hashing, filesystem access, and
external signing remain off async executor threads or use bounded blocking
execution. Configuration and module snapshots are immutable; mutable key state
has one narrowly scoped concurrency-safe owner.

## 13. Compatibility Contract Tests

Before moving an implementation, tests record:

- the complete method/route inventory and initial conditional behavior;
- the canonical configuration key set, values, defaults, precedence, and
  invalid-input behavior;
- migration filenames, checksums/order, fresh schema, and upgrade results;
- every Valkey key builder, representative payload, TTL, and Lua transition;
- token, authorization response, logout, and introspection claim fixtures;
- OAuth/OIDC error status, code, headers, body, and redirect fixtures;
- discovery, authorization-server, protected-resource, and JWKS metadata;
- CIBA, Device, PAR/JAR/JARM, DPoP, mTLS, userinfo, introspection, DCR, SCIM,
  session, identity, and admin behavior;
- runtime module transition, dependency, metadata atomicity, drain, audit,
  restart, idempotency, and concurrent-update behavior.

Tests compare observable values rather than internal paths. Existing coverage
moves to the owning crate and is not weakened or discarded.

## 14. One-Cutover Implementation and Push Strategy

One branch and Draft PR per repository, multiple logical commits, and one final
coordinated production cutover are used. Draft PRs are created early rather
than after the entire rewrite, allowing CI feedback throughout.

Commit/migration sequence:

1. add compatibility contracts, workspace lint policy, CI path coverage, and
   exact Rust toolchain pin;
2. extract the framework-independent resource-server and delete Tower/Tonic;
3. rename and verify the independent HTTP Signatures crate;
4. extract key-management and purpose-scoped signing;
5. extract identity domain/services and SCIM identity logic;
6. establish auth with the direct identity dependency and move protocol policy;
7. extract PostgreSQL rows/repositories/transactions and add the new runtime-
   module desired-state migration;
8. extract Valkey mechanisms and remove business policy from its boundary;
9. reduce Actix handlers to parsing, direct calls, and presentation;
10. replace giant settings/state with focused configuration/services and build
    the server composition root;
11. implement concrete runtime module snapshots, persistence, privileged Admin
    API, MFA step-up, dependency validation, drains, and metadata atomicity;
12. branch NazoAuthWeb from latest `origin/main`, split the giant admin page by
    real responsibility, and implement the module status/audit/control UI;
13. delete the old Rust root monolith, prelude, glob re-exports, duplicate
    helpers, dead code, unused dependencies, and obsolete tests;
14. update both repositories' CI, containers, deployment, configuration,
    architecture, frontend, security, and operations documentation;
15. run all local gates for both repositories and complete coordinated
    production/conformance acceptance.

After the first compiling boundary and targeted fmt/check/clippy/test pass, push
the NazoAuth branch and open its Draft PR. Create and push the NazoAuthWeb Draft
PR as soon as its first tested management slice exists. Cross-link both PRs,
push each subsequent complete locally tested phase, and inspect CI. The final
production deployment uses the exact pair of commits that passed their complete
local gates.

## 15. Toolchain, Dependency, and Supply-Chain Policy

`rust-toolchain.toml`, CI, and `Containerfile` pin exact Rust 1.97.0, the current
verified stable baseline, rather than a floating `stable` tag. An automated
update PR must change all three together and run the complete workspace gate.

Workspace dependencies have one canonical version/feature declaration and are
used only by crates that need them. Compatible latest stable upgrades require
official changelog/migration review, `Cargo.lock` update, and the full test
suite. Duplicate versions are reduced where upstream compatibility permits;
remaining duplicates are understood and governed.

Dependabot covers Cargo, GitHub Actions, containers, and Python locks. CI covers
`crates/**` and runs dependency review, `cargo audit`, `cargo deny`, CodeQL,
SBOM generation, container vulnerability scanning, and workspace quality gates.

## 16. Verification and Release Flow

Local completion requires fresh successful runs of:

```text
cargo fmt --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
```

All locally executable unit, integration, real HTTP E2E, migration, security,
concurrency/load, fault-injection, container-build, and local consistency suites
also run. A failure is root-caused, fixed with a regression test where
applicable, and rerun.

NazoAuthWeb must freshly pass:

```text
npm ci
npm run lint
npm run build
npm test
```

Frontend tests cover privilege visibility, state rendering, reason and
confirmation requirements, MFA step-up without automatic mutation replay,
revision conflicts, dependency/cascade display, polling termination, redacted
failures, and the browser credential-persistence policy.

After local verification:

1. identify the exact NazoAuth and NazoAuthWeb Draft PR head commits;
2. inspect `hostinger` and retain a verified rollback version;
3. deploy those exact backend/frontend heads to `auth.nazo.run`, including
   additive migrations and the same-origin management UI;
4. verify both running commit SHAs, process, logs, PostgreSQL, Valkey, TLS,
   health, management authorization/step-up, discovery, JWKS, authorization,
   token, PAR, CIBA, userinfo, and introspection;
5. repair or roll back a failed deployment before conformance testing;
6. run the host-local complete OIDF matrix;
7. run the official complete OIDF matrix against `https://auth.nazo.run`;
8. repair all checks on both PRs and update both descriptions with actual
   evidence and their paired commit;
9. mark both Ready for Review only when all gates pass; never merge
   automatically.

OIDF acceptance requires zero failed modules, condition failures, or unexpected
warnings, REVIEW states, or skips. Existing expected REVIEW/SKIPPED outcomes
must be in a version-controlled allowlist bound to an exact suite version,
plan/profile/module, and reason. The allowlist may not expand to mask a
regression and may not exceed baseline counts. Evidence binds deployed commit,
host-local run, official plan IDs, and PR-check commit.

## 17. Acceptance Criteria

Completion requires all of the following:

- crate responsibilities and exact dependency directions match this design;
- auth has no Actix, Diesel, Fred, or database-row dependency and directly uses
  only identity's minimal public API;
- identity has no auth dependency;
- resource-server has no auth, identity, or Web-framework dependency;
- Tower/Axum/Tonic adapters, dependencies, tests, docs, and exports are gone;
- HTTP Signatures remains an independently tested neutral primitive;
- key-management is a purpose-scoped security boundary;
- PostgreSQL rows do not leave `nazo-postgres`;
- Valkey owns mechanisms, not business policy;
- the giant prelude, glob re-exports, giant AppState/Settings, and miscellaneous
  support layer are gone;
- normal requests have no forwarding-only abstraction layers;
- traits, registries, and dynamic dispatch satisfy the rules in this design;
- optional runtime modules activate/drain atomically without metadata drift;
- desired state persists and all module changes are authorized, audited,
  idempotent, dependency-checked, and concurrency-safe;
- the NazoAuthWeb administrator UI enforces visibility, reason, confirmation,
  MFA step-up, conflict handling, dependency display, and no credential/state
  persistence in browser storage;
- the oversized frontend Admin page is split into focused responsibility-based
  panels without adding a forwarding service layer;
- all compatibility contracts and local quality/integration/security/migration/
  concurrency/fault/container gates pass;
- `hostinger` runs the final paired backend/frontend PR heads and public
  critical endpoints plus management controls pass;
- host-local and official OIDF full matrices meet the stated acceptance rule;
- checks on both PRs pass and both descriptions match observed evidence.

The governing rule is: split every real boundary, keep direct calls and static
types on the core path, compile optional RFCs into the one binary with atomic
runtime activation, and delete every abstraction that does not prevent a
demonstrable dependency, security, failure, or reuse problem.
