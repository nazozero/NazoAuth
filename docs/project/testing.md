# Test Architecture

## Boundary

Production and test implementations are separate artifacts. A Rust file under
`crates/*/src` may contain runtime code plus only the minimum hooks required to
compile private-unit tests. It must not contain `#[test]`, `#[tokio::test]`, an
inline `mod tests { ... }`, a test fixture implementation, or a test-only helper
implementation.

Each crate uses this layout:

```text
crates/<crate>/
├── src/<module>.rs
└── tests/
    ├── unit/<module>.rs
    ├── unit/<module>/<concern>.rs
    ├── support/
    │   ├── fixtures/<concern>.rs
    │   └── ...
    └── <integration-target>.rs
```

- `tests/unit` contains private-unit tests mounted as children of their owning
  production module. The path mirrors the production module exactly once.
- `tests/support` contains fixtures, macros, schemas, and other test-only
  infrastructure shared by tests.
- `tests/support` may build fixtures, fakes, and infrastructure, but it must not
  parse a production protocol, reproduce a key format, implement a policy, or
  contain a second version of production behavior.
- top-level `tests/*.rs` files are Cargo integration-test targets. They test the
  crate through its public API and must not depend on private implementation.

Names such as `tests/source_mounted`, `tests/.../src`, `src/tests`, and repeated
`.../tests/.../tests/...` segments are forbidden. They describe a compiler
mechanism rather than the product or module responsibility.

## Mount Rules

A private-unit test uses an explicit, minimal mount in its owning module:

```rust
#[cfg(test)]
#[path = "../tests/unit/policy.rs"]
mod tests;
```

Do not compile a production source file into an integration test and do not
`include!` a test implementation into production source. Private-unit tests
belong in the mounted child module; reusable test infrastructure belongs in the
crate's test-support module. If a test can use the public API, make it an
integration test instead. If a behavior cannot be tested without duplicating
it, first move that behavior behind an owned production API.

`tests/support/seams` is forbidden. Test-only dependency composition belongs in
an explicitly named `tests/support` module mounted with `#[path]`; it must not
reimplement policy, parsing, key derivation, cryptography, or state
transitions. Tests that need raw persistence keys use the owning storage
crate's test harness so the derivation still has one implementation.

The only `cfg(test)` construct allowed under `src/` is a test module mount that
resolves into `tests/`; every other test-only implementation or import lives
under `tests/`.

## Enforcement

`python scripts/verify_static_contracts.py --check` enforces the physical
separation only; it does not freeze test file names, test function names, or
the internal layout of `tests/`. It rejects:

- executable tests (`#[test]`, `#[tokio::test]`, `#[actix_web::test]`) or
  inline test modules under `src`;
- any other test-only item under `src` — a `#[cfg(test)]` function, `impl`
  block, constant, import, re-export, or statement belongs under `tests/`
  (conditions that a feature flag can also enable, such as
  `#[cfg(any(test, feature = "..."))]`, remain production-possible);
- test files under `src` (`src/tests.rs`, `src/*_tests.rs`, `src/**/tests/`);
- a test-only module declaration without an external `#[path]` mount, or a
  test-only mount that resolves back into `src`;
- a production `#[path]` module remap that compiles a file outside `src`;
- a test file that reaches into `src` with `#[path]` or `include!`;
- missing mount targets.

Run the structure check before the Rust quality gate below.

## Verification

Use Rust 1.99.0, pinned in `rust-toolchain.toml` and the build images. The
workflow toolchain actions use the same release at an immutable revision. The executable CI definition
is [code-quality.yml](../../.github/workflows/code-quality.yml); it owns the
service versions, fixtures, and complete environment. Do not point these tests
at a deployment database or state store.

Construct PostgreSQL pools inside a Tokio runtime that lives at least as long
as the pool. Test-local pools can use the test runtime; a process-lifetime
shared audit fixture must retain its own runtime with its pool. Pure logic
tests should pass the configuration they use instead of constructing unrelated
database infrastructure.

The workspace suite requires isolated PostgreSQL and Valkey, a separate audit
test database (`NAZO_AUDIT_TEST_DATABASE_URL`), and the S3-compatible fixture
configured with `NAZO_TEST_S3_*`. Copy the workflow's other fixture settings,
including its state epoch and tenant/federation setup. The shared integration
fixtures run with `RUST_TEST_THREADS=1`.

```sh
python scripts/verify_static_contracts.py --check
python scripts/check_persistence_dependency_graph.py
cargo fmt --check
cargo clippy --workspace --all-targets --all-features --locked --keep-going -- -D warnings
cargo test --all-features --locked -p nazo-postgres --test migrations pending_migrations_create_all_runtime_module_state_tables
cargo test --workspace --all-features --locked --no-fail-fast
```

The migration test prepares the isolated schema before the full suite, as in
CI. The full suite collects failures across test targets in one run; any failed
target still fails the gate. For a focused change, run the owning package/test
target first; broaden
validation when the change crosses boundaries or leaves an unresolved risk.
Documentation-only changes need source/example/reference checks, not a Rust
build. A passed unit suite does not replace required HTTP, migration, recovery,
conformance, deployment, or performance evidence.

CI budgets Cargo build concurrency from the runner's available logical CPUs
and memory (3 GiB per build job). Shared-state tests remain serial. Schema
materialization uses the workspace suite's feature set to reuse its artifacts.
The audit backlog scale fixture vacuums its deleted rows at handoff; the
separate dead-prefix regression still creates its own ack-deleted prefix and
requires natural autovacuum recovery without manual vacuum of that lifecycle.

Targeted suites with their own entry points:

- `crates/identity/tests/unit/federation.rs` defines tenant-separated digest and
  legacy parsing checks. `crates/state-store-valkey/tests/federation_binding.rs`
  defines real-Valkey matching-take concurrency, exact raw/deadline preservation,
  matching-owner typed corruption and the single-EVAL call-path contract.
- `crates/nazoauth/tests/unit/http/auth/federation/browser_binding.rs` defines
  canonical cookie/security attributes, missing-cookie zero-store calls,
  backend failure mapping, OIDC/social attacker-to-other-browser rejection with
  subsequent owner completion, parallel established-cookie starts, and the
  fail-closed simultaneous cold-start race. HTTP completion fixtures use the
  isolated PostgreSQL and Valkey configured above; the state-only checks require
  Valkey. These focused cases supplement existing nonce, PKCE and provider
  mismatch regressions.

- `crates/persistence-postgres/tests/schema_cleanup.rs` exercises the
  inert-state migration's up/down data preservation, refusal of populated
  legacy state and schema drift, external dependency blocking, and retained
  tenant-composite foreign-key behavior. It uses transaction-local schemas
  in the isolated test database. Existing controller, recovery, MFA and client
  repository suites cover runtime behavior against the complete migration chain.
- `crates/nazoauth/tests/unit/http/token/authorization_code/identity.rs` covers
  real issuance with a hidden commit ACK, stable identity after cache restoration,
  fresh signed DPoP holder checks with missing or expired Pending payload, mTLS
  receipt matching after current binding is disabled, and historical payload or
  cache-only marker denial. It needs both isolated PostgreSQL and Valkey. A port
  wrapper injects the lost ACK after a real commit; driver packet loss is outside
  this fixture's evidence boundary.
- `crates/persistence-postgres/tests/token_issuance_atomicity.rs` covers the
  durable SingleUse fence, concurrent code identities with independent holder
  evidence, actual receipt migration/old-insert rejection/rollback guard, controlled
  `GrantExpired` rollback (including connection return to the pool), rotation
  conflicts, and the final schema shape. It needs an isolated PostgreSQL from
  `NAZO_TEST_DATABASE_URL`/`DATABASE_URL`.
- `crates/persistence-postgres/tests/support/mfa_generation.rs`, mounted by
  `identity_repositories`, uses real MFA confirmation, encryption and factor
  consumption against isolated PostgreSQL. TOTP and backup-code cases cover an
  admitted G1 proof delayed until formal G2 installation, reverse lock ordering,
  rollback after dependent deletes, and a real committed clear with a hidden ACK
  followed by a stale G1 retry. Full credential/flag/backup/remembered-device
  snapshots establish preservation; a forwarding fault injector hides only the
  clear ACK. It does not prove driver packet loss or Required audit crash closure.
- `crates/state-store-valkey/tests/replay_contract.rs` covers real client-
  attestation owner-clock expiry, shared token/PAR consumption and concurrent NX.
  `crates/nazoauth/tests/unit/http/token/dispatch/attestation.rs` combines signed
  input with real Valkey expiry and covers post-NX Unknown in both endpoints,
  including the retained physical marker and cross-endpoint rejection. These
  host cases need both isolated PostgreSQL and Valkey; semantic ACK injection
  does not substitute for physical failover evidence.
- `crates/persistence-postgres/tests/security_state_maintenance.rs` covers
  the bounded maintenance pass against the same isolated database.
- `crates/nazoauth/tests/token_issuance_simplification.rs` drives the real
  spawned `nazoauth server` dispatcher against isolated PostgreSQL and Valkey.
- `crates/nazoauth/tests/token_hotpath_perf.rs` is the opt-in hot-path
  benchmark: set `NAZO_PERF_HOTPATH=1`, `NAZO_PERF_OUTPUT`, an isolated
  PostgreSQL with `pg_stat_statements` preloaded
  (`NAZO_TEST_DATABASE_URL`/`DATABASE_URL`), and `NAZO_TEST_VALKEY_URL`/
  `VALKEY_URL`. `NAZO_PERF_OPS` (default 10000 measured operations per
  group-run), `NAZO_PERF_RUNS` (default 5), `NAZO_PERF_WARMUP`, and
  `NAZO_PERF_CONCURRENCIES` (default `1,8,32`) control the matrix. The
  benchmark fails when `pg_stat_statements` cannot be read, when a measured
  group records any error, or when successful operations fall short of the
  configured count — empty statistics or partial results are never reported
  as success. One-time inputs are seeded through the owning stores'
  production APIs, and per-tenant keysets are seeded through the
  key-management `test-support` harness so every supported access-token
  signing algorithm is exercised; no production logic is reimplemented in
  the harness.

Update affected documentation, examples, and index entries when a change
affects documented behavior, contracts, ownership, configuration, or source
paths; purely internal or mechanical changes do not require documentation-only
churn. Keep historical reports tied to their recorded revisions instead of
rewriting them as current test results.

## Release CI prerequisites

Release commits must be reachable from `main`. `code-quality.yml`,
`release-policy.yml`, and `operator-fuzz.yml` each require a completed
successful run on `main`, triggered by `push` or `workflow_dispatch`. The gate
searches the latest 100 runs per workflow.

A run may cover the exact release commit or an ancestor when the intervening
net changes affect only `docs/`, root Markdown files, or the retired
`NazoAuth-Web-Runtime-Refactor-Task-Package/`. Code, dependencies, build inputs,
scripts, and workflow changes require fresh checks. PR runs, failed checks,
unrelated commits, and later commits do not qualify. Accepted run IDs and
commits are printed in the policy job log.

Documentation-only pushes retain the existing quality-workflow path filter.
If suitable evidence is missing, run the required workflow manually on `main`
and wait for success before retrying a release from that commit. Rerunning an
old tag still uses the workflow stored at that tag; this policy change takes
effect for subsequent release commits containing it.

## Runtime image security updates

Runtime stages install their required packages on a digest-pinned Debian base
and never run `apt-get upgrade`. Security-sensitive packages may additionally be
pinned to exact Debian versions (Renovate-managed) when the pinned base does not
yet carry a fix; the resulting image is scanned fail-closed by Trivy for fixable
HIGH/CRITICAL findings. Routine security updates land by updating the pinned
base digest (Renovate covers the base images), after which the conformance image
build bypasses BuildKit cache
for `runtime-base` and every downstream runtime stage; release OCI assembly
bypasses cache for its `runtime` stage. Both paths scan the resulting image
and reject fixable HIGH/CRITICAL vulnerabilities before reuse or publication.

Runtime descendants are rebuilt as well so an imported cached final stage cannot
retain the former package layer. CI logs the installed versions of the affected
packages from the final image before scanning its exported archive.

## Avatar focused regressions

Local storage definitions in `crates/nazoauth/tests/unit/adapters/avatar_files.rs`
exercise immutable preparation, unique CAS loser cleanup, repository errors
before/after a committed reference, cancellation at each observed I/O suspension
and either side of CAS, deletion ordering, restart/legacy fallback, tenant/user
isolation, partial versions, unsafe paths and best-effort retirement. Their
fixtures live in `tests/support/local_avatar.rs`. The profile HTTP suite also
wraps the real PostgreSQL CAS with an error after commit and checks that the
selected image remains readable. Run it with the existing isolated PG/Valkey
fixture settings; an unconfigured fixture is not execution evidence.

Identity Avatar regressions retain Publishing retry ETag/hash/decoder checks,
count the initial Pending staged read, verify the single hash and byte-drop
source contract, reject failed candidate recording before publication and
preserve shared direct candidates after CAS miss/error. The object-store
`s3_read_final` integration target records signed HTTP methods and tests one
GET/no HEAD, MIME/body binding, missing MIME, error mappings and unsafe IDs
without I/O. Existing staged-read and publication regressions remain applicable.

- OpenID4VC wire/proof repairs: `openid4vc/credential_proofs.rs` uses signed
  positive and negative cases for scalar audiences, present issuer matching,
  optional attestation key binding, nonce, advertised algorithms and one-JWT
  attestation batches. `openid4vci_response.rs`, `transport_contract.rs` and the
  live deferred fixture cover encrypted HTTP 202 and exact stored response
  replay. VP service and endpoint mapping tests preserve completion dependency
  failures as server errors and reject unsupported holder-binding waivers.
  These mounted tests are source evidence until executed at the candidate SHA.
  See [validation boundaries](../protocol/openid4vc-validation.md).

## PostgreSQL cancellation observation

The Required dataset and mTLS cancellation fixtures hold a server-side append
barrier and require an independent peer to acquire the unchanged business row
before the retained owner pool is checked out again. Their owner connections
explicitly set `client_connection_check_interval=100ms` for this observation.
The barrier and the three-second peer lock timeout remain in place; no query
timeout or explicit server cancellation replaces physical connection disposal.

PostgreSQL's default zero interval detects a closed client at a later socket
interaction, so a backend blocked inside the artificial barrier can retain its
locks after the client driver closes. These fixtures qualify `DiscardOnDrop`
retirement under the declared observation setting; they do not establish a
three-second lock-release bound under the production default or qualify physical
commit-acknowledgement loss. The setting is confined to those test connections.
See the [PostgreSQL connection-check documentation](https://www.postgresql.org/docs/18/runtime-config-connection.html#GUC-CLIENT-CONNECTION-CHECK-INTERVAL).
