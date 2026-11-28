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

### Framework adapter conformance

The facade's `conformance` feature exposes reusable cases and assertion helpers
under `nazoauth::integration::conformance`. The cases call production routing and
presenters; framework tests only convert transport values. The Actix suite
checks canonical registration, raw targets and duplicate values, unchanged
`Bytes` storage, decoder bounds, real connection facts, and host security headers.
The native fixture compares public `NazoAuth::handle` with the production Actix
registration with absent process routes, registered but disabled tenant
capabilities, and an enabled credential issuer. The credential fixture creates
offers and tokens through the public facade, then compares the first JSON and
encrypted JWT credential responses with their durable retries through both
transports. See the [adapter guide](../integration/rust-embedding.md).

```sh
python3 scripts/check_native_transport.py
cargo test -p nazo-http-actix --lib
cargo test -p nazo-http-tower --all-features --lib
cargo test -p nazoauth --lib
cargo test -p nazoauth --test native_send
cargo test --manifest-path examples/hyper-embedding/Cargo.toml
cargo check --manifest-path examples/axum-embedding/Cargo.toml --all-targets
cargo test -p nazo-server --lib facade_conformance
```

The dependency check verifies official Actix sources, requires `actix-http`
3.21.3 or later for the chunked-body parsing and keep-alive timeout fixes, and
rejects feature unification that re-enables inbound HTTP/2 or an affected h2 version. The direct
TLS/mTLS test verifies HTTP/1.1 negotiation and rejection of an h2-only client.
Metadata conversion tests preserve raw URI/header semantics; only body and replay
bytes require pointer identity across the HTTP 0.2/1.x boundary.

The last command uses the ordinary test PostgreSQL and Valkey configuration.
Its mounted fixtures exercise root and nested prefixes through Actix and
independent Hyper and Axum consumers, including standard discovery exceptions
and unchanged host routes. The Axum fixture checks original method rejection and
fallbacks, connection facts, shared body handling, and its normal listener with
the standard Tower service-factory mount. Tower transport tests
check retained `Bytes` storage and bounded decoding. The stateful fixtures cover
real PKCE/DPoP/refresh/session transitions, Passkey ceremonies and credential
issuance/replay. The federation linking suite also mounts the public
facade and completes login, linking, callback replay rejection and unlinking for
OIDC and social providers (`cargo test -p nazo-server --lib mounted_federation`).
The separate `test-support` feature is permitted only in the native host's dev
dependency; adapters cannot use internal endpoint handles in place of this kit.

### Portable inner packages and runtime behavior

The [WASM portability workflow](../../.github/workflows/wasm-portability.yml)
checks the domain/application/facade package set owned by
`scripts/verify_static_contracts.py`. It runs on pull requests, main pushes and
manual dispatch without a database, cache, HTTP server, or native task scheduler.
The `nazoauth` facade participates in this gate; the `nazo-server` native host
and concrete HTTP/storage adapters do not.

```sh
rustup target add wasm32-unknown-unknown
python scripts/check_wasm_portability.py --list
python scripts/check_wasm_portability.py
python -m unittest tests.unit.test_application_dependency_boundaries tests.unit.test_wasm_portability
```

The checker uses each package's production features in isolation, then checks
the combined graph with all six portable cryptographic capabilities enabled.
The native host's `nazo-crypto/certificate-issuance` feature is excluded from this
contract and rejected if an inner dependency activates it. `--all-features`
continues to apply to native workspace validation. Test fixture features are
activated only by the corresponding test consumers.

Target compilation is followed by executing the same application contracts in
Node with `wasm-bindgen-test`. Install `wasm-bindgen-cli` at the exact
`wasm-bindgen` version recorded in `Cargo.lock`; the workflow derives this
version and installs it with its own locked dependency graph. The test profile
uses optimization for RSA key generation, matching the workflow:

```sh
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner
export CARGO_PROFILE_TEST_OPT_LEVEL=2
export CARGO_PROFILE_TEST_DEBUG=0
cargo test --target wasm32-unknown-unknown --locked \
  -p nazo-oauth-server -p nazo-identity -p nazo-openid4vci -p nazo-openid4vp \
  -p nazo-runtime-modules -p nazo-crypto \
  --features nazo-crypto/jose,nazo-crypto/ecdh,nazo-crypto/aead,nazo-crypto/password,nazo-crypto/ed25519,nazo-crypto/x509 \
  --test application_boundaries --test authorization_application \
  --test security_facts --test host_replacement_contract \
  --test delivery_batches --test token_outcome --test federation_authentication --test oidc_rp \
  --test service_contract --test revision_races --test portable_jose --test certificate_paths
cargo test --target wasm32-unknown-unknown --locked -p nazo-identity \
  --lib oidc_profile_fields_validate_their_declared_syntax
```

These targets exercise authorization and PAR, token signing and validation,
UserInfo, DPoP signature/target/replay decisions, one-shot delivery batches,
federated identity/MFA, credential issuance and presentation verification through
their production APIs and semantic port fixtures. Runtime-module tests exercise
persisted clock deadlines and enable/disable discovery publication. The filtered
profile unit test checks UTC, IANA names, aliases and case handling against the
bundled timezone index. Integration targets share one feature closure to avoid
recompiling common dependencies; the separate library invocation runs only the
named profile test. The native and WASM harnesses
execute the same assertions. Signature tampering and token revocation must
remain failures on both platforms. Run the concrete host's integration suite
alongside this shared portability gate.

### Cloudflare Workers host and adapters

The [Workers workflow](../../.github/workflows/cloudflare-workers.yml) checks the
concrete host separately from the portable inner-package gate. It verifies the
production dependency graph, the D1 adapter's semantic SQL contracts, transport
conformance, and the bundled application in local workerd. The
[deployment guide](../operations/cloudflare-workers.md) describes the supported
profile and the authenticated ingress requirement.

```sh
python scripts/verify_static_contracts.py --check
python scripts/check_crypto_boundary.py
python -m unittest tests.unit.test_worker_portability
python scripts/check_worker_portability.py
cargo test --locked -p nazo-oauth-server-d1 -p nazo-http-worker -p nazo-server-worker \
  --features nazo-oauth-server-d1/local-sqlite
CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner \
  cargo test --locked --target wasm32-unknown-unknown -p nazo-http-worker --test ingress
cargo clippy --locked --target wasm32-unknown-unknown -p nazo-http-worker --all-targets -- -D warnings
cargo install worker-build --version 0.9.0 --locked
npm ci --prefix deploy/cloudflare
npm run bundle --prefix deploy/cloudflare
npm test --prefix deploy/cloudflare
```

Install the lockfile-matched `wasm-bindgen-cli` as described above before running
the WASM ingress target. Its tests execute the production forwarding helpers
against JavaScript streams: canonical request heads, duplicate-header
normalization, explicit authenticated source facts, decoded body limits,
malformed compression, incremental multipart reads, and unchanged response
`Bytes` allocations. This ingress target runs on WASM. Node lacks Cloudflare's
`FixedLengthStream`, so the SDK's outgoing Fetch conversion is exercised by the
real workerd host suite.

`local-sqlite` tests execute the adapter's production SQL and migrations against
SQLite, including concurrent single-use decisions, atomic audit rollback,
tenant isolation, replay state, session replacement, and expiry cleanup. The
workerd suite uses the actual WASM application and local D1 binding for login,
authorization, token issuance, refresh, UserInfo, DPoP, revocation, logout,
concurrent redemption and isolate replacement. It also records local request
latencies. Measure Cloudflare throughput, latency and database capacity against
an isolated deployment on the selected plan.

### Audit backlog scale checks

The ordinary workspace suite checks audit claims at zero and 10,000 pending
rows, including cross-connection claim/ACK behavior. The unchanged one-million
and fifteen-million row SQL plan assertions run as the explicitly ignored
`audit_claim_is_bounded_at_million_row_backlogs` test. The separate
[audit-scale workflow](../../.github/workflows/audit-scale.yml) owns that test:
it runs only on manual dispatch. Ordinary functional/security checks remain
in automatic CI, including the zero/10,000-row claim and cross-connection ACK
regressions. The ordinary suite reports the million-row test as ignored; use
the manual workflow for its result.

The manual workflow uses its own PostgreSQL database and the shared Cargo cache.
It always executes the selected scale test. Maintainers can run it for changes
to audit queries/indexes, PostgreSQL versions, or an observed backlog regression.
It does not block unrelated PRs or releases and is not a coverage measurement.

```sh
gh workflow run audit-scale.yml --repo nazozero/NazoAuth --ref main
```

To execute the scale test explicitly against an isolated audit database:

```sh
cargo test --locked --all-features -p nazo-postgres --test audit_ledger \
  audit_claim_is_bounded_at_million_row_backlogs -- --ignored --exact --nocapture
```

### CI selection and reuse

Rust workspace checks cover changes to Rust sources, manifests, toolchains,
fixtures, migrations, build/coverage scripts and their workflow. Python and
architecture checks run separately and do not compile the service. Operator
parser fuzzing, service-image/HTTP security checks and performance-runner
images each have their own inputs in `scripts/ci_inputs.py`.

CodeQL scans every PR update and main push. GitHub publishes its security result
in the independent `CodeQL` check.

Input-selected automatic runs compare the actual checkout's Git file identities, including
the PR merge result, with a successful run of the same workflow and event in the
same repository/branch/PR context, or from successful main checks when opening a
same-repository PR. Identical inputs can reuse evidence for seven
days; security scans use a 24-hour limit because advisory data can change without
a source edit. The job summary links that run. Failed, cancelled, running or missing
results never permit reuse. Reuse does not renew evidence age. Manual and scheduled
runs execute their checks regardless of prior results. Updated PRs cancel obsolete
in-progress runs; main runs remain independent.

This avoids rebuilding and retesting an unchanged service after documentation or
specification-inventory edits. Changing test or workflow inputs invalidates that
evidence. Ordinary functional tests can also transfer from a successful same-repo
PR to main when its tested base is an ancestor of its head and Git proves its
inputs equal the current main inputs. The merged PR head/base are read from the
commit-to-PR association: Actions can clear a historical run's `pull_requests`
list after merge. Only the Rust input-selection job receives PR read permission.
Otherwise main runs the full ordinary suite.
Other workflows retain their separate main checks.

Coverage runs weekly and on manual dispatch; it is not repeated on every merge.
Manual `code-quality` runs coverage plus the uninstrumented timing/documentation
exclusions. Coverage and ordinary binaries have different instrumentation and
cannot share compiled workspace artifacts. Release checks consume successful governed main CI through
`scripts/check_release_ci.py`, then build and verify release artifacts.

| Stage or changed inputs | Checks to execute |
| --- | --- |
| Documentation or specification inventory only | Source/reference, Python and workflow-policy checks; reuse successful unchanged Rust, fuzz and image checks. Without reusable evidence, execute the selected checks. |
| Rust, dependencies, toolchain, fixtures or migrations | Workspace formatting, Clippy and PostgreSQL/Valkey tests; CodeQL and service security checks. Operator fuzzing runs when its parser, crypto, manifest, corpus or workflow inputs change. |
| Every PR or main push | CodeQL analysis, WASM production dependency/feature checks and portable runtime contracts; compiled artifacts use the separate WASM cache. |
| Performance runner or its workflow | Build the Goose runner and smoke-test its executable. The Python gate verifies that the English and Chinese reports match the retained measurements. Use `make perf-verify` to also recalculate available per-request records. |
| Main after merge | Reuse ordinary PR tests only with identical proven inputs; retain main CodeQL/security roles and run missing or expired checks. |
| Release | Require successful governed main CI, then build, scan and verify the release artifacts. Do not dispatch another complete functional CI run. |
| Weekly or manual checks | Execute selected checks even with matching prior inputs; coverage uses its own instrumented build. |

Rust 1.100.0 is the minimum supported version, declared in every package's
manifest and pinned in `rust-toolchain.toml` and the build images. The
workflow toolchain actions use the same release at an immutable revision. The executable CI definition
is [code-quality.yml](../../.github/workflows/code-quality.yml); it owns the
service versions, fixtures, and complete environment. Python tools use
Python 3.15.2 in CI and the development image; the latter retains Debian's
separate system interpreter for OS tools. The S3 fixture builds the pinned
latest public MinIO and mc releases; see [its source and license details](../../tests/fixtures/minio/README.md).
Do not point these tests
at a deployment database or state store.

The workspace treats Cargo's native unused-dependency diagnostics as errors;
the standalone fuzz and benchmark packages report them as warnings.
When reviewing dependency scope, check production targets separately from tests:

```sh
cargo check --workspace --lib --bins --all-features --locked
```

The all-target Clippy check below also builds tests, whose imports can conceal a
dependency that belongs only in `[dev-dependencies]`. Cargo does not check unused
development dependencies, even with `--all-targets`; a dependency used only to
enable a transitive feature also needs manual review before removal.

The repository's `.cargo/config.toml` requires registry releases to be at least
three days old before Cargo selects them during dependency resolution. Versions
already in `Cargo.lock` remain usable with `--locked`. Registries without publish
timestamps and `cargo install` are outside this policy. For a reviewed urgent
fix, override the policy for that update and commit the resulting lockfile:

```sh
CARGO_RESOLVER_INCOMPATIBLE_PUBLISH_AGE=allow cargo update <crate> --precise <version>
```

Construct PostgreSQL pools inside a Tokio runtime that lives at least as long
as the pool. Test-local pools can use the test runtime; a process-lifetime
shared audit fixture must retain its own runtime with its pool. Pure logic
tests should pass the configuration they use instead of constructing unrelated
database infrastructure.

Hot-path PostgreSQL reads complete on the pool owner runtime and return owned row data.
`read_connection_ownership` uses a real database lock and an independent observer
to check that completed reads release pool capacity before a delayed caller resumes.

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
git fetch --no-tags --depth=1 origin 385d23a330158ae78ff3fd55df2eac3a74cb2aec
cargo test --locked -p nazo-postgres --test migration_baseline
cargo test --all-features --locked -p nazo-postgres --test migrations pending_migrations_create_all_runtime_module_state_tables
cargo test --workspace --all-features --locked --no-fail-fast
```

The migration test prepares the test database before the full suite. CI builds
one test archive without debug symbols or incremental compilation, then runs
six nextest partitions with independently isolated PostgreSQL, Valkey and S3
fixtures. Tests within each partition remain serial; documentation tests run
separately and any failed partition fails the gate. For a focused change, run the owning package/test
target first; broaden
validation when the change crosses boundaries or leaves an unresolved risk.
Documentation-only changes need source/example/reference checks; native Rust
builds can reuse unchanged evidence, while the portability gate retains its
independent checks. A passed unit suite does not replace required HTTP, migration, recovery,
conformance, deployment, or performance evidence.

CI budgets Cargo build concurrency from the runner's available logical CPUs
and memory (3 GiB per build job). Schema materialization reuses the test archive
in each isolated partition.
The audit backlog scale fixture vacuums its deleted rows at handoff; the
separate dead-prefix regression still creates its own ack-deleted prefix and
requires natural autovacuum recovery without manual vacuum of that lifecycle.

Targeted suites with their own entry points:

- `crates/identity/tests/unit/federation.rs` defines tenant-separated digest and
  legacy parsing checks. `crates/state-store-valkey/tests/federation_binding.rs`
  defines real-Valkey matching-take concurrency, exact raw/deadline preservation,
  matching-owner typed corruption and the single-EVAL call-path contract.
- `crates/server/tests/unit/http/auth/federation/browser_binding.rs` defines
  canonical cookie/security attributes, missing-cookie zero-store calls,
  backend failure mapping, OIDC/social attacker-to-other-browser rejection with
  subsequent owner completion, parallel established-cookie starts, and the
  fail-closed simultaneous cold-start race. HTTP completion fixtures use the
  isolated PostgreSQL and Valkey configured above; the state-only checks require
  Valkey. These focused cases supplement existing nonce, PKCE and provider
  mismatch regressions.

- `crates/persistence-postgres/tests/migration_baseline.rs` reads the 127 released
  migrations from the pinned v0.3.2 Git commit, without embedding historical SQL
  in the current artifact. It compares empty-install schema, ACLs and initial
  facts, then verifies populated adoption, unchanged object identities/data,
  concurrent retry, real runtime LOGIN permissions, tenant constraints, and
  pre-cutoff rejection. Failed installation must roll back DDL and remain
  retryable. Use PostgreSQL 18+ and its matching `pg_dump`; `PG_DUMP` can select
  the executable. CI uses `scripts/pg_dump_test_container.sh` on its isolated
  Docker runner. The database login needs CREATE DATABASE and CREATE ROLE.
  Existing controller, recovery, MFA and client suites verify current runtime
  behavior against complete isolated databases.
- `crates/server/tests/unit/http/token/authorization_code/identity.rs` covers
  real issuance with a hidden commit ACK, stable identity after cache restoration,
  fresh signed DPoP holder checks with missing or expired Pending payload, mTLS
  receipt matching after current binding is disabled, and historical payload or
  cache-only marker denial. It needs both isolated PostgreSQL and Valkey. A port
  wrapper injects the lost ACK after a real commit; driver packet loss is outside
  this fixture's evidence boundary.
- `crates/persistence-postgres/tests/token_issuance_atomicity.rs` covers the
  durable SingleUse fence, concurrent code identities with independent holder
  evidence, controlled
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
  clear ACK. Use separate fault tests for driver packet loss and crash recovery.
- `crates/state-store-valkey/tests/replay_contract.rs` covers real client-
  attestation owner-clock expiry, shared token/PAR consumption and concurrent NX.
  `crates/server/tests/unit/http/token/dispatch/attestation.rs` combines signed
  input with real Valkey expiry and covers post-NX Unknown in both endpoints,
  including the retained physical marker and cross-endpoint rejection. These
  host cases need both isolated PostgreSQL and Valkey; semantic ACK injection
  does not substitute for physical failover evidence.
- `crates/persistence-postgres/tests/receipt_key_scope.rs` verifies the compact
  one-use index against real PostgreSQL. `token_issuance_atomicity` covers its
  current consumption behavior; `migration_baseline` verifies receipt preservation
  across the supported upgrade boundary. The holder serialization tests cover sparse and historical
  explicit-null proof encodings through the same checked restoration boundary.
- `crates/persistence-postgres/tests/security_state_maintenance.rs` covers
  the bounded maintenance pass against the same isolated database, including
  multi-batch expiry of idle remembered devices, an independently locked row,
  expired consumed/unconsumed controller approvals and live-state preservation.
  MFA repository tests verify that audit failure restores the verifier deleted
  by a failed consumption transaction. The baseline upgrade preserves existing
  credential facts without replaying historical compaction migrations.
- `crates/server/tests/token_issuance_simplification.rs` drives the real
  spawned `nazoauth server` dispatcher against isolated PostgreSQL and Valkey.
- `crates/server/tests/token_hotpath_perf.rs` is the opt-in hot-path
  benchmark: run `cargo test -p nazo-server --test token_hotpath_perf -- --ignored`
  with `NAZO_PERF_OUTPUT`, an isolated
  PostgreSQL with `pg_stat_statements` preloaded
  (`NAZO_TEST_DATABASE_URL`/`DATABASE_URL`), and `NAZO_TEST_VALKEY_URL`/
  `VALKEY_URL`. `NAZO_PERF_OPS` (default 2000 measured operations per
  group-run), `NAZO_PERF_RUNS` (default 3), `NAZO_PERF_WARMUP` (default 200), and
  `NAZO_PERF_CONCURRENCIES` (default `1,8,32`) control the matrix. The
  benchmark fails when `pg_stat_statements` cannot be read, when a measured
  group records any error, or when successful operations fall short of the
  configured count — empty statistics or partial results are never reported
  as success. One-time inputs are seeded through the owning stores'
  production APIs, and per-tenant keysets are seeded through the
  key-management `test-support` harness so every supported access-token
  signing algorithm is exercised; no production logic is reimplemented in
  the harness. Refresh and Native SSO workers use independent users so the
  per-user refresh-family limit does not invalidate another worker's inputs.
  Native SSO follows each response's new ID token and device secret; it does
  not keep presenting the initial family after that family has been retired.

Update affected documentation, examples, and index entries when a change
affects documented behavior, contracts, ownership, configuration, or source
paths; purely internal or mechanical changes do not require documentation-only
churn. Store run-specific reports outside the source tree, bound to the tested revision.

## Release CI prerequisites

Release commits must be reachable from `main`. `code-quality.yml`,
`release-policy.yml`, and `operator-fuzz.yml` each require a completed
successful run on `main`, triggered by `push` or `workflow_dispatch`. The gate
searches the latest 100 runs per workflow.

`conformance-security.yml` runs its protocol and supply-chain checks on matching
changes.

A run may cover the exact release commit or an ancestor when the intervening
net changes affect only `docs/`, root Markdown files, or the retired
`NazoAuth-Web-Runtime-Refactor-Task-Package/`. Code, dependencies, build inputs,
scripts, and workflow changes require fresh checks. PR runs, failed checks,
unrelated commits, and later commits do not qualify. Accepted run IDs and
commits are printed in the policy job log.

Documentation-only pushes run CodeQL, the input-selection gate and lightweight
checks; unchanged heavy jobs reuse successful evidence as described above.
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

Local storage definitions in `crates/server/tests/unit/adapters/avatar_files.rs`
exercise immutable preparation, unique CAS loser cleanup, repository errors
before/after a committed reference, cancellation at each observed I/O suspension
and either side of CAS, deletion ordering, restart/legacy fallback, tenant/user
isolation, partial versions, unsafe paths and best-effort retirement. Their
fixtures live in `tests/support/local_avatar.rs`. The profile HTTP suite also
wraps the real PostgreSQL CAS with an error after commit and checks that the
selected image remains readable. Run it with the existing isolated PostgreSQL
and Valkey fixture settings.

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
locks after the client driver closes. These fixtures observe `DiscardOnDrop`
retirement with a 100 ms connection check and a three-second peer lock timeout.
The setting is confined to those test connections. Production lock-release time
depends on the server's connection-check settings and socket activity.
See the [PostgreSQL connection-check documentation](https://www.postgresql.org/docs/18/runtime-config-connection.html#GUC-CLIENT-CONNECTION-CHECK-INTERVAL).

`audit_bounded_reads` executes real finalize/ACK functions with stale pending
and delivered-chain statistics. It asserts bounded logical buffer reads for a
256-event batch and exact checkpoint/reclamation, independently of shared CPU
scheduling. All seed rows and table options are transaction-local; it requires
the isolated `NAZO_AUDIT_TEST_DATABASE_URL` like other audit integration tests.

## Model and revocation identity compaction

`migration_baseline` checks populated v0.3.2 adoption without rewriting business
rows or object identities. Controller and recovery repository suites verify
provisioning receipts and used-key authority against the baseline.
`access_token_retention` and the revocation unit suite retain monotonic deadlines,
clock-skew coverage, no-op updates, ownership conflict rollback and tenant isolation
checks; fixture identity assertions use the actual tenant/JTI key.
`audit_health_distinguishes_absent_retryable_and_blocked_batch` exercises the real
PG health projection and stale ACK rejection. The host checkpoint test retains
all four committed-checkpoint presence checks after removing unused local copies.
Existing mTLS tests still reject future/expired DER and validate current trust.
