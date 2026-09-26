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

Use the pinned toolchain in `rust-toolchain.toml`. The executable CI definition
is [code-quality.yml](../../.github/workflows/code-quality.yml); it owns the
service versions, fixtures, and complete environment. Do not point these tests
at a deployment database or state store.

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
cargo test --locked -p nazo-postgres --test migrations pending_migrations_create_all_runtime_module_state_tables
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

Targeted suites with their own entry points:

- `crates/persistence-postgres/tests/token_issuance_atomicity.rs` covers the
  durable SingleUse fence, concurrent grant consumption, controlled
  `GrantExpired` rollback (including connection return to the pool), rotation
  conflicts, and the final schema shape. It needs an isolated PostgreSQL from
  `NAZO_TEST_DATABASE_URL`/`DATABASE_URL`.
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
