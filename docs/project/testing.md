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

Conditional runtime behavior under `cfg(test)` is exceptional. It is allowed
only when the production action is unsafe or nondeterministic in a test process
(for example, process abort, real network proxy discovery, or live service
composition). Every exception is enumerated by
`scripts/verify_static_contracts.py`; adding one requires an architectural
review and a concrete explanation.

## Enforcement

`python scripts/verify_static_contracts.py --check` rejects:

- executable tests or inline test modules under `src`;
- test files under `src`;
- top-level `cfg(test)` items that are not explicit unit/support mounts;
- unreviewed nested test seams;
- a test that reaches into `src` with `#[path]` or `include!`;
- missing mount targets, any `tests/support/seams` file, test-side `include!`,
  and the legacy `tests/source_mounted` directory.

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
cargo test --workspace --all-features --locked
```

The migration test prepares the isolated schema before the full suite, as in
CI. For a focused change, run the owning package/test target first; broaden
validation when the change crosses boundaries or leaves an unresolved risk.
Documentation-only changes need source/example/reference checks, not a Rust
build. A passed unit suite does not replace required HTTP, migration, recovery,
conformance, deployment, or performance evidence.

Every change must update its corresponding documentation, examples, and index
entries. If behavior is unchanged, update the relevant explanation or source
reference without inventing a behavior change. Keep historical reports tied to
their recorded revisions instead of rewriting them as current test results.

## Release CI prerequisites

Release commits must be reachable from `main`. Both `code-quality.yml` and
`release-policy.yml` require a completed successful run on `main`, triggered by
`push` or `workflow_dispatch`. The gate searches the latest 100 runs per workflow.

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

The conformance image build bypasses BuildKit cache for `runtime-base`; release
OCI assembly bypasses cache for its `runtime` stage. This reruns the existing
`apt-get update` and `apt-get upgrade` on every CI build, while keeping Rust
compilation caches. Docker does not invalidate a cached `RUN` layer when Debian
publishes package updates. Both paths still scan the resulting image and reject
fixable HIGH/CRITICAL vulnerabilities before reuse or publication.
