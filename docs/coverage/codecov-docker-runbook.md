# Docker-backed Codecov Runbook

This project runs the coverage compiler on the host and lets the coverage
script own disposable PostgreSQL, Valkey, and MinIO containers. It labels
fixtures for ownership checks and removes them on exit. Tests connect locally
on ports 15432, 16383, and 9000. The current Docker publication for PostgreSQL
and Valkey does not restrict the host bind address; use an isolated test host
or network controls. MinIO is explicitly published on loopback.

## Recommended Command

Run this from the repository root in Bash (Git Bash is supported on Windows):

```sh
CARGO_BUILD_JOBS=1 \
CARGO_TERM_COLOR=never \
CARGO_TARGET_DIR="$PWD/target/codecov-coverage" \
RUST_TEST_THREADS=1 \
bash scripts/generate_codecov_lcov.sh
```

PowerShell 7 launcher for Git Bash:

```powershell
$repo = git rev-parse --show-toplevel
if ($LASTEXITCODE -ne 0) { throw "Run from a NazoAuth Git worktree" }
Set-Location $repo
$env:CARGO_BUILD_JOBS = '1'
$env:CARGO_TERM_COLOR = 'never'
$env:CARGO_TARGET_DIR = "$repo/target/codecov-coverage"
$env:RUST_TEST_THREADS = '1'
& 'C:\Program Files\Git\bin\bash.exe' scripts/generate_codecov_lcov.sh
if ($LASTEXITCODE -ne 0) { throw "Coverage generation failed" }
```

## Known Failure Modes

- Run the command from the resolved NazoAuth repository root.
  `CARGO_TARGET_DIR` must resolve to `<repository>/target/codecov-coverage`.
  The script rejects other target directories to prevent coverage and ordinary
  Cargo artifacts from contaminating each other.
- Do not set `CODECOV_DOCKER_NETWORK`, fixture host/container overrides, or
  non-default fixture ports. The script owns ports 15432, 16383, and 9000 and
  refuses to remove containers without its ownership label.
- If a fixed port is already in use, stop the conflicting process or
  container before starting coverage; do not redirect the script to an external
  database or Valkey instance.
- The two loopback HTTP ports default to 18000 and 18001. On a shared validation
  host, set `CODECOV_PRIMARY_SERVER_PORT` and `CODECOV_SIGNED_SERVER_PORT` to two
  distinct free unprivileged ports. The script validates both ports before it
  creates fixtures or starts a build; it never terminates an existing listener.
- On Linux the script auto-detects `python3`; set `PYTHON` only when the desired
  interpreter is not available under the usual `python3` or `python` names.
- Private-unit tests live under `tests/unit`. They are compiled through a minimal
  `#[cfg(test)] #[path = "..."]` mount from the owning `src/**` module. Reusable
  dependency composition lives under `tests/support` and is also mounted by
  explicit path; `include!` and `tests/support/seams` are forbidden. Coverage
  runs both library and existing integration tests with
  `cargo test --locked --workspace --all-features --lib --tests`, then derives
  the exact instrumented test-object list from Cargo's JSON artifact stream.
  Do not add duplicate top-level integration tests for behavior already covered
  by the owning private-unit or integration suite.
- Avoid unconditional `cargo clean` during the coverage loop. The script uses a
  dedicated `CARGO_TARGET_DIR`, and Cargo fingerprints the llvm-cov
  instrumentation flags. Use `CODECOV_FORCE_CARGO_CLEAN=1` only when changing the
  target directory or investigating stale instrumentation.
- Do not run ordinary Cargo builds in `target/codecov-coverage`. Use a separate
  target such as `target/check` for focused non-coverage checks. If coverage
  artifacts are contaminated, use the script's explicit clean option once.

## Focused tests

For a focused non-coverage check, select the owning package and test name from
[the test architecture](../project/testing.md) and current Cargo targets:

```sh
CARGO_TARGET_DIR="$PWD/target/check" \
  cargo test --locked -p PACKAGE TEST_FILTER -- --nocapture
```

Replace `PACKAGE` and `TEST_FILTER` with actual names. Database, Valkey, object
storage, and HTTP tests still require their documented fixtures and current
configuration; a name-filtered unit run is not coverage or deployment proof.
Use the coverage script for its owned full fixture lifecycle. There is no
required pre-existing `nazo-oauth-codecov-runner:local` image or named coverage
network in the current workflow.
