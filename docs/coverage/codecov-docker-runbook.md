# Codecov Docker Runbook

This project should run local coverage in Docker on Windows. The host Rust
toolchain may fail on native OpenSSL/libpq linking, while the Docker runner keeps
the compiler, PostgreSQL, Valkey, and Python environment consistent.

## Recommended Command

Create the reusable Docker network once:

```sh
docker network create nazo-oauth-codecov-net || true
```

Run coverage with cached Cargo registry/git/target volumes:

```sh
docker rm -f nazo-oauth-codecov-postgres nazo-oauth-codecov-valkey 2>/dev/null || true
docker run --rm --name nazo-oauth-codecov-runner \
  --network nazo-oauth-codecov-net \
  -v "$PWD:/workspace" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v nazo-oauth-cargo-registry:/usr/local/cargo/registry \
  -v nazo-oauth-cargo-git:/usr/local/cargo/git \
  -v nazo-oauth-codecov-target:/docker-target \
  -w /workspace \
  -e CODECOV_DOCKER_NETWORK=nazo-oauth-codecov-net \
  -e CARGO_TARGET_DIR=/docker-target/codecov \
  -e CARGO_BUILD_JOBS=1 \
  -e CARGO_TERM_COLOR=never \
  -e PYTHON=python3 \
  nazo-oauth-codecov-runner:local \
  bash -lc '. /usr/local/cargo/env && bash scripts/generate_codecov_lcov.sh'
```

PowerShell equivalent:

```powershell
Set-Location F:\projects\nazo_oauth\oauth_backend_rust
docker network inspect nazo-oauth-codecov-net *> $null
if ($LASTEXITCODE -ne 0) { docker network create nazo-oauth-codecov-net | Out-Null }
docker rm -f nazo-oauth-codecov-postgres nazo-oauth-codecov-valkey 2>$null
docker run --rm --name nazo-oauth-codecov-runner `
  --network nazo-oauth-codecov-net `
  -v ${PWD}:/workspace `
  -v /var/run/docker.sock:/var/run/docker.sock `
  -v nazo-oauth-cargo-registry:/usr/local/cargo/registry `
  -v nazo-oauth-cargo-git:/usr/local/cargo/git `
  -v nazo-oauth-codecov-target:/docker-target `
  -w /workspace `
  -e CODECOV_DOCKER_NETWORK=nazo-oauth-codecov-net `
  -e CARGO_TARGET_DIR=/docker-target/codecov `
  -e CARGO_BUILD_JOBS=1 `
  -e CARGO_TERM_COLOR=never `
  -e PYTHON=python3 `
  nazo-oauth-codecov-runner:local `
  bash -lc '. /usr/local/cargo/env && bash scripts/generate_codecov_lcov.sh'
```

## Known Failure Modes

- Run the PowerShell command from `oauth_backend_rust`, not the monorepo root.
  `${PWD}:/workspace` must mount the directory containing `Cargo.toml`. If in
  doubt, replace `${PWD}` with an absolute path such as
  `F:/projects/nazo_oauth/oauth_backend_rust`.
- Do not run the coverage runner container with the script defaults for database
  host access. Inside the runner, `127.0.0.1` points to the runner container, not
  the disposable PostgreSQL container. Set `CODECOV_DOCKER_NETWORK` so the script
  uses container DNS names and internal ports.
- Debian-based runner images usually provide `python3`, not `python`. The script
  now auto-detects `python3`, and the Docker command still sets `PYTHON=python3`
  for explicitness.
- Avoid unconditional `cargo clean` during the coverage loop. The script uses a
  dedicated `CARGO_TARGET_DIR`, and Cargo fingerprints the llvm-cov
  instrumentation flags. Use `CODECOV_FORCE_CARGO_CLEAN=1` only when changing the
  target directory or investigating stale instrumentation.
- Do not run non-coverage `cargo test` commands in the same
  `CARGO_TARGET_DIR=/docker-target/codecov` directory. Use a separate target
  directory such as `/docker-target/check` for targeted compile/test checks. If
  the coverage target directory has been polluted by a non-llvm-cov build, run
  one clean coverage pass with `CODECOV_FORCE_CARGO_CLEAN=1`, then return to the
  cached command above.

## Targeted Test Command

Use this for fast compile checks before a full coverage run:

```sh
docker run --rm --network nazo-oauth-codecov-net \
  -v "$PWD:/workspace" \
  -v nazo-oauth-cargo-registry:/usr/local/cargo/registry \
  -v nazo-oauth-cargo-git:/usr/local/cargo/git \
  -v nazo-oauth-codecov-target:/docker-target \
  -w /workspace \
  -e CARGO_TARGET_DIR=/docker-target/check \
  -e CARGO_BUILD_JOBS=1 \
  -e CARGO_TERM_COLOR=never \
  nazo-oauth-codecov-runner:local \
  bash -lc '. /usr/local/cargo/env && cargo test --locked --workspace --all-features --lib <test-filter> -- --nocapture'
```

For targeted tests that need PostgreSQL or Valkey, start disposable dependency
containers on the same Docker network first:

```powershell
docker rm -f nazo-oauth-codecov-postgres nazo-oauth-codecov-valkey 2>$null
docker run -d --name nazo-oauth-codecov-postgres `
  --network nazo-oauth-codecov-net `
  -e POSTGRES_PASSWORD=postgres `
  -e POSTGRES_DB=oauth `
  postgres:18-alpine
docker run -d --name nazo-oauth-codecov-valkey `
  --network nazo-oauth-codecov-net `
  valkey/valkey:9-alpine
Start-Sleep -Seconds 3
docker exec nazo-oauth-codecov-postgres pg_isready -U postgres -d oauth
docker exec nazo-oauth-codecov-valkey valkey-cli ping
```

Then pass the service URLs into the targeted test runner:

```powershell
docker run --rm --network nazo-oauth-codecov-net `
  -v F:/projects/nazo_oauth/oauth_backend_rust:/workspace `
  -v nazo-oauth-cargo-registry:/usr/local/cargo/registry `
  -v nazo-oauth-cargo-git:/usr/local/cargo/git `
  -v nazo-oauth-codecov-target:/docker-target `
  -w /workspace `
  -e DATABASE_URL=postgresql://postgres:postgres@nazo-oauth-codecov-postgres:5432/oauth `
  -e VALKEY_URL=redis://nazo-oauth-codecov-valkey:6379/0 `
  -e CARGO_TARGET_DIR=/docker-target/check `
  -e CARGO_BUILD_JOBS=1 `
  -e CARGO_TERM_COLOR=never `
  nazo-oauth-codecov-runner:local `
  bash -lc '. /usr/local/cargo/env && cargo test --locked --workspace --all-features --lib <test-filter> -- --nocapture'
```

If another agent holds `/docker-target/check`, wait for it to finish. Using a
fresh target directory avoids the lock but triggers a slow full rebuild.
