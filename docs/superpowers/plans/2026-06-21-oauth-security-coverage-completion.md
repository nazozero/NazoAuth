# OAuth Security Coverage Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the in-progress coverage and CI stabilization work for `oauth_backend_rust` without weakening OAuth/OIDC/FAPI security semantics, then deliver a verified branch ready for PR review.

**Architecture:** Treat coverage as evidence of real protocol behavior, not as a number to game. Keep changes close to the owning protocol modules and tests; remove unreachable or duplicated control flow only when it is provably redundant, and never hide real security failures behind fallback behavior.

**Tech Stack:** Rust, Actix Web, Diesel, PostgreSQL, Valkey, Docker, cargo-llvm-cov, GitHub Actions, Codecov.

---

## Current State

Repository root:

- `F:\projects\nazo_oauth`

Rust service root:

- `F:\projects\nazo_oauth\oauth_backend_rust`

Current branch:

- `codex/improve-codecov-coverage`

Important local facts at handoff time:

- The remote branch cleanup task was already completed earlier. Do not spend more time deleting remote branches unless GitHub state has changed.
- The current branch contains many uncommitted coverage and security-path changes across `src/http/authorization`, `src/http/token`, `src/resource_server`, `src/support`, and corresponding `tests/in_source` files.
- The last known successful full Docker coverage parse recorded `oauth_fapi_core: 6709/6797 = 98.71%`, with `88` missed lines.
- The last attempted coverage run did not produce a usable success result. Local `tmp_cov_exit.txt` currently contains `101`, and `_tmp_coverage_run.log` shows a native Windows OpenSSL detection failure. Do not treat that run as evidence of test failure in the Linux/Docker CI path.
- Native Windows `cargo` checks are known to fail on OpenSSL/libpq environment issues. Prefer Docker for compile, test, and coverage gates.

## Non-Negotiable Rules

- Do not lower OAuth/OIDC/FAPI, DPoP, mTLS, PKCE, refresh-token rotation, token revocation, introspection, PAR, JAR, nonce, issuer, audience, subject, or client-authentication checks.
- Do not add wrapper, adapter, shim, compatibility switch, fallback path, or configuration flag to bypass a real protocol defect.
- Do not mark security-critical protocol files as ignored in Codecov just to reach a numeric target.
- Do not commit generated coverage artifacts such as `*.profraw`, temporary logs, `target`, `_tmp_coverage_run.log`, or local `.env.yaml` material.
- Do not use native Windows `cargo test` or `cargo llvm-cov` as the final gate for this branch.

## Primary Targets

1. Restore a clean, reproducible Docker verification loop.
2. Preserve and validate all existing uncommitted security-path changes.
3. Reach and document one of these explicit outcomes:
   - preferred: `oauth_fapi_core` reaches `100%`;
   - acceptable pause point: `oauth_fapi_core >= 98%`, production-code Codecov-included coverage remains in the intended high range, and every remaining miss is classified as either low-value defensive/randomness code or intentionally deferred with a concrete reason.
4. Make PR checks green for format, clippy, tests, coverage, CodeQL, and supply-chain gates.

## Files And Responsibilities

Coverage and CI:

- `oauth_backend_rust/scripts/generate_codecov_lcov.sh`: authoritative local/CI coverage script.
- `oauth_backend_rust/codecov.yml`: Codecov ignore and target configuration.
- `oauth_backend_rust/docs/coverage/codecov-docker-runbook.md`: Docker runbook for Windows-safe coverage and targeted tests.

High-priority protocol files:

- `oauth_backend_rust/src/http/token/authorization_code.rs`: authorization-code consumption, replay handling, mTLS binding, Valkey state failure behavior.
- `oauth_backend_rust/src/http/token/issue.rs`: access token, refresh token, and ID Token issuance boundaries.
- `oauth_backend_rust/src/http/token/revoke.rs`: token revocation endpoint and client-auth fail-closed behavior.
- `oauth_backend_rust/src/http/token/introspect.rs`: token introspection endpoint and privacy-preserving error behavior.
- `oauth_backend_rust/src/http/token/dispatch.rs`: token endpoint dispatch and client-auth routing.
- `oauth_backend_rust/src/http/token/forms.rs`: token and token-management form parsing.
- `oauth_backend_rust/src/http/authorization/request.rs`: authorization endpoint request validation and request-object/PAR consumption.
- `oauth_backend_rust/src/http/authorization/par.rs`: pushed authorization request validation and storage.
- `oauth_backend_rust/src/http/authorization/decision.rs`: consent/decision state handling before authorization-code issuance.
- `oauth_backend_rust/src/http/authorization/request/prompt_none.rs`: OIDC `prompt=none` non-interactive authorization behavior.
- `oauth_backend_rust/src/resource_server/dpop.rs`: DPoP proof validation and replay/nonce behavior.
- `oauth_backend_rust/src/resource_server/jwk.rs`: public JWK parsing and algorithm constraints.
- `oauth_backend_rust/src/support/oauth.rs`: client metadata, grant, redirect, audience, JWKS, and mTLS metadata rules.
- `oauth_backend_rust/src/support/security.rs`: password, token, private_key_jwt, and random code security helpers.
- `oauth_backend_rust/src/support/uri_policy.rs`: redirect URI and loopback policy helpers.

Representative tests:

- `oauth_backend_rust/tests/in_source/src/http/token/tests/authorization_code.rs`
- `oauth_backend_rust/tests/in_source/src/http/token/tests/issue.rs`
- `oauth_backend_rust/tests/in_source/src/http/token/tests/revoke.rs`
- `oauth_backend_rust/tests/in_source/src/http/token/tests/introspect.rs`
- `oauth_backend_rust/tests/in_source/src/http/token/tests/client_credentials.rs`
- `oauth_backend_rust/tests/in_source/src/http/token/tests/dispatch.rs`
- `oauth_backend_rust/tests/in_source/src/http/authorization/tests/par.rs`
- `oauth_backend_rust/tests/in_source/src/http/authorization/tests/decision.rs`
- `oauth_backend_rust/tests/in_source/src/http/authorization/tests/request/prompt_none.rs`
- `oauth_backend_rust/tests/in_source/src/http/authorization/request/tests/parameters.rs`
- `oauth_backend_rust/tests/in_source/src/resource_server/tests/dpop.rs`
- `oauth_backend_rust/tests/in_source/src/support/tests/oauth_client_metadata.rs`
- `oauth_backend_rust/tests/in_source/src/support/tests/oauth_client_jwks.rs`
- `oauth_backend_rust/tests/in_source/src/support/tests/oauth_mtls_metadata.rs`
- `oauth_backend_rust/tests/in_source/src/support/tests/security/client_assertion.rs`
- `oauth_backend_rust/tests/in_source/src/support/tests/uri_policy.rs`

## Task 1: Baseline And Dirty-Tree Audit

**Files:**

- Read: `oauth_backend_rust/docs/coverage/codecov-docker-runbook.md`
- Read: `oauth_backend_rust/codecov.yml`
- Read: `oauth_backend_rust/scripts/generate_codecov_lcov.sh`
- Modify only if needed: `oauth_backend_rust/docs/coverage/codecov-docker-runbook.md`

- [ ] **Step 1: Capture current Git state**

Run from `F:\projects\nazo_oauth`:

```powershell
git -C oauth_backend_rust status --short --branch
git -C oauth_backend_rust diff --stat
git -C oauth_backend_rust log --oneline --decorate -5
```

Expected:

- Branch is `codex/improve-codecov-coverage`.
- There are uncommitted source and test changes.
- No generated coverage artifacts should be staged.

- [ ] **Step 2: Inspect the modified production files before editing**

Run:

```powershell
git -C oauth_backend_rust diff -- src/http/token src/http/authorization src/resource_server src/support
```

Expected:

- Changes are limited to protocol behavior, parser simplification, test-only visibility, or direct security-path corrections.
- Any behavior change has a matching test or a clear test file listed in this plan.

- [ ] **Step 3: Inspect the modified test files before editing**

Run:

```powershell
git -C oauth_backend_rust diff -- tests/in_source/src/http tests/in_source/src/resource_server tests/in_source/src/support
```

Expected:

- Tests assert concrete OAuth/OIDC/FAPI behavior, not implementation trivia.
- DB/Valkey failure injection targets actual queried columns or active storage paths.

- [ ] **Step 4: Remove generated artifacts from consideration**

Run:

```powershell
git -C oauth_backend_rust status --ignored --short | Select-String -Pattern '\.profraw|target|tmp_cov|_tmp_coverage|lcov\.info'
```

Expected:

- Generated files may exist locally.
- Do not stage them.
- If any generated file is tracked unintentionally, stop and decide whether it belongs in `.gitignore` or should be removed from the branch.

## Task 2: Re-establish Docker Verification

**Files:**

- Read: `oauth_backend_rust/docs/coverage/codecov-docker-runbook.md`
- Modify only if command documentation is wrong: `oauth_backend_rust/docs/coverage/codecov-docker-runbook.md`

- [ ] **Step 1: Create or confirm the Docker network**

Run from `F:\projects\nazo_oauth\oauth_backend_rust`:

```powershell
docker network inspect nazo-oauth-codecov-net *> $null
if ($LASTEXITCODE -ne 0) { docker network create nazo-oauth-codecov-net | Out-Null }
```

Expected:

- The network exists.

- [ ] **Step 2: Run Docker compile check, not native Windows cargo**

Run:

```powershell
docker run --rm --network nazo-oauth-codecov-net `
  -v F:/projects/nazo_oauth/oauth_backend_rust:/workspace `
  -v nazo-oauth-cargo-registry:/usr/local/cargo/registry `
  -v nazo-oauth-cargo-git:/usr/local/cargo/git `
  -v nazo-oauth-codecov-target:/docker-target `
  -w /workspace `
  -e CARGO_TARGET_DIR=/docker-target/check `
  -e CARGO_BUILD_JOBS=1 `
  -e CARGO_TERM_COLOR=never `
  nazo-oauth-codecov-runner:local `
  bash -lc '. /usr/local/cargo/env && cargo check --locked --workspace --all-features'
```

Expected:

- Exit code `0`.
- If this fails, fix only the reported compile error before touching coverage.

- [ ] **Step 3: Run format check**

Run:

```powershell
cargo fmt --manifest-path oauth_backend_rust/Cargo.toml --check
```

Expected:

- Exit code `0`.
- If it fails only on formatting, run:

```powershell
cargo fmt --manifest-path oauth_backend_rust/Cargo.toml
```

Then rerun the check.

## Task 3: Refresh Coverage Once

**Files:**

- Read: `oauth_backend_rust/scripts/generate_codecov_lcov.sh`
- Read: `oauth_backend_rust/lcov.info` after the run

- [ ] **Step 1: Run the authoritative Docker coverage command**

Run from `F:\projects\nazo_oauth\oauth_backend_rust`:

```powershell
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

Expected:

- E2E passes.
- Library tests pass.
- Source-mounted tests under `tests/in_source` pass through `cargo test --locked --workspace --all-features --lib`.
- `lcov.info` is refreshed.

- [ ] **Step 2: If coverage fails, classify the failure**

Use this decision table:

| Failure | Required action |
|---|---|
| Rust compile error | Fix the exact source/test compile error, then rerun Docker compile check. |
| Test assertion failure | Read the handler and fixture; fix the test precondition if the request never reaches the intended branch. Do not weaken production behavior to satisfy a bad fixture. |
| DB relation missing | Ensure migrations are run before targeted DB tests. |
| Valkey timeout | Use the Docker dependency containers and internal DNS; do not rely on host `127.0.0.1` from inside a runner. |
| Native Windows OpenSSL/libpq failure | Ignore for final gate and rerun in Docker. |
| Coverage instrumentation SIGSEGV | Rerun with serialized tests if needed by setting `RUST_TEST_THREADS=1` in the coverage command environment. |

## Task 4: Compute Coverage With The Correct Scope

**Files:**

- Read: `oauth_backend_rust/lcov.info`
- Read: `oauth_backend_rust/codecov.yml`

- [ ] **Step 1: Do not rely on raw LCOV total alone**

The LCOV file can contain paths that need normalization before applying Codecov ignore rules. Compute at least:

- raw project coverage;
- Codecov-included production coverage after normalized ignore matching;
- `oauth_fapi_core` coverage for protocol/security files.

- [ ] **Step 2: Report the numbers in this format**

Use this exact result format in the handoff or PR note:

```text
raw: <hit>/<found> = <percent>%
codecov_included: <hit>/<found> = <percent>%
oauth_fapi_core: <hit>/<found> = <percent>% miss=<count>
lcov_source: oauth_backend_rust/lcov.info
coverage_command: Docker scripts/generate_codecov_lcov.sh
```

Expected:

- The previous known `oauth_fapi_core` baseline was `6709/6797 = 98.71%`.
- New numbers must be equal or better unless a previously ignored path is intentionally reintroduced and explained.

## Task 5: Close Remaining Core Misses

**Files:**

- Modify: protocol files listed in "High-priority protocol files"
- Modify: corresponding tests listed in "Representative tests"

- [ ] **Step 1: Sort remaining misses by protocol value**

Prioritize in this order:

1. authorization-code replay, consumed-marker, and failure-marker behavior;
2. token issuance before/after durable state writes;
3. revoke/introspect client lookup, privacy, and fail-closed behavior;
4. authorization decision and consent state race/failure behavior;
5. PAR/JAR/request object validation;
6. DPoP/mTLS proof and sender-constraint checks;
7. parser branches with direct input meaning;
8. random rejection-sampling or logging-only branches.

- [ ] **Step 2: For each missed line, classify before editing**

Use exactly one classification:

| Classification | Action |
|---|---|
| Reachable protocol behavior | Add or fix a focused test. |
| Reachable failure-closed behavior | Add a DB/Valkey/storage failure test using an actual queried column or active dependency path. |
| Duplicate/unreachable control flow | Remove or simplify the duplicate branch if doing so preserves behavior. |
| Randomness/internal loop | Leave untested unless a deterministic public behavior can be asserted without weakening randomness. |
| Logging-only branch | Do not distort code for coverage; document as residual risk if it remains. |

- [ ] **Step 3: Add tests near the owning module**

Examples of acceptable test intent:

```rust
#[actix_web::test]
async fn openid_issue_without_user_subject_fails_before_token_signing() {
    // The test must assert invalid_grant and absence of access_token,
    // refresh_token, and id_token.
}
```

```rust
#[actix_web::test]
async fn introspection_fails_closed_when_client_lookup_query_fails() {
    // The test must corrupt the actual isolated schema column used by
    // the query, then assert service_unavailable/server_error without
    // leaking active token metadata.
}
```

```rust
#[test]
fn requested_acr_claim_rejects_non_object_id_token_claims() {
    // The test should call the parser directly and assert Err(()),
    // not route through a full authorization request.
}
```

Do not add tests that only assert private implementation sequence when the public protocol response is unchanged.

- [ ] **Step 4: Run targeted tests before a full coverage run**

For parser-only tests:

```powershell
docker run --rm --network nazo-oauth-codecov-net `
  -v F:/projects/nazo_oauth/oauth_backend_rust:/workspace `
  -v nazo-oauth-cargo-registry:/usr/local/cargo/registry `
  -v nazo-oauth-cargo-git:/usr/local/cargo/git `
  -v nazo-oauth-codecov-target:/docker-target `
  -w /workspace `
  -e CARGO_TARGET_DIR=/docker-target/check `
  -e CARGO_BUILD_JOBS=1 `
  -e CARGO_TERM_COLOR=never `
  nazo-oauth-codecov-runner:local `
  bash -lc '. /usr/local/cargo/env && cargo test --locked --workspace --all-features --lib <test-filter> -- --nocapture'
```

For DB/Valkey-backed tests, start dependencies and run migrations first:

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
  bash -lc '. /usr/local/cargo/env && cargo run --locked --bin nazo-oauth-migrate && cargo test --locked --workspace --all-features --lib <test-filter> -- --nocapture'
```

Expected:

- Targeted tests pass before starting another full coverage run.

## Task 6: Final Verification

**Files:**

- Read: all modified files from `git status --short`
- Read: `oauth_backend_rust/lcov.info`
- Modify only if verification exposes a real issue

- [ ] **Step 1: Format**

Run:

```powershell
cargo fmt --manifest-path oauth_backend_rust/Cargo.toml --check
```

Expected:

- Exit code `0`.

- [ ] **Step 2: Docker compile**

Run the Docker `cargo check --locked --workspace --all-features` command from Task 2.

Expected:

- Exit code `0`.

- [ ] **Step 3: Docker coverage**

Run the Docker coverage command from Task 3.

Expected:

- Exit code `0`.
- Refreshed `lcov.info`.
- Reported `oauth_fapi_core` is at the selected target.

- [ ] **Step 4: CI-aligned quality**

If CI uses clippy and the local Docker runner lacks the clippy component, use GitHub Actions as the source of truth after pushing. If a local clippy-capable Linux environment is available, run:

```powershell
docker run --rm --network nazo-oauth-codecov-net `
  -v F:/projects/nazo_oauth/oauth_backend_rust:/workspace `
  -v nazo-oauth-cargo-registry:/usr/local/cargo/registry `
  -v nazo-oauth-cargo-git:/usr/local/cargo/git `
  -v nazo-oauth-codecov-target:/docker-target `
  -w /workspace `
  -e CARGO_TARGET_DIR=/docker-target/check `
  -e CARGO_BUILD_JOBS=1 `
  -e CARGO_TERM_COLOR=never `
  nazo-oauth-codecov-runner:local `
  bash -lc '. /usr/local/cargo/env && cargo clippy --locked --workspace --all-targets --all-features -- -D warnings'
```

Expected:

- Exit code `0`, or a documented environment limitation if the runner image lacks clippy.

## Task 7: Commit And PR Handoff

**Files:**

- Modify: none unless verification requires it

- [ ] **Step 1: Stage only source, tests, docs, and CI config**

Run:

```powershell
git -C oauth_backend_rust status --short
```

Stage only intentional files:

```powershell
git -C oauth_backend_rust add src tests docs codecov.yml scripts
```

Before committing, confirm no generated artifacts are staged:

```powershell
git -C oauth_backend_rust diff --cached --name-only
```

Expected:

- No `*.profraw`.
- No `target`.
- No temporary coverage logs.
- No secret-bearing `.env.yaml`.

- [ ] **Step 2: Commit**

Use a direct commit message:

```powershell
git -C oauth_backend_rust commit -m "test: raise oauth security coverage"
```

- [ ] **Step 3: Push**

Run:

```powershell
git -C oauth_backend_rust push origin codex/improve-codecov-coverage
```

- [ ] **Step 4: Check PR status**

Run:

```powershell
gh -R bymoye/NazoAuth pr checks 10
```

Expected:

- Format/quality gate passes.
- Rust tests pass.
- Coverage check passes or reports only the expected target comparison.
- CodeQL passes.
- Supply-chain gate passes.

If any check fails, fix the concrete failing job. Do not push unrelated coverage-ignore changes while a previous run is still pending.

## Final Delivery Format

The final response or PR note must include:

- changed behavior summary;
- security boundary summary;
- files changed by category;
- migration impact, explicitly saying `none` if no migration changed;
- new configuration impact, explicitly saying `none` if no config changed;
- verification commands and results;
- coverage numbers in the exact format from Task 4;
- remaining misses, if any, with classification and reason;
- PR check status.

## Completion Criteria

The task is complete only when all are true:

- Working tree has no unintended generated artifacts staged.
- `cargo fmt --check` passes.
- Docker `cargo check --locked --workspace --all-features` passes.
- Docker coverage command passes and refreshes `lcov.info`.
- `oauth_fapi_core` target is reached or residual misses are explicitly classified.
- PR #10 checks are green or every remaining non-green check is explained with a current failing job and next fix.
- The branch is pushed if the user or project workflow expects PR validation.
