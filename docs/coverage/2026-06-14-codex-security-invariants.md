# Codex Security Coverage Invariant Batch

Date: 2026-06-14
Branch: `codex/security-coverage-invariants`

This batch continues the effective-coverage work from
`docs/coverage/2026-06-14-security-coverage-checkpoint.md`.

## Baseline inspected

The latest reliable checkpoint records:

```text
TOTAL LH=7234 LF=15514 46.63%
src/support/sessions.rs LH=102 LF=186 54.84%
```

The same checkpoint identifies the next high-value production targets as
refresh-token lifecycle, repository state transitions, token issue/refresh,
federation, DPoP/mTLS, JAR/PAR/JARM, and resource-server verification. Those are
real protocol and security paths and remain in coverage.

## Tests added in this batch

### Resource server sender constraints

File: `tests/unit/src/resource_server/tests/security_invariants.rs`

Covered invariants:

- a resource server configured with `RequireMtlsThumbprint` accepts only the exact
  `cnf.x5t#S256` thumbprint;
- missing mTLS confirmation fails as `MissingSenderConstraint`;
- mismatched mTLS confirmation fails as `MtlsBindingMismatch`;
- `RequireAnySenderConstraint` accepts either DPoP `jkt` or mTLS `x5t#S256`;
- an empty or absent `cnf` object does not satisfy sender-constraint policy;
- a token presented with the DPoP authorization scheme must itself be
  sender-constrained;
- verified DPoP/mTLS proof material must exactly match the access-token
  confirmation claim.

### Settings and startup security policy

File: `tests/unit/src/settings/tests/security.rs`

Covered invariants:

- production HTTPS issuers cannot disable secure cookies;
- pairwise subject identifiers require stable pairwise secret material;
- FAPI2 profiles cap authorization-code lifetime at 60 seconds;
- FAPI2 profiles force PAR even when raw config disables it;
- FAPI2 profiles force required DPoP nonce policy;
- external signing command parsing trims empty segments without reordering argv.

### Refresh-token lifecycle and rotation policy

File: `tests/unit/src/http/token/tests/refresh_security.rs`

Covered invariants:

- refresh-token scope narrowing is exact and case-sensitive;
- refresh-token scope requests cannot add privileges outside the original grant;
- confidential holder-of-key client authentication preserves mTLS-bound refresh
  tokens where the implementation intentionally avoids rotating them;
- public clients and shared-secret authenticated clients do not preserve refresh
  tokens merely because a token has confirmation material;
- malformed refresh-token requests fail before storage lookup/token issuance and
  do not emit client-credentials challenges.

## Coverage exclusions

No coverage exclusions were added in this batch.

Existing exclusions remain limited to generated Diesel schema/row projection,
connection-pool glue, route wiring, thin Valkey command wrappers, thin binary
wrappers, test files, benches, examples, and migrations.

This batch does not exclude protocol core, security core, configuration
validation, token validation, repository state transitions, error mapping,
resource-server verification, DPoP, mTLS, PAR, JAR, JARM, or refresh-token
rotation logic.

## Validation status

The current execution environment could not run Rust validation commands:

- `git clone https://github.com/bymoye/NazoAuth.git` failed because DNS could not
  resolve `github.com`;
- `rustc --version` failed because the Rust toolchain is not installed in the
  container.

Therefore the following required commands were not run locally in this batch:

```sh
cargo fmt
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo llvm-cov ...
```

This document intentionally records that limitation instead of claiming a local
100% coverage result that was not produced.
