# Native Jiff migration

This change replaces application-owned Chrono timestamps with `jiff::Timestamp`
and elapsed durations with `jiff::SignedDuration`. It is stacked on the joint
mdoc/WebAuthn validation branch, not a production deployment.

## Boundaries

Domain APIs expose Jiff values directly. PostgreSQL uses the official
`jiff-diesel` scalar wrappers only at its SQL boundary. Borrowed query payloads,
transaction ownership, prepared-statement identities, timestamp column types,
and existing SQL statements are retained. Small SQL scalar wrappers live on the
existing query object when Diesel's AST needs their lifetimes; no payload copy
or second conversion batch is introduced for that purpose.

TTL and age calculations use fixed elapsed durations, not calendar `Span`s.
Invalid persisted or externally supplied instants fail at their existing error
boundary; they must not acquire a fresh wall-clock creation or expiry time.

The frozen audit-chain v1 encoding uses floor-rounded Unix microseconds,
including dates before 1970. Audit-anchor v2 timestamp serialization keeps its
0/3/6/9 fractional digit policy and `Z` offset. Runtime-management JSON retains
its existing fractional precision and `+00:00` representation. These specific
serializers stream to serde rather than allocate intermediate timestamp strings.
Ordinary timestamp-valued JSON fields retain their meaning; consumers must not
rely on a uniform number of trailing fractional zeros.

The official PostgreSQL adapter encodes signed microseconds relative to the
PostgreSQL epoch (2000-01-01). Its truncation rule is distinct from audit-chain
v1 floor rounding. Regression tests cover both sides of that epoch, both sides
of the Unix epoch, optional values and arrays.

### Certificate calendar bounds and CRL publication

The IACA validity ceiling is twenty calendar years, not a fixed number of days.
The profile first rejects certificate validity fields with fractional seconds,
then adds `Span::new().years(20)` to the UTC civil representation of `notBefore`.
Conversion and arithmetic failures retain the existing rejection boundary.
Certificate profile, issuer-binding, signature/path and revocation ownership
are unchanged.

CRL publication uses floor-rounded whole-second POSIX instants. Its publication
interval is exactly `SignedDuration::from_hours(24)`, not a calendar day.
Persisted fractional publication times, a non-24-hour interval, invalid revision
metadata and clock rollback remain errors. A CAS conflict reloads the winning
revocation facts and observes time again; reusing a publication retains its
persisted number and interval. The existing concurrency, reload, reseal,
invalid-metadata and revision-exhaustion regression assertions are retained.

### Protocol and application time

The mdoc protocol timestamp retains its own representation. Application Jiff
instants are POSIX values; converting an authenticated protocol leap second to
the application domain rejects it instead of silently changing the signed
instant. This is a documented application boundary, not a claim that ISO mdoc
has no leap seconds. The shared Jiff verification instant needs no second,
impossible Chrono-style leap-second check. Path and revocation verification
continue to use that shared current instant, never the credential's signed time.

## Joint source identity

The initial Jiff candidate `74f22b17` passed workspace/all-target/all-feature
locked compilation, formatting and warnings-denied Clippy in run 44142164247.
That result predates the current peer reconciliation.

Merge `313b96eee2b7efe71ec3ff9aa21bac8d0afcb734` preserves current joint peer
`e0014c4a7088085b7b08288ae5f739f27f3f818c` and the initial Jiff candidate. It
retains the peer's DS/IACA certificate profile, issuer binding, mDL issuer
attributes, shared verification instant and CRL publication checks. Both
independent integration PRs remain unchanged. No force-push, production merge,
security-policy exception or deployment is part of this migration.

The focused continuation through `ac870ad7784b3f8216be875f4b6e32fd3446879b`
repairs residual Chrono APIs in the reconciled IACA, CRL publication and mdoc
verification paths, plus the CRL test fixture. The audit-chain epoch regression
was moved intact to `crates/persistence/tests/unit/audit_chain.rs`, restoring the
repository's test-placement boundary rather than weakening that check.

## Validation status

Current-source acceptance is recorded in PR #289 with exact head commits and
GitHub Actions run IDs. It requires fresh warnings-denied Clippy, the complete
native PostgreSQL/Valkey test suite, documentation tests, WASM package checks
and runtime execution, and the existing supply-chain/real-HTTP security gates.
Earlier results are not a substitute. A successful preliminary step, an older
commit's result, or a skipped check is not an end-to-end gate pass. Until those
exact-source checks are complete, the migration remains a draft.
