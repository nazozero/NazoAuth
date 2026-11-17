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

The mdoc protocol timestamp retains its own representation. Application Jiff
instants are POSIX values; converting an authenticated protocol leap second to
the application domain rejects it instead of silently changing the signed
instant. This is a documented application boundary, not a claim that ISO mdoc
has no leap seconds.

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

## Validation status

The reconciled source requires fresh compilation, warnings-denied lint,
PostgreSQL/Valkey tests, documentation tests, WASM runtime checks and the existing
supply-chain/real-HTTP security gates. Earlier results are not a substitute.
This document will be updated with the actual completed exact-source outcomes;
while those checks are pending, the migration remains a draft.
