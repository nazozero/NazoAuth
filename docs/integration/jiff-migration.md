# Native Jiff time boundaries

Application and domain APIs use `jiff::Timestamp` for instants and
`jiff::SignedDuration` for elapsed time. Jiff uses the POSIX time scale. TTLs,
retry intervals and token ages use elapsed time, not calendar-day arithmetic.
Invalid external or persisted instants fail at the owning boundary; they never
acquire a replacement creation or expiry time from the wall clock.

## PostgreSQL

The official `jiff-diesel` types are confined to the PostgreSQL adapter. Domain
and persistence ports remain independent of Diesel. Query objects retain only
the timestamp scalar wrappers required by Diesel's bind lifetimes; request
payloads remain borrowed and prepared-query identities are unchanged.

PostgreSQL stores signed microseconds relative to 2000-01-01. Its adapter
truncates submicrosecond differences toward zero. This database precision rule
is distinct from the frozen audit-chain v1 rule below. Nullable timestamps and
timestamp arrays use the same official adapter. SQL and column types do not
change with this migration.

## Serialization and audit identity

Ordinary timestamp-valued JSON fields serialize the typed instant directly.
Consumers parse the timestamp, rather than requiring a fixed number of trailing
fractional zeros. String-typed response fields and HTTP headers still require
owned text.

Audit-chain v1 hashes floor-rounded Unix microseconds, including dates before
1970. Audit-anchor v2 checkpoints and v1 receipt signatures serialize 0/3/6/9
fractional digits and a `Z` offset. The independent receiver uses the same frozen
format, including pre-epoch hash rounding. Runtime-management JSON retains
0/3/6/9 digits and `+00:00`. These frozen formats
stream directly into serde without an intermediate timestamp string. The runtime
HTTP boundary converts `web_time::SystemTime` through epoch nanoseconds because
its WASM type is distinct from the standard library's `SystemTime`.

## Credentials and certificates

Credential privacy times are floored to the start of their UTC day without
extending the original deadline. If midnight falls outside Jiff's representable
range, the original instant is retained.

The IACA validity ceiling uses twenty calendar years in UTC, including leap-year
month-end adjustment; it is not a fixed day count. Certificate validity fields
must have whole-second precision. CRL publication instead uses an exact elapsed
24-hour interval and floor-rounded whole seconds. Its persisted publication
identity, CAS conflict handling and clock-rollback rejection remain unchanged.

The mdoc protocol type retains its wire-time semantics. Conversion to the POSIX
application type is fallible: an authenticated protocol leap second cannot be
silently replaced with a neighboring instant and is rejected at that boundary.
There is no application leap-second calendar or compatibility layer. Certificate
path and revocation checks use the same current verification instant, not the
credential's signed time.
