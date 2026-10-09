# CodeQL fixture follow-up — 2026-10-09

Final source: `e195844aad31a4cb8796dd751d94424e5e4413cb`. Runtime/performance source: `b5b0f4246d8a443466a1c256429a76f88bf2c6e0`.
Prior report remains unchanged at `894a3f119cfdaab519f79481f5844e5921ed8313` in [the complete model and capacity report](../publish/README.md).

The first report-head CodeQL check failed with six hard-coded cryptographic-value alerts, all in three test files. The annotations and failed check output are retained here. These were test-only keys, not production key material. No alerts were dismissed and no query, security gate or test assertion was removed.

Tests now generate ephemeral encryption keys and nonces. The two TOTP repository tests enroll and exercise the same randomly generated secret. Their fixture excludes neighboring six-digit code collisions so randomness cannot invalidate the intended exact-step/replay assertions. Fixed protocol-vector tests elsewhere remain unchanged.

## Validation

- PostgreSQL unit tests: [('78', '0', '0')] (passed, failed, ignored).
- Real PostgreSQL identity repository tests: [('61', '0', '0')] (passed, failed, ignored). The existing authorized isolated PG fixture was started; database configuration was present, so tests did not take the missing-fixture return.
- Format and complete workspace/all-target/all-feature Clippy: exit 0.
- Commands, raw logs and exit codes are included in `verification.json` and adjacent files.
- Production code, migrations, dependencies, runtime configuration, and all load parameters remain identical to the short-tested source. The original four PASS points, 60,000 natural decision deletions and their limitations remain applicable through `source-equivalence.json`; no new load test is claimed.
- The previous 3,701-test workspace suite and explicit FAPI evidence remain in the original report. Final report-head CI will be recorded on the PR after this follow-up is pushed; this document does not predeclare CI success.

CODE, SECURITY, RECOVERY, PERFORMANCE and short-test STORAGE retain their documented local PASS scopes. Long-term storage remains unmeasured. The higher historical-relative revoke tail/PG CPU and some storage costs remain unresolved qualifications, not universal-improvement claims.
