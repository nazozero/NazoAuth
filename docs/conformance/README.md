# Conformance Records

## Scope

Conformance records are the durable index for official suite evidence and
post-change suite regressions. GitHub Actions artifacts expire; these files keep
run metadata, plan IDs, artifact digests when available, and tested commit SHAs
in the repository.

## Current Evidence

- [2026-06-09 OIDF full matrix](2026-06-09-oidf-full-matrix.md)
- [2026-06-13 real public UI OIDF regression](2026-06-13-real-public-ui-regression.md)
- [2026-06-14 security-coverage OIDF full matrix](2026-06-14-local-refactor-full-matrix.md)

The latest official full-matrix workflow record before the current local
security-coverage batch is run `27500481513` against `https://auth.nazo.run` at
commit `8370f8123af310a7dae009609021c7320a19a725`. GitHub reported `success`.

The latest local full-matrix regression record is
`runtime/oidf/results-local-full-20260614T140947Z`. It exported all 16 plan
archives and a read-only Conformance Suite API audit found 562 module results:
559 `PASSED`, 3 allowed `REVIEW`, and no `FAILED`, `WARNING`, `SKIPPED`, or
`INTERRUPTED` results.

## Record Format

- implementation commit SHA
- current documentation commit SHA, when different
- workflow name and run URL, or local suite runner path
- job URL and matrix name, when applicable
- pass time and suite runtime
- profiles and feature combinations
- exported artifact name, digest, expiry, and zip filenames when applicable
- plan IDs and plan detail URLs
- pass/failure/warning counts
- any allowed review states
- notes about the public issuer, UI boundary, and test environment

## Boundary

Official suite output is indexed here. The files are not OpenID Foundation
certification statements.
