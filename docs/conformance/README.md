# Conformance Records

## Scope

Conformance records are the durable index for official suite evidence and
post-change suite regressions. GitHub Actions artifacts expire; these files keep
run metadata, plan IDs, artifact digests when available, and tested commit SHAs
in the repository.

## Current Evidence

- [2026-06-09 OIDF full matrix](2026-06-09-oidf-full-matrix.md)
- [2026-06-13 real public UI OIDF regression](2026-06-13-real-public-ui-regression.md)

The latest official full-matrix workflow record is run `27472766776` against
`https://auth.nazo.run` at commit
`c9a5a19c651ce2cd8b6861ceaf66b135569764c6`. GitHub reported `success`; the
official runner reported 71 test modules, 5929 successes, `0 failures`, and
`0 warnings`. The exported artifact is `oidf-conformance-results-full` with
digest
`sha256:54c39e3bc8a5602fa3e4deed522256699f12b033a678229c7c2eb83090ffb7e8`.

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
