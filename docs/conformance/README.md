# Conformance Records

## Scope

Conformance records are the durable index for official suite evidence and
post-change suite regressions. GitHub Actions artifacts expire; these files keep
run metadata, plan IDs, artifact digests when available, and tested commit SHAs
in the repository.

## Current Evidence

- [2026-06-09 OIDF full matrix](2026-06-09-oidf-full-matrix.md)
- [2026-06-13 real public UI OIDF regression](2026-06-13-real-public-ui-regression.md)

The latest official full-matrix workflow record is run `27491182262` against
`https://auth.nazo.run` at commit
`31c3d0665ec72ffb4babedfea519ed175ef403ad`. GitHub reported `success`; the
official runner reported 71 test modules, 6375 successes, `0 failures`, and
`0 warnings`. The exported artifact is `oidf-conformance-results-full` with
digest
`sha256:3faed1f41a2258c8b948d73b0356dd8bbe7b6b701afd3c845939b3ea17585d8a`.

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
