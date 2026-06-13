# Conformance Records

## Scope

Conformance records are the durable index for official suite evidence and
post-change suite regressions. GitHub Actions artifacts expire; these files keep
run metadata, plan IDs, artifact digests when available, and tested commit SHAs
in the repository.

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
