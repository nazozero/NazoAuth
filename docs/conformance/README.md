# Conformance Records

## Scope

Conformance records are the durable index for official suite evidence. GitHub
Actions artifacts expire; these files keep run metadata, plan IDs, artifact
digests, and tested commit SHAs in the repository.

## Record Format

- implementation commit SHA
- current documentation commit SHA, when different
- workflow name and run URL
- job URL and matrix name
- pass time and suite runtime
- profiles and feature combinations
- exported artifact name, digest, expiry, and zip filenames
- plan IDs and plan detail URLs
- pass/failure/warning counts
- any allowed review states
- notes about the public issuer and test environment

## Boundary

Official suite output is indexed here. The files are not OpenID Foundation
certification statements.
