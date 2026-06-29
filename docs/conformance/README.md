# Conformance Records

## Scope

Conformance records are the durable index for official suite evidence and
post-change suite regressions. GitHub Actions artifacts expire; these files keep
run metadata, plan IDs, artifact digests when available, and tested commit SHAs
in the repository.

## Current Evidence

- Certification baseline: [2026-06-09 OIDF full matrix](2026-06-09-oidf-full-matrix.md)
- Latest Hostinger-local full matrix: [2026-06-26 security findings OIDF full matrix](2026-06-26-security-findings-full-matrix.md)
- Latest official full matrix: [2026-06-27 PR 15 official OIDF full matrix](2026-06-27-pr15-official-oidf-full-matrix.md)

The latest recorded official full-matrix suite run is the 2026-06-27 PR 15
run against `https://auth.nazo.run`. The deployed runtime implementation was
`be7ef9f6a9197520235a59d42866a0918a293014`, and the current PR head at
verification time was `bac10af902e574d4bd98741eaa2ce0121278608c`. It exported
all 16 plan archives from `https://www.certification.openid.net/`; the final
runner output reported `0 failures` and `0 warnings`.

The latest Hostinger-local full-matrix regression record is
`oidf-local-results/run-20260626T165725Z` for the same public issuer and commit.
It exported all 16 plan archives; the runner log contains 16 plan summaries,
all with `0 failures` and `0 warnings`.

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

## Request Object Compatibility

Baseline OIDC metadata advertises `none` in
`request_object_signing_alg_values_supported` so the server can exercise OIDC
conformance tests for unsigned Request Objects. This is a compatibility feature,
not a high-security profile feature.

Unsigned Request Objects remain disallowed for FAPI2 profiles, clients that
require PAR request objects, and holder-bound clients. Those paths require
signed Request Objects or reject the request object fail closed.
