# Conformance Records

## Scope

Conformance records are the durable index for official suite evidence and
post-change suite regressions. GitHub Actions artifacts expire; these files keep
run metadata, plan IDs, artifact digests when available, and tested commit SHAs
in the repository.

## Current Evidence

- Certification baseline: [2026-06-09 OIDF full matrix](2026-06-09-oidf-full-matrix.md)
- Matrix scope: [OIDF full matrix](oidf-full-matrix.md)
- Latest private full-matrix regression: [2026-07-01 TP/PS OIDF full matrix](2026-07-01-tp-ps-full-matrix.md)
- Latest official full matrix: [2026-06-27 PR 15 official OIDF full matrix](2026-06-27-pr15-official-oidf-full-matrix.md)
- Latest RFC coverage check: [2026-07-01 NI-002 RFC 8628 OIDF coverage](2026-07-01-ni-002-oidf-coverage.md)

The latest recorded official full-matrix suite run is the 2026-06-27 PR 15
run against `https://auth.nazo.run`. The deployed runtime implementation was
`be7ef9f6a9197520235a59d42866a0918a293014`, and the current PR head at
verification time was `bac10af902e574d4bd98741eaa2ce0121278608c`. It exported
all 16 plan archives from `https://www.certification.openid.net/`; the final
runner output reported `0 failures` and `0 warnings`.

The latest private full-matrix regression record is the 2026-07-01 TP/PS run
against `https://auth.nazo.run` at runtime commit `31e8f9f`. It used the
repository 16-plan matrix, exported 16 plan archives, and reported 578 test
modules with `0 failures` and `0 warnings`.

## Coverage Update Rule

Every newly supported RFC, OIDC/FAPI profile, or standards-track protocol
capability must trigger an OIDF suite coverage check. Search the OpenID
Foundation Conformance Suite official production/staging plans, public source,
and release notes for matching official tests.

If official coverage exists, update the repository OIDF matrix execution in the
same change, including the workflow/config inputs, plan list, matrix
documentation, and conformance record. If official coverage does not exist,
record the negative search result and date in the relevant implementation or
conformance record. Local positive, negative, metadata-truth, and
security-boundary tests remain mandatory either way.

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
