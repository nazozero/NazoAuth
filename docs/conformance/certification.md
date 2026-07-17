# Certification and Conformance Evidence

This page is the entry point for certification status and current official-suite
evidence. Detailed protocol support is documented in
[Standards and profile support](../integration/openid-connect.md).

## OpenID Foundation certification listing

The OpenID Foundation certification pages list `Nazo Auth Server 0.1.0`, dated
`09-Jun-2026`, for the certified profiles below:

| Profile | Evidence |
| --- | --- |
| OIDC Basic OP | [Plan result](https://www.certification.openid.net/plan-detail.html?plan=Srk6iaVDVcqO5) |
| OIDC Config OP | [Plan result](https://www.certification.openid.net/plan-detail.html?plan=fGiz8QZYR1LVy) |

Official listing pages:

- [OpenID Connect Certified providers](https://openid.net/certification/#OPs)
- [Certified OpenID Provider profiles](https://openid.net/certification/certified-openid-providers-profiles/)
- [Certified FAPI 2.0 OP Security Profile Final and Message Signing Final](https://openid.net/certification/certified-fapi-2-0-op-security-profile-final-message-signing-final/)

## Current public black-box evidence

Current conformance evidence is recorded in
[2026-07-17 public black-box full OIDF results](2026-07-17-public-black-box-full-oidf-results.md).
The run used an operator-provided production HTTPS issuer. Public documentation
uses `https://issuer.example` only as a sanitized placeholder. Repository
workflows require operators to provide their own externally reachable
`OIDF_TARGET_ISSUER` and `OPENID4VC_TARGET_ORIGIN`.

| Matrix | Result | Scope |
| --- | --- | --- |
| OIDC / FAPI / FAPI-CIBA | Success | 25 official public plans: 23 concurrent plans plus 2 browser-isolated plans |
| OpenID4VC Final / HAIP | Success | 17 official-suite regression plans |

Combined exported result:

| Metric | Value |
| --- | ---: |
| Plan executions | 42 |
| Finished modules | 1,178 |
| Condition successes | 101,519 |
| Condition failures | 0 |
| Bounded warnings | 30 |
| Expected skips | 15 |
| Review entries | 136 |

The bounded warnings and expected skips are documented in the linked evidence
record. They are not hidden: the OIDC/FAPI/FAPI-CIBA matrix is not zero-warning
or zero-skipped evidence.

## Matrix scope

| Area | Scope document |
| --- | --- |
| OIDC / FAPI / FAPI-CIBA | [OIDF full matrix](oidf-full-matrix.md) |
| OpenID4VC Final / HAIP | [OpenID4VC Final matrix](openid4vc-final-matrix.md) |
| RFC 9967 SCIM SET local black-box regression | [RFC 9967 SCIM SET black-box matrix](rfc9967-scim-set-matrix.md) |

## Evidence boundary

Conformance claims for this repository must come from public black-box official
suite runs against an explicitly configured production issuer. Runs that depend
on non-public endpoints, private DNS names, private trust roots, local-only
callback origins, or suite-private hostnames are diagnostic runs and must not be
used as production conformance evidence.

OpenID4VC suite results are official-suite regression evidence. They are not an
OpenID Foundation certification listing unless the OpenID Foundation publishes a
matching certification result.
