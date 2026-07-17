# 2026-07-16 OpenID4VC Final / HAIP OIDF results

Superseded for current conformance evidence by
[2026-07-17 Public Black-Box Full OIDF Results](2026-07-17-public-black-box-full-oidf-results.md).
This file remains a historical implementation record. Current conformance
evidence must use public black-box official-suite runs against
`https://issuer.example`, not local suite endpoints or private test roots.

## Summary

OpenID4VCI Credential Issuer and OpenID4VP Verifier passed both required
conformance gates against the public production deployment:

| Gate | Result |
|---|---|
| Hostinger local official-suite matrix targeting `https://issuer.example` | `success` |
| GitHub official OpenID4VC matrix targeting `https://issuer.example` | `success` |
| PR #60 required checks | `success` |

This is official-suite regression evidence for the OIDF v5.2.0 OpenID4VC
Final/HAIP alpha plans. It is **not** an OpenID Foundation certification claim;
the upstream plan titles remain alpha and outside the formal certification
program.

## Tested revision and deployment

| Item | Value |
|---|---|
| Implementation branch | `agent/openid4vc-final` |
| Tested commit | `8b2f7a70cd4d51f4ff668ea761a6562616a90c37` |
| Production issuer / verifier origin | `https://issuer.example` |
| Hostinger image | `localhost/nazo-oauth-server:openid4vc-8b2f7a70` |
| Production OCI revision | `8b2f7a70cd4d51f4ff668ea761a6562616a90c37` |
| OIDF suite commit | `dee9a25160e789f0f80517674693ef7989ab9fa1` (`v5.2.0`) |
| Official workflow | [`openid4vc-conformance`](https://github.com/nazozero/NazoAuth/actions/runs/29530484889) |
| Official job | [`official-openid4vc-matrix`](https://github.com/nazozero/NazoAuth/actions/runs/29530484889/job/87729342552) |

## Plan scope

The matrix expands four upstream plans into 17 bounded executions:

- `oid4vci-1_0-issuer-test-plan`
- `oid4vci-1_0-issuer-haip-test-plan`
- `oid4vp-1final-verifier-test-plan`
- `oid4vp-1final-verifier-haip-test-plan`

Covered axes include `dc+sd-jwt`, `mso_mdoc`, issuer- and wallet-initiated VCI,
authorization-code and pre-authorized-code VCI, DPoP/private-key client
authentication, signed and encrypted credential flows, OpenID4VP
`direct_post`/`direct_post.jwt`, URL-query and signed request-URI retrieval,
`x509_san_dns`, `x509_hash`, and HAIP issuer/verifier combinations.

## Hostinger local production-target run

The Hostinger local run used the locally hosted official suite as the
conformance server and `https://issuer.example` as the tested production target.
It did not test a local issuer/verifier origin.

| Item | Value |
|---|---|
| Materialized config directory | `/root/oauth2_server/openid4vc-deploy/oidf-materialized-8b2f7a70-local-prod` |
| Result log | `/root/oauth2_server/openid4vc-deploy/runs-8b2f7a70-prod-target-20260717035800.log` |
| Result directory | `/root/oauth2_server/openid4vc-deploy/runs-8b2f7a70-prod-target-20260717035800` |
| Plans completed | `17 / 17` |
| Failures | `0` |
| Warnings | `4` expected HAIP refresh-token warnings |

The log ends with `All tests ran to completion. See above for any test
condition failures.` Every plan summary reported `0 failures`; 13 plans reported
`0 warnings`, and four HAIP plans reported one bounded refresh-token warning.

## Official GitHub run

The official workflow ran from the same exact source revision and against
`https://issuer.example`.

| Item | Value |
|---|---|
| Run URL | <https://github.com/nazozero/NazoAuth/actions/runs/29530484889> |
| Job URL | <https://github.com/nazozero/NazoAuth/actions/runs/29530484889/job/87729342552> |
| Status | `success` |
| Runtime | `17m38s` |
| Exported plan archives | `17` |
| Exported module logs | `391` |
| Module status | `391 FINISHED` |
| Condition successes | `41,781` |
| Review states | `32` |
| Skipped conditions/modules | `7` |
| Warnings | `4` expected HAIP refresh-token warnings |
| Failures | `0` |

The exported artifact is
`openid4vc-conformance-8b2f7a70cd4d51f4ff668ea761a6562616a90c37`.

The four warnings are all the official suite's
`fapi2-security-profile-final-refresh-token` advisory:

> The server supports refresh tokens, but did not issue one.

This is expected for the bounded HAIP client policy and does not represent a
failed condition.

## Evidence boundary

The OIDF v5.2.0 OpenID4VC plans are explicitly alpha. These results prove that
the deployed production implementation completed the available upstream
OpenID4VC Final/HAIP regression plans. They do not authorize use of the OpenID
Certified mark for OpenID4VC.
