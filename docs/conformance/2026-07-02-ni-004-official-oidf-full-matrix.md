# 2026-07-02 NI-004 Official OIDF Full Matrix

## Outcome

OpenID Foundation Conformance Suite official full-matrix regression for the
NI-004 dynamic client registration hardening branch, executed against the public
issuer at `https://auth.nazo.run`.

The GitHub Actions workflow completed successfully. The suite reported `0
failures` and `0 warnings`, but the run was not a zero-SKIPPED run: two OIDC
dynamic-registration modules were skipped by the official runner and allowed by
the repository `oidf-expected-skips.json` file generated in the workflow.

| Field | Value |
| --- | --- |
| Result | Passed with expected skips |
| Zero-SKIPPED gate | Not met |
| Workflow | `oidf-conformance-full` |
| Workflow run | <https://github.com/nazozero/NazoAuth/actions/runs/28536018404> |
| Job | <https://github.com/nazozero/NazoAuth/actions/runs/28536018404/job/84597453834> |
| Trigger | `workflow_dispatch` |
| Started | `2026-07-01T17:32:57Z` / `2026-07-02 01:32:57 +08:00` |
| Completed | `2026-07-01T17:44:23Z` / `2026-07-02 01:44:23 +08:00` |
| Branch | `codex/ni-004-dynamic-client-registration` |
| Workflow head SHA | `0b00ea7d50443cb54fc17631a9238126fa837e42` |
| Runtime implementation commit | Not independently recorded in this workflow log |
| Public issuer under test | `https://auth.nazo.run` |
| Conformance server | `https://www.certification.openid.net/` |
| Official suite ref | `33a724c7d809a6f9db05cbb513ff2a77cbac905e` |
| Plan set | Generated `oidf-full-plan-set.json` in `.github/workflows/oidf-conformance-full.yml` |
| Expected skips file | Generated `oidf-expected-skips.json` in `.github/workflows/oidf-conformance-full.yml` |
| GitHub artifact export | None; the run used the default `OIDF_EXPORT_RESULTS=false` path |
| Final line | `All tests ran to completion. See above for any test condition failures.` |

## Summary

Parsed runner totals:

| Metric | Value |
| --- | ---: |
| Plan summaries | `17` |
| Test modules reported by plan summaries | `617` |
| Success conditions | `46560` |
| Failure conditions | `0` |
| Warning conditions | `0` |
| Skipped module instances | `2` |

## Expected Skips

The skipped modules were both in plan 2, the dynamic-client-registration OIDC
Basic OP plan at
<https://www.certification.openid.net/plan-detail.html?plan=k9vtssH5SjqqT>.

| Module | Variant | Result | Rationale |
| --- | --- | --- | --- |
| `oidcc-idtoken-unsigned` | `client_auth_type=client_secret_basic`, `response_mode=default`, `response_type=code` | `SKIPPED` | Nazo Auth does not advertise unsigned ID Token support. The deployed issuer advertises `id_token_signing_alg_values_supported` as signed algorithms only (`PS256`, `RS256` at verification time). Adding `none` for ID Tokens would weaken the product surface and is not needed for the current OIDC/FAPI evidence matrix. |
| `oidcc-request-uri-unsigned-supported-correctly-or-rejected-as-unsupported` | `client_auth_type=client_secret_basic`, `response_mode=default`, `response_type=code` | `SKIPPED` | The deployed issuer advertises `request_uri_parameter_supported=false`. The current security posture prefers PAR and direct request-object compatibility over enabling OIDC `request_uri` support just to exercise this optional module. |

Assessment: these skips are reasonable for the current matrix because both
correspond to optional OIDC compatibility surfaces that are intentionally not
enabled in the deployed issuer. They are still real `SKIPPED` results, so this
record must not be cited as zero-SKIPPED evidence.

If a future release requires a zero-SKIPPED official matrix, the acceptance
criterion must change from "workflow success with expected skips" to "no module
result is SKIPPED". That would require either changing product capabilities and
metadata so these modules run, or changing the matrix scope. The stronger gate
should also remove `--expected-skips-file` from the workflow or make it empty.

## Plan Results

| # | Scope | Plan ID | Modules | Successes | Failures | Warnings | Skipped |
| ---: | --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | OIDC Basic OP, static client | [rgX0h0HUIVRoB](https://www.certification.openid.net/plan-detail.html?plan=rgX0h0HUIVRoB) | 36 | 1926 | 0 | 0 | 0 |
| 2 | OIDC Basic OP, dynamic client registration | [k9vtssH5SjqqT](https://www.certification.openid.net/plan-detail.html?plan=k9vtssH5SjqqT) | 39 | 2280 | 0 | 0 | 2 |
| 3 | OIDC Config OP | [c3NJTCkznTiDQ](https://www.certification.openid.net/plan-detail.html?plan=c3NJTCkznTiDQ) | 2 | 40 | 0 | 0 | 0 |
| 4 | FAPI2 Message Signing, `private_key_jwt`, DPoP, OIDC, JARM | [ZZSBuiGwGD4Ri](https://www.certification.openid.net/plan-detail.html?plan=ZZSBuiGwGD4Ri) | 71 | 6684 | 0 | 0 | 0 |
| 5 | FAPI2 Message Signing, `private_key_jwt`, DPoP, OIDC, plain response | [KUtv2dZtYSlAs](https://www.certification.openid.net/plan-detail.html?plan=KUtv2dZtYSlAs) | 71 | 6238 | 0 | 0 | 0 |
| 6 | FAPI2 Security, mTLS client auth, DPoP sender, OIDC | [LJaGCMCPSNHhw](https://www.certification.openid.net/plan-detail.html?plan=LJaGCMCPSNHhw) | 47 | 4531 | 0 | 0 | 0 |
| 7 | FAPI2 Security, mTLS client auth, DPoP sender, client credentials | [r0ayTKD6KTvBa](https://www.certification.openid.net/plan-detail.html?plan=r0ayTKD6KTvBa) | 10 | 1039 | 0 | 0 | 0 |
| 8 | FAPI2 Security, mTLS client auth, DPoP sender, plain OAuth | [UhSHtjuPP89y1](https://www.certification.openid.net/plan-detail.html?plan=UhSHtjuPP89y1) | 41 | 3430 | 0 | 0 | 0 |
| 9 | FAPI2 Security, mTLS client auth, mTLS sender, OIDC | [sUiqhHxfljlBj](https://www.certification.openid.net/plan-detail.html?plan=sUiqhHxfljlBj) | 38 | 2507 | 0 | 0 | 0 |
| 10 | FAPI2 Security, mTLS client auth, mTLS sender, client credentials | [wk6zwOA4NDnOM](https://www.certification.openid.net/plan-detail.html?plan=wk6zwOA4NDnOM) | 6 | 199 | 0 | 0 | 0 |
| 11 | FAPI2 Security, mTLS client auth, mTLS sender, plain OAuth | [cg06u0v45flTK](https://www.certification.openid.net/plan-detail.html?plan=cg06u0v45flTK) | 32 | 1667 | 0 | 0 | 0 |
| 12 | FAPI2 Security, `private_key_jwt`, DPoP sender, OIDC | [xH8wGTSqocrW7](https://www.certification.openid.net/plan-detail.html?plan=xH8wGTSqocrW7) | 57 | 5141 | 0 | 0 | 0 |
| 13 | FAPI2 Security, `private_key_jwt`, DPoP sender, client credentials | [WPnT0h0NCU1uk](https://www.certification.openid.net/plan-detail.html?plan=WPnT0h0NCU1uk) | 15 | 1172 | 0 | 0 | 0 |
| 14 | FAPI2 Security, `private_key_jwt`, DPoP sender, plain OAuth | [9322y9fxlH7qf](https://www.certification.openid.net/plan-detail.html?plan=9322y9fxlH7qf) | 51 | 3927 | 0 | 0 | 0 |
| 15 | FAPI2 Security, `private_key_jwt`, mTLS sender, OIDC | [M2QMqg0kDzM0T](https://www.certification.openid.net/plan-detail.html?plan=M2QMqg0kDzM0T) | 48 | 3205 | 0 | 0 | 0 |
| 16 | FAPI2 Security, `private_key_jwt`, mTLS sender, client credentials | [1HnDW9X3hGnWT](https://www.certification.openid.net/plan-detail.html?plan=1HnDW9X3hGnWT) | 11 | 338 | 0 | 0 | 0 |
| 17 | FAPI2 Security, `private_key_jwt`, mTLS sender, plain OAuth | [ndalD364e3iR8](https://www.certification.openid.net/plan-detail.html?plan=ndalD364e3iR8) | 42 | 2236 | 0 | 0 | 0 |

## Verification Notes

- `gh run view 28536018404 --repo nazozero/NazoAuth --json ...` reported
  workflow conclusion `success`.
- `gh run view 28536018404 --repo nazozero/NazoAuth --job 84597453834 --log`
  reported the two `SKIPPED` module lines and printed `Test was skipped as
  expected` for both.
- The public plan-detail URL may redirect to the OIDF login page unless the
  viewer has an authenticated conformance-suite session.
- The public GitHub Actions page is visible, but raw job logs require GitHub
  access.

## Boundary

This is a conformance evidence record for a deployed runtime and one workflow
run. It is not an OpenID Foundation certification listing, and because it
contains expected skips it is not zero-SKIPPED release evidence.
