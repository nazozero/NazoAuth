# 2026-06-07 OIDF Full Matrix

## Summary

This record preserves the OpenID Foundation Conformance Suite result index for
the full 16-plan matrix that passed on `main` for the version 1 profile set.

| Field | Value |
| --- | --- |
| Result | Passed |
| Failures | `0` across all plans |
| Warnings | `0` across all plans |
| Workflow | `oidf-conformance-full` |
| Matrix job | `oidf-conformance-full` |
| Workflow run | <https://github.com/bymoye/oauth2_server/actions/runs/27101793794> |
| Job URL | <https://github.com/bymoye/oauth2_server/actions/runs/27101793794/job/79983734940> |
| Workflow event | `workflow_dispatch` |
| Head branch | `main` |
| Implementation commit | `dd5be83823c1d992592dc0b38a174c4b6b224e98` |
| Public issuer under test | `https://oauth-test.nazo.run` |
| Conformance server | `https://www.certification.openid.net/` |
| Started | `2026-06-07T18:59:34Z` |
| Completed | `2026-06-07T20:24:57Z` |
| Runtime | 1h 25m 23s |
| Artifact | `oidf-conformance-results-full` |
| Artifact ID | `7467654875` |
| Artifact digest | `sha256:b80028c5ac795c56d4ce11d3bdc0836d1df02b8f007eb15836088c18a354db6c` |
| Artifact size | `15089021` bytes |
| Artifact created | `2026-06-07T20:24:55Z` |
| Artifact expires | `2026-09-05T18:59:35Z` |
| Post-run selector sweep | `2026-06-08`: all 16 plans returned `Selected modules: 0` and empty `OIDF_RERUN` |

## Coverage

Important profiles and protocol features covered by this run:

- OIDC Basic OP certification plan
- OIDC Config OP certification plan
- FAPI2 Security Profile Final
- FAPI2 Message Signing Final
- FAPI2 client credentials grant variants
- `private_key_jwt`
- mTLS client authentication
- DPoP sender constraint
- mTLS sender constraint
- PAR
- signed request objects / JAR
- JARM and plain authorization responses
- OpenID Connect and plain OAuth modes

## Plan Results

All listed plans completed with no selected rerun modules in the post-run
selector sweep.

| # | Suite / profile | Client auth | Sender constraint | Mode | Variant | Plan ID | Result |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | OIDC Basic OP certification | static client | n/a | OpenID Connect | discovery | [`87bOQUdyMc5Rp`](https://www.certification.openid.net/plan-detail.html?plan=87bOQUdyMc5Rp) | Passed; selector clean |
| 2 | OIDC Config OP certification | n/a | n/a | OpenID Connect | server metadata | [`K4YFaqR7SYTeS`](https://www.certification.openid.net/plan-detail.html?plan=K4YFaqR7SYTeS) | Passed; selector clean |
| 3 | FAPI2 Message Signing Final | `private_key_jwt` | `dpop` | OpenID Connect | JARM | [`JNFchTM1q78fa`](https://www.certification.openid.net/plan-detail.html?plan=JNFchTM1q78fa) | Passed; selector clean |
| 4 | FAPI2 Message Signing Final | `private_key_jwt` | `dpop` | OpenID Connect | plain response / JAR | [`YhcGfBtmjnNot`](https://www.certification.openid.net/plan-detail.html?plan=YhcGfBtmjnNot) | Passed; selector clean |
| 5 | FAPI2 Security Profile Final | `mtls` | `dpop` | OpenID Connect | plain FAPI | [`fpoAWLrdzLpUs`](https://www.certification.openid.net/plan-detail.html?plan=fpoAWLrdzLpUs) | Passed; selector clean |
| 6 | FAPI2SP Client Credentials | `mtls` | `dpop` | plain OAuth | client credentials | [`oHjLerkwhuEew`](https://www.certification.openid.net/plan-detail.html?plan=oHjLerkwhuEew) | Passed; selector clean |
| 7 | FAPI2 Security Profile Final | `mtls` | `dpop` | plain OAuth | plain FAPI | [`ZO5DoHtpYvtd1`](https://www.certification.openid.net/plan-detail.html?plan=ZO5DoHtpYvtd1) | Passed; selector clean |
| 8 | FAPI2 Security Profile Final | `mtls` | `mtls` | OpenID Connect | plain FAPI | [`ipXfsQnCbeY5J`](https://www.certification.openid.net/plan-detail.html?plan=ipXfsQnCbeY5J) | Passed; selector clean |
| 9 | FAPI2SP Client Credentials | `mtls` | `mtls` | plain OAuth | client credentials | [`nvZJd4vr0IqXx`](https://www.certification.openid.net/plan-detail.html?plan=nvZJd4vr0IqXx) | Passed; selector clean |
| 10 | FAPI2 Security Profile Final | `mtls` | `mtls` | plain OAuth | plain FAPI | [`FUoOGumcgKpJz`](https://www.certification.openid.net/plan-detail.html?plan=FUoOGumcgKpJz) | Passed; selector clean |
| 11 | FAPI2 Security Profile Final | `private_key_jwt` | `dpop` | OpenID Connect | plain FAPI | [`bXXPQwWXHxV7E`](https://www.certification.openid.net/plan-detail.html?plan=bXXPQwWXHxV7E) | Passed; selector clean |
| 12 | FAPI2SP Client Credentials | `private_key_jwt` | `dpop` | plain OAuth | client credentials | [`u604H5ZpGo2tY`](https://www.certification.openid.net/plan-detail.html?plan=u604H5ZpGo2tY) | Passed; selector clean |
| 13 | FAPI2 Security Profile Final | `private_key_jwt` | `dpop` | plain OAuth | plain FAPI | [`ZegrCZxXAsN3y`](https://www.certification.openid.net/plan-detail.html?plan=ZegrCZxXAsN3y) | Passed; selector clean |
| 14 | FAPI2 Security Profile Final | `private_key_jwt` | `mtls` | OpenID Connect | plain FAPI | [`AiGm3vZvKF6co`](https://www.certification.openid.net/plan-detail.html?plan=AiGm3vZvKF6co) | Passed; selector clean |
| 15 | FAPI2SP Client Credentials | `private_key_jwt` | `mtls` | plain OAuth | client credentials | [`YWUXCatXsSwOd`](https://www.certification.openid.net/plan-detail.html?plan=YWUXCatXsSwOd) | Passed; selector clean |
| 16 | FAPI2 Security Profile Final | `private_key_jwt` | `mtls` | plain OAuth | plain FAPI | [`FA9CyMHySCQbC`](https://www.certification.openid.net/plan-detail.html?plan=FA9CyMHySCQbC) | Passed; selector clean |

## Exported Artifact Filenames

These are the 16 zip files inside `oidf-conformance-results-full`:

- `oidcc-basic-certification-test-plan-discovery-static_client-87bOQUdyMc5Rp-07-Jun-2026.zip`
- `oidcc-config-certification-test-plan--K4YFaqR7SYTeS-07-Jun-2026.zip`
- `fapi2-message-signing-final-test-plan-private_key_jwt-dpop-simple-openid_connect-signed_non_repudiation-plain_fapi-jarm-JNFchTM1q78fa-07-Jun-2026.zip`
- `fapi2-message-signing-final-test-plan-private_key_jwt-dpop-simple-openid_connect-signed_non_repudiation-plain_fapi-plain_response-YhcGfBtmjnNot-07-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-openid_connect-plain_fapi-fpoAWLrdzLpUs-07-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-plain_oauth-fapi_client_credentials_grant-oHjLerkwhuEew-07-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-plain_oauth-plain_fapi-ZO5DoHtpYvtd1-07-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-openid_connect-plain_fapi-ipXfsQnCbeY5J-07-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-plain_oauth-fapi_client_credentials_grant-nvZJd4vr0IqXx-07-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-plain_oauth-plain_fapi-FUoOGumcgKpJz-07-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-openid_connect-plain_fapi-bXXPQwWXHxV7E-07-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-plain_oauth-fapi_client_credentials_grant-u604H5ZpGo2tY-07-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-plain_oauth-plain_fapi-ZegrCZxXAsN3y-07-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-openid_connect-plain_fapi-AiGm3vZvKF6co-07-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-plain_oauth-fapi_client_credentials_grant-YWUXCatXsSwOd-07-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-plain_oauth-plain_fapi-FA9CyMHySCQbC-07-Jun-2026.zip`

## Workflow Steps

The GitHub job completed every step successfully:

| Step | Result |
| --- | --- |
| checkout | success |
| setup Python 3.13 | success |
| clone official conformance suite | success |
| install official runner dependencies | success |
| write full OIDF matrix plan set | success |
| write full OIDF matrix config | success |
| run full OIDF matrix | success |
| upload result archive | success |

## Notes

- This record indexes official suite output for commit `dd5be83823c1d992592dc0b38a174c4b6b224e98`.
- The post-run selector sweep returned no modules requiring rerun for all 16 plan IDs.
- This record is not itself an OpenID Foundation certification statement.
