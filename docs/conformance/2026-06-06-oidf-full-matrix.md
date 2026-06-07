# 2026-06-06 OIDF Full Matrix

## Summary

This record preserves the OpenID Foundation Conformance Suite result index for the full 16-plan matrix that passed on `main`.

| Field | Value |
| --- | --- |
| Result | Passed |
| Failures | `0` across all plans |
| Warnings | `0` across all plans |
| Workflow | `oidf-conformance-full` |
| Matrix job | `oidf-conformance-full` |
| Workflow run | <https://github.com/bymoye/oauth2_server/actions/runs/27067936867> |
| Job URL | <https://github.com/bymoye/oauth2_server/actions/runs/27067936867/job/79891980678> |
| Workflow event | `workflow_dispatch` |
| Head branch | `main` |
| Implementation commit | `4e15e77d70749e3b01d29670d449b40ac834f206` |
| Record update base | `3eb18e0f1046a2d9ef46177da11f84f3bf3cbfef` |
| Public issuer under test | `https://oauth-test.nazo.run` |
| Conformance server | `https://www.certification.openid.net/` |
| Started | `2026-06-06T16:40:35Z` |
| Completed | `2026-06-06T18:16:43Z` |
| Passed at | `2026-06-06T18:16:43Z` |
| Runtime | 1h 36m 8s |
| Artifact | `oidf-conformance-results-full` |
| Artifact ID | `7456740969` |
| Artifact digest | `sha256:e83b6a28dba209cf2136a8e36401aa510d36747df22a99bb799e6a274b4bf063` |
| Artifact size | `15103435` bytes |
| Artifact created | `2026-06-06T18:16:41Z` |
| Artifact expires | `2026-09-04T16:40:33Z` |

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

| # | Suite / profile | Client auth | Sender constraint | Mode | Variant | Plan ID | Result |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | OIDC Basic OP certification | static client | n/a | OpenID Connect | discovery | [`x8DmDn94xmYfX`](https://www.certification.openid.net/plan-detail.html?plan=x8DmDn94xmYfX) | 32 `FINISHED/PASSED`, 3 allowed `FINISHED/REVIEW`, 0 failures, 0 warnings |
| 2 | OIDC Config OP certification | n/a | n/a | OpenID Connect | server metadata | [`16x9lgL9ihmup`](https://www.certification.openid.net/plan-detail.html?plan=16x9lgL9ihmup) | 1 `FINISHED/PASSED`, 0 failures, 0 warnings |
| 3 | FAPI2 Message Signing Final | `private_key_jwt` | `dpop` | OpenID Connect | JARM | [`oYPZCixzxjfVd`](https://www.certification.openid.net/plan-detail.html?plan=oYPZCixzxjfVd) | 70 `FINISHED/PASSED`, 0 failures, 0 warnings |
| 4 | FAPI2 Message Signing Final | `private_key_jwt` | `dpop` | OpenID Connect | plain response / JAR | [`wQ9mXntUd2UWU`](https://www.certification.openid.net/plan-detail.html?plan=wQ9mXntUd2UWU) | 70 `FINISHED/PASSED`, 0 failures, 0 warnings |
| 5 | FAPI2 Security Profile Final | `mtls` | `dpop` | OpenID Connect | plain FAPI | [`YVqnfDmoEyASy`](https://www.certification.openid.net/plan-detail.html?plan=YVqnfDmoEyASy) | 46 `FINISHED/PASSED`, 0 failures, 0 warnings |
| 6 | FAPI2SP Client Credentials | `mtls` | `dpop` | plain OAuth | client credentials | [`QOJfNiRLtWSV9`](https://www.certification.openid.net/plan-detail.html?plan=QOJfNiRLtWSV9) | 9 `FINISHED/PASSED`, 0 failures, 0 warnings |
| 7 | FAPI2 Security Profile Final | `mtls` | `dpop` | plain OAuth | plain FAPI | [`PH1AWHPyeFAJu`](https://www.certification.openid.net/plan-detail.html?plan=PH1AWHPyeFAJu) | 40 `FINISHED/PASSED`, 0 failures, 0 warnings |
| 8 | FAPI2 Security Profile Final | `mtls` | `mtls` | OpenID Connect | plain FAPI | [`Zn9HjU2GrBMGw`](https://www.certification.openid.net/plan-detail.html?plan=Zn9HjU2GrBMGw) | 37 `FINISHED/PASSED`, 0 failures, 0 warnings |
| 9 | FAPI2SP Client Credentials | `mtls` | `mtls` | plain OAuth | client credentials | [`B1hVWghjPciLj`](https://www.certification.openid.net/plan-detail.html?plan=B1hVWghjPciLj) | 5 `FINISHED/PASSED`, 0 failures, 0 warnings |
| 10 | FAPI2 Security Profile Final | `mtls` | `mtls` | plain OAuth | plain FAPI | [`stDOAYIEKgjtU`](https://www.certification.openid.net/plan-detail.html?plan=stDOAYIEKgjtU) | 31 `FINISHED/PASSED`, 0 failures, 0 warnings |
| 11 | FAPI2 Security Profile Final | `private_key_jwt` | `dpop` | OpenID Connect | plain FAPI | [`lpDSdVJU0ANgN`](https://www.certification.openid.net/plan-detail.html?plan=lpDSdVJU0ANgN) | 56 `FINISHED/PASSED`, 0 failures, 0 warnings |
| 12 | FAPI2SP Client Credentials | `private_key_jwt` | `dpop` | plain OAuth | client credentials | [`GMNZVTkLMJH4H`](https://www.certification.openid.net/plan-detail.html?plan=GMNZVTkLMJH4H) | 14 `FINISHED/PASSED`, 0 failures, 0 warnings |
| 13 | FAPI2 Security Profile Final | `private_key_jwt` | `dpop` | plain OAuth | plain FAPI | [`vuw4pKPMPzLyW`](https://www.certification.openid.net/plan-detail.html?plan=vuw4pKPMPzLyW) | 50 `FINISHED/PASSED`, 0 failures, 0 warnings |
| 14 | FAPI2 Security Profile Final | `private_key_jwt` | `mtls` | OpenID Connect | plain FAPI | [`dDighQlP2vniE`](https://www.certification.openid.net/plan-detail.html?plan=dDighQlP2vniE) | 47 `FINISHED/PASSED`, 0 failures, 0 warnings |
| 15 | FAPI2SP Client Credentials | `private_key_jwt` | `mtls` | plain OAuth | client credentials | [`HaI9ULUYJ27GM`](https://www.certification.openid.net/plan-detail.html?plan=HaI9ULUYJ27GM) | 10 `FINISHED/PASSED`, 0 failures, 0 warnings |
| 16 | FAPI2 Security Profile Final | `private_key_jwt` | `mtls` | plain OAuth | plain FAPI | [`HPWBKELxKxDKI`](https://www.certification.openid.net/plan-detail.html?plan=HPWBKELxKxDKI) | 41 `FINISHED/PASSED`, 0 failures, 0 warnings |

## Exported Artifact Filenames

These are the 16 zip files inside `oidf-conformance-results-full`:

- `oidcc-basic-certification-test-plan-discovery-static_client-x8DmDn94xmYfX-06-Jun-2026.zip`
- `oidcc-config-certification-test-plan--16x9lgL9ihmup-06-Jun-2026.zip`
- `fapi2-message-signing-final-test-plan-private_key_jwt-dpop-simple-openid_connect-signed_non_repudiation-plain_fapi-jarm-oYPZCixzxjfVd-06-Jun-2026.zip`
- `fapi2-message-signing-final-test-plan-private_key_jwt-dpop-simple-openid_connect-signed_non_repudiation-plain_fapi-plain_response-wQ9mXntUd2UWU-06-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-openid_connect-plain_fapi-YVqnfDmoEyASy-06-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-plain_oauth-fapi_client_credentials_grant-QOJfNiRLtWSV9-06-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-plain_oauth-plain_fapi-PH1AWHPyeFAJu-06-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-openid_connect-plain_fapi-Zn9HjU2GrBMGw-06-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-plain_oauth-fapi_client_credentials_grant-B1hVWghjPciLj-06-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-plain_oauth-plain_fapi-stDOAYIEKgjtU-06-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-openid_connect-plain_fapi-lpDSdVJU0ANgN-06-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-plain_oauth-fapi_client_credentials_grant-GMNZVTkLMJH4H-06-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-plain_oauth-plain_fapi-vuw4pKPMPzLyW-06-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-openid_connect-plain_fapi-dDighQlP2vniE-06-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-plain_oauth-fapi_client_credentials_grant-HaI9ULUYJ27GM-06-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-plain_oauth-plain_fapi-HPWBKELxKxDKI-06-Jun-2026.zip`

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

- The implementation commit for this conformance run is `4e15e77d70749e3b01d29670d449b40ac834f206`.
- The repository later added this durable record and documentation updates, so the documentation commit can differ from the implementation commit under test.
- OIDC Basic contained 3 allowed `FINISHED/REVIEW` modules and no failures or warnings.
- This record indexes the official suite output; it is not itself an OpenID Foundation certification statement.
