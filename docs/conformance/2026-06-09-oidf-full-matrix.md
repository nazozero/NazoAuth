# 2026-06-09 OIDF Full Matrix

## Outcome

OpenID Foundation Conformance Suite result index for the 16-plan matrix that
passed on `main`.

| Field | Value |
| --- | --- |
| Result | Passed |
| Failures | `0` across all plans |
| Warnings | `0` across all plans |
| Workflow | `oidf-conformance-full` |
| Matrix job | `oidf-conformance-full` |
| Workflow run | <https://github.com/bymoye/NazoAuth/actions/runs/27217886808> |
| Job URL | <https://github.com/bymoye/NazoAuth/actions/runs/27217886808/job/80364452311> |
| Workflow event | `workflow_dispatch` |
| Head branch | `main` |
| Implementation commit | `4c3533ef707dc6cce15862a02ec7188b814cb7a7` |
| Public issuer under test | `https://auth.nazo.run` |
| Conformance server | `https://www.certification.openid.net/` |
| Started | `2026-06-09T15:42:50Z` |
| Completed | `2026-06-09T15:52:25Z` |
| Runtime | 9m 35s |
| Artifact | `oidf-conformance-results-full` |
| Artifact ID | `7512921698` |
| Artifact digest | `sha256:6dd6c6d53d8e24df561d3127fec7a058a9b90356423127d8dcacc8e09a5f29ec` |
| Artifact size | `15602106` bytes |
| Artifact created | `2026-06-09T15:52:23Z` |
| Artifact expires | `2026-09-07T15:42:47Z` |
| Runner mode | Official runner, parallel execution |

## Coverage

Profiles and protocol features covered by this run:

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

The official runner completed all selected plans. The workflow log reported
`All tests ran to completion` and each plan reported `0 failures, 0 warnings`.

| # | Suite / profile | Client auth | Sender constraint | Mode | Variant | Plan ID | Result |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | OIDC Basic OP certification | static client | n/a | OpenID Connect | discovery | [`00evsRkkwZmJD`](https://www.certification.openid.net/plan-detail.html?plan=00evsRkkwZmJD) | Passed |
| 2 | OIDC Config OP certification | n/a | n/a | OpenID Connect | server metadata | [`fulPmYjPko8Ys`](https://www.certification.openid.net/plan-detail.html?plan=fulPmYjPko8Ys) | Passed |
| 3 | FAPI2 Message Signing Final | `private_key_jwt` | `dpop` | OpenID Connect | JARM | [`6NrAQ0iAYM4b9`](https://www.certification.openid.net/plan-detail.html?plan=6NrAQ0iAYM4b9) | Passed |
| 4 | FAPI2 Message Signing Final | `private_key_jwt` | `dpop` | OpenID Connect | plain response / JAR | [`PepEHUPDBWVIS`](https://www.certification.openid.net/plan-detail.html?plan=PepEHUPDBWVIS) | Passed |
| 5 | FAPI2 Security Profile Final | `mtls` | `dpop` | OpenID Connect | plain FAPI | [`VFWzhLyufobZ7`](https://www.certification.openid.net/plan-detail.html?plan=VFWzhLyufobZ7) | Passed |
| 6 | FAPI2SP Client Credentials | `mtls` | `dpop` | plain OAuth | client credentials | [`y3Wum0K4rUwJc`](https://www.certification.openid.net/plan-detail.html?plan=y3Wum0K4rUwJc) | Passed |
| 7 | FAPI2 Security Profile Final | `mtls` | `dpop` | plain OAuth | plain FAPI | [`O1Hm9RheiNMdF`](https://www.certification.openid.net/plan-detail.html?plan=O1Hm9RheiNMdF) | Passed |
| 8 | FAPI2 Security Profile Final | `mtls` | `mtls` | OpenID Connect | plain FAPI | [`Hy3zhTo2RZirQ`](https://www.certification.openid.net/plan-detail.html?plan=Hy3zhTo2RZirQ) | Passed |
| 9 | FAPI2SP Client Credentials | `mtls` | `mtls` | plain OAuth | client credentials | [`OyEn4BcuQ1tvY`](https://www.certification.openid.net/plan-detail.html?plan=OyEn4BcuQ1tvY) | Passed |
| 10 | FAPI2 Security Profile Final | `mtls` | `mtls` | plain OAuth | plain FAPI | [`JOrJCsGt0h9d2`](https://www.certification.openid.net/plan-detail.html?plan=JOrJCsGt0h9d2) | Passed |
| 11 | FAPI2 Security Profile Final | `private_key_jwt` | `dpop` | OpenID Connect | plain FAPI | [`Cqb95D4PvAwgy`](https://www.certification.openid.net/plan-detail.html?plan=Cqb95D4PvAwgy) | Passed |
| 12 | FAPI2SP Client Credentials | `private_key_jwt` | `dpop` | plain OAuth | client credentials | [`U2cP2nE7nf0ze`](https://www.certification.openid.net/plan-detail.html?plan=U2cP2nE7nf0ze) | Passed |
| 13 | FAPI2 Security Profile Final | `private_key_jwt` | `dpop` | plain OAuth | plain FAPI | [`JegEEWrStZUh4`](https://www.certification.openid.net/plan-detail.html?plan=JegEEWrStZUh4) | Passed |
| 14 | FAPI2 Security Profile Final | `private_key_jwt` | `mtls` | OpenID Connect | plain FAPI | [`UAWqwZ6WNuxVM`](https://www.certification.openid.net/plan-detail.html?plan=UAWqwZ6WNuxVM) | Passed |
| 15 | FAPI2SP Client Credentials | `private_key_jwt` | `mtls` | plain OAuth | client credentials | [`0UgHfnansF44o`](https://www.certification.openid.net/plan-detail.html?plan=0UgHfnansF44o) | Passed |
| 16 | FAPI2 Security Profile Final | `private_key_jwt` | `mtls` | plain OAuth | plain FAPI | [`g724WRqbM9FzK`](https://www.certification.openid.net/plan-detail.html?plan=g724WRqbM9FzK) | Passed |

## Exported Artifact Filenames

Artifact contents:

- `oidcc-basic-certification-test-plan-discovery-static_client-00evsRkkwZmJD-09-Jun-2026.zip`
- `oidcc-config-certification-test-plan--fulPmYjPko8Ys-09-Jun-2026.zip`
- `fapi2-message-signing-final-test-plan-private_key_jwt-dpop-simple-openid_connect-signed_non_repudiation-plain_fapi-jarm-6NrAQ0iAYM4b9-09-Jun-2026.zip`
- `fapi2-message-signing-final-test-plan-private_key_jwt-dpop-simple-openid_connect-signed_non_repudiation-plain_fapi-plain_response-PepEHUPDBWVIS-09-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-openid_connect-plain_fapi-VFWzhLyufobZ7-09-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-plain_oauth-fapi_client_credentials_grant-y3Wum0K4rUwJc-09-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-plain_oauth-plain_fapi-O1Hm9RheiNMdF-09-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-openid_connect-plain_fapi-Hy3zhTo2RZirQ-09-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-plain_oauth-fapi_client_credentials_grant-OyEn4BcuQ1tvY-09-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-plain_oauth-plain_fapi-JOrJCsGt0h9d2-09-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-openid_connect-plain_fapi-Cqb95D4PvAwgy-09-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-plain_oauth-fapi_client_credentials_grant-U2cP2nE7nf0ze-09-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-plain_oauth-plain_fapi-JegEEWrStZUh4-09-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-openid_connect-plain_fapi-UAWqwZ6WNuxVM-09-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-plain_oauth-fapi_client_credentials_grant-0UgHfnansF44o-09-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-plain_oauth-plain_fapi-g724WRqbM9FzK-09-Jun-2026.zip`

## Workflow Steps

Workflow step results:

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

- Official suite output is indexed for commit `4c3533ef707dc6cce15862a02ec7188b814cb7a7`.
- The workflow used the official OpenID Foundation conformance runner in parallel mode.
- The durable record was added after the implementation commit was tested, so the documentation commit may differ from the implementation commit under test.
- Not an OpenID Foundation certification statement.
