# 2026-06-08 OIDF Full Matrix

## Summary

This record preserves the OpenID Foundation Conformance Suite result index for
the full 16-plan matrix that passed on `main` after the external-signer,
resource-server DPoP verifier, SCIM token model, and OAuth 2.1 self-audit work.

| Field | Value |
| --- | --- |
| Result | Passed |
| Failures | `0` across all plans |
| Warnings | `0` across all plans |
| Workflow | `oidf-conformance-full` |
| Matrix job | `oidf-conformance-full` |
| Workflow run | <https://github.com/bymoye/oauth2_server/actions/runs/27113465641> |
| Job URL | <https://github.com/bymoye/oauth2_server/actions/runs/27113465641/job/80015656145> |
| Workflow event | `workflow_dispatch` |
| Head branch | `main` |
| Implementation commit | `8f6901abe2a014b4a5d1e486d986598daf3b825f` |
| Public issuer under test | `https://oauth-test.nazo.run` |
| Conformance server | `https://www.certification.openid.net/` |
| Started | `2026-06-08T02:59:47Z` |
| Completed | `2026-06-08T04:32:30Z` |
| Runtime | 1h 32m 43s |
| Artifact | `oidf-conformance-results-full` |
| Artifact ID | `7471680299` |
| Artifact digest | `sha256:5df11ff4785f7b08056201fb515ae954b4013bebe5602a56131794cdcd269ee4` |
| Artifact size | `15096178` bytes |
| Artifact created | `2026-06-08T04:32:26Z` |
| Artifact expires | `2026-09-06T02:59:48Z` |
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
| 1 | OIDC Basic OP certification | static client | n/a | OpenID Connect | discovery | [`2nsmZuUFRxRFE`](https://www.certification.openid.net/plan-detail.html?plan=2nsmZuUFRxRFE) | Passed; selector clean |
| 2 | OIDC Config OP certification | n/a | n/a | OpenID Connect | server metadata | [`c9uGZxnhzvWWj`](https://www.certification.openid.net/plan-detail.html?plan=c9uGZxnhzvWWj) | Passed; selector clean |
| 3 | FAPI2 Message Signing Final | `private_key_jwt` | `dpop` | OpenID Connect | JARM | [`yuV8K3dsykqOJ`](https://www.certification.openid.net/plan-detail.html?plan=yuV8K3dsykqOJ) | Passed; selector clean |
| 4 | FAPI2 Message Signing Final | `private_key_jwt` | `dpop` | OpenID Connect | plain response / JAR | [`D7xA1bnY6p8ZU`](https://www.certification.openid.net/plan-detail.html?plan=D7xA1bnY6p8ZU) | Passed; selector clean |
| 5 | FAPI2 Security Profile Final | `mtls` | `dpop` | OpenID Connect | plain FAPI | [`3VUHfTblLMe1P`](https://www.certification.openid.net/plan-detail.html?plan=3VUHfTblLMe1P) | Passed; selector clean |
| 6 | FAPI2SP Client Credentials | `mtls` | `dpop` | plain OAuth | client credentials | [`AHdoSIpbePJpu`](https://www.certification.openid.net/plan-detail.html?plan=AHdoSIpbePJpu) | Passed; selector clean |
| 7 | FAPI2 Security Profile Final | `mtls` | `dpop` | plain OAuth | plain FAPI | [`DXKtQlCU89TXv`](https://www.certification.openid.net/plan-detail.html?plan=DXKtQlCU89TXv) | Passed; selector clean |
| 8 | FAPI2 Security Profile Final | `mtls` | `mtls` | OpenID Connect | plain FAPI | [`D4eakI6E1SXVy`](https://www.certification.openid.net/plan-detail.html?plan=D4eakI6E1SXVy) | Passed; selector clean |
| 9 | FAPI2SP Client Credentials | `mtls` | `mtls` | plain OAuth | client credentials | [`1iTC0uFxX5JMa`](https://www.certification.openid.net/plan-detail.html?plan=1iTC0uFxX5JMa) | Passed; selector clean |
| 10 | FAPI2 Security Profile Final | `mtls` | `mtls` | plain OAuth | plain FAPI | [`5Mx87oW9gI8V2`](https://www.certification.openid.net/plan-detail.html?plan=5Mx87oW9gI8V2) | Passed; selector clean |
| 11 | FAPI2 Security Profile Final | `private_key_jwt` | `dpop` | OpenID Connect | plain FAPI | [`WOTLVlHItAbFR`](https://www.certification.openid.net/plan-detail.html?plan=WOTLVlHItAbFR) | Passed; selector clean |
| 12 | FAPI2SP Client Credentials | `private_key_jwt` | `dpop` | plain OAuth | client credentials | [`Tezpcf0eeGh6w`](https://www.certification.openid.net/plan-detail.html?plan=Tezpcf0eeGh6w) | Passed; selector clean |
| 13 | FAPI2 Security Profile Final | `private_key_jwt` | `dpop` | plain OAuth | plain FAPI | [`WtNOqlCUb4dhF`](https://www.certification.openid.net/plan-detail.html?plan=WtNOqlCUb4dhF) | Passed; selector clean |
| 14 | FAPI2 Security Profile Final | `private_key_jwt` | `mtls` | OpenID Connect | plain FAPI | [`Bc3hYvOzMJwjS`](https://www.certification.openid.net/plan-detail.html?plan=Bc3hYvOzMJwjS) | Passed; selector clean |
| 15 | FAPI2SP Client Credentials | `private_key_jwt` | `mtls` | plain OAuth | client credentials | [`10ztpAjtFzAos`](https://www.certification.openid.net/plan-detail.html?plan=10ztpAjtFzAos) | Passed; selector clean |
| 16 | FAPI2 Security Profile Final | `private_key_jwt` | `mtls` | plain OAuth | plain FAPI | [`w5xgj1pGNSqPC`](https://www.certification.openid.net/plan-detail.html?plan=w5xgj1pGNSqPC) | Passed; selector clean |

## Exported Artifact Filenames

These are the 16 zip files inside `oidf-conformance-results-full`:

- `oidcc-basic-certification-test-plan-discovery-static_client-2nsmZuUFRxRFE-08-Jun-2026.zip`
- `oidcc-config-certification-test-plan--c9uGZxnhzvWWj-08-Jun-2026.zip`
- `fapi2-message-signing-final-test-plan-private_key_jwt-dpop-simple-openid_connect-signed_non_repudiation-plain_fapi-jarm-yuV8K3dsykqOJ-08-Jun-2026.zip`
- `fapi2-message-signing-final-test-plan-private_key_jwt-dpop-simple-openid_connect-signed_non_repudiation-plain_fapi-plain_response-D7xA1bnY6p8ZU-08-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-openid_connect-plain_fapi-3VUHfTblLMe1P-08-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-plain_oauth-fapi_client_credentials_grant-AHdoSIpbePJpu-08-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-plain_oauth-plain_fapi-DXKtQlCU89TXv-08-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-openid_connect-plain_fapi-D4eakI6E1SXVy-08-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-plain_oauth-fapi_client_credentials_grant-1iTC0uFxX5JMa-08-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-plain_oauth-plain_fapi-5Mx87oW9gI8V2-08-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-openid_connect-plain_fapi-WOTLVlHItAbFR-08-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-plain_oauth-fapi_client_credentials_grant-Tezpcf0eeGh6w-08-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-plain_oauth-plain_fapi-WtNOqlCUb4dhF-08-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-openid_connect-plain_fapi-Bc3hYvOzMJwjS-08-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-plain_oauth-fapi_client_credentials_grant-10ztpAjtFzAos-08-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-plain_oauth-plain_fapi-w5xgj1pGNSqPC-08-Jun-2026.zip`

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

- This record indexes official suite output for commit `8f6901abe2a014b4a5d1e486d986598daf3b825f`.
- The post-run selector sweep returned no modules requiring rerun for all 16 plan IDs.
- The repository added this durable record after the implementation commit was tested, so the documentation commit can differ from the implementation commit under test.
- This record is not itself an OpenID Foundation certification statement.
