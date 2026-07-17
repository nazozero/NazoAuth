# 2026-06-26 Security Findings OIDF Full Matrix

## Outcome

OpenID Foundation Conformance Suite full-matrix regression after the
2026-06-25 security findings hardening branch was deployed to the public
issuer at `https://issuer.example`.

The same deployed commit was verified in two stages:

1. Diagnostic Conformance Suite regression against the public issuer.
2. Official OpenID Foundation Conformance Suite against the public issuer.

Both stages completed all configured 16 plans with `0 failures` and
`0 warnings`.

| Field | Value |
| --- | --- |
| Result | Passed |
| Implementation commit | `be7ef9f6a9197520235a59d42866a0918a293014` |
| Branch | `codex/security-findings-20260625` |
| Public issuer under test | `https://issuer.example` |
| Public health check | `{"status":"正常"}` |
| Deployment runner | Diagnostic runner details intentionally omitted |
| Service HEAD after deployment | `be7ef9f` |

## Security Boundary

This run preserves the existing security boundary for request objects and
holder-bound clients:

- Baseline OIDC may support unsigned Request Objects for OIDC compatibility.
- FAPI2 Security Profile Final and FAPI2 Message Signing Final remain
  fail-closed for unsigned Request Objects.
- Clients requiring PAR request objects or holder-bound tokens still require
  signed Request Objects.
- Explicit OIDC `claims` requests are treated as explicit authorization
  material and are still filtered by the requested claim name and any
  `value` / `values` constraints.

## Diagnostic Suite Regression

| Field | Value |
| --- | --- |
| Result | Passed |
| Conformance server | diagnostic suite origin (private regression only; not conformance evidence) |
| Target issuer | `https://issuer.example` |
| Export directory | `sanitized diagnostic artifact` |
| Runner log | `sanitized diagnostic artifact` |
| Exported plan archives | `16` |
| Plan summaries | `16` |
| Final line | `All tests ran to completion. See above for any test condition failures.` |
| Largest plan summary | `Overall totals: ran 71 test modules. Conditions: 6464 successes, 0 failures, 0 warnings. 330.1 seconds` |

Every printed diagnostic plan summary reported `0 failures` and
`0 warnings`:

```text
Overall totals: ran 2 test modules. Conditions: 29 successes, 0 failures, 0 warnings. 1.1 seconds
Overall totals: ran 6 test modules. Conditions: 188 successes, 0 failures, 0 warnings. 5.6 seconds
Overall totals: ran 11 test modules. Conditions: 325 successes, 0 failures, 0 warnings. 11.1 seconds
Overall totals: ran 10 test modules. Conditions: 1028 successes, 0 failures, 0 warnings. 12.0 seconds
Overall totals: ran 15 test modules. Conditions: 1159 successes, 0 failures, 0 warnings. 15.4 seconds
Overall totals: ran 36 test modules. Conditions: 1821 successes, 0 failures, 0 warnings. 106.5 seconds
Overall totals: ran 32 test modules. Conditions: 1656 successes, 0 failures, 0 warnings. 275.3 seconds
Overall totals: ran 38 test modules. Conditions: 2388 successes, 0 failures, 0 warnings. 287.7 seconds
Overall totals: ran 42 test modules. Conditions: 2223 successes, 0 failures, 0 warnings. 287.9 seconds
Overall totals: ran 41 test modules. Conditions: 3419 successes, 0 failures, 0 warnings. 295.7 seconds
Overall totals: ran 47 test modules. Conditions: 4385 successes, 0 failures, 0 warnings. 300.8 seconds
Overall totals: ran 48 test modules. Conditions: 3054 successes, 0 failures, 0 warnings. 300.9 seconds
Overall totals: ran 51 test modules. Conditions: 3914 successes, 0 failures, 0 warnings. 304.4 seconds
Overall totals: ran 57 test modules. Conditions: 4963 successes, 0 failures, 0 warnings. 313.5 seconds
Overall totals: ran 71 test modules. Conditions: 6018 successes, 0 failures, 0 warnings. 327.1 seconds
Overall totals: ran 71 test modules. Conditions: 6464 successes, 0 failures, 0 warnings. 330.1 seconds
```

## Official OIDF Suite

| Field | Value |
| --- | --- |
| Result | Passed |
| Conformance server | `https://www.certification.openid.net/` |
| Target issuer | `https://issuer.example` |
| Export directory | `oidf-official-results/run-20260626T170746Z` |
| Runner log | `runtime/oidf/oidf-run-official-full-20260626T170746Z.log` |
| Exported plan archives | `16` |
| Plan summaries | `16` |
| Final line | `All tests ran to completion. See above for any test condition failures.` |

Every printed official plan summary reported `0 failures` and `0 warnings`:

```text
Overall totals: ran 2 test modules. Conditions: 38 successes, 0 failures, 0 warnings. 2.8 seconds
Overall totals: ran 6 test modules. Conditions: 194 successes, 0 failures, 0 warnings. 16.9 seconds
Overall totals: ran 11 test modules. Conditions: 333 successes, 0 failures, 0 warnings. 25.6 seconds
Overall totals: ran 10 test modules. Conditions: 1034 successes, 0 failures, 0 warnings. 50.6 seconds
Overall totals: ran 15 test modules. Conditions: 1167 successes, 0 failures, 0 warnings. 60.0 seconds
Overall totals: ran 36 test modules. Conditions: 1926 successes, 0 failures, 0 warnings. 222.2 seconds
Overall totals: ran 32 test modules. Conditions: 1662 successes, 0 failures, 0 warnings. 354.0 seconds
Overall totals: ran 42 test modules. Conditions: 2231 successes, 0 failures, 0 warnings. 379.6 seconds
Overall totals: ran 38 test modules. Conditions: 2502 successes, 0 failures, 0 warnings. 385.8 seconds
Overall totals: ran 41 test modules. Conditions: 3425 successes, 0 failures, 0 warnings. 416.9 seconds
Overall totals: ran 48 test modules. Conditions: 3200 successes, 0 failures, 0 warnings. 422.1 seconds
Overall totals: ran 51 test modules. Conditions: 3922 successes, 0 failures, 0 warnings. 448.9 seconds
Overall totals: ran 47 test modules. Conditions: 4526 successes, 0 failures, 0 warnings. 455.7 seconds
Overall totals: ran 57 test modules. Conditions: 5136 successes, 0 failures, 0 warnings. 488.3 seconds
Overall totals: ran 71 test modules. Conditions: 6233 successes, 0 failures, 0 warnings. 510.7 seconds
Overall totals: ran 71 test modules. Conditions: 6679 successes, 0 failures, 0 warnings. 516.2 seconds
```

Official plan detail URLs:

- <https://www.certification.openid.net/plan-detail.html?plan=GWLxnaolcAPZl>
- <https://www.certification.openid.net/plan-detail.html?plan=JjJ4TO9vBkYVM>
- <https://www.certification.openid.net/plan-detail.html?plan=DJi1vNB1L1Ccm>
- <https://www.certification.openid.net/plan-detail.html?plan=IpoG9gv6TAdXd>
- <https://www.certification.openid.net/plan-detail.html?plan=WLt7N8PgfF8hT>
- <https://www.certification.openid.net/plan-detail.html?plan=T7sX48IRZ34GB>
- <https://www.certification.openid.net/plan-detail.html?plan=rY72VWZzxM7C6>
- <https://www.certification.openid.net/plan-detail.html?plan=YCaY28vc1be4g>
- <https://www.certification.openid.net/plan-detail.html?plan=iBCVE4uBgdJaQ>
- <https://www.certification.openid.net/plan-detail.html?plan=BIyLD62Pns0Gq>
- <https://www.certification.openid.net/plan-detail.html?plan=T8gTRvtutKsfy>
- <https://www.certification.openid.net/plan-detail.html?plan=cuumrV2XJn1Sh>
- <https://www.certification.openid.net/plan-detail.html?plan=oiPHbIUnIy6ua>
- <https://www.certification.openid.net/plan-detail.html?plan=ZNjVO1aTk5QMJ>
- <https://www.certification.openid.net/plan-detail.html?plan=NV24KmXHVGjX3>
- <https://www.certification.openid.net/plan-detail.html?plan=lAM5vh5bWvv6u>

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
- unsigned Request Object compatibility for baseline OIDC
- JARM and plain authorization responses
- OpenID Connect and plain OAuth modes
- explicit OIDC `claims` parameter handling for UserInfo and ID Token claims

## Official Exported Artifact Filenames

Artifact contents in `oidf-official-results/run-20260626T170746Z`:

- `fapi2-message-signing-final-test-plan-private_key_jwt-dpop-simple-openid_connect-signed_non_repudiation-plain_fapi-jarm-T8gTRvtutKsfy-26-Jun-2026.zip`
- `fapi2-message-signing-final-test-plan-private_key_jwt-dpop-simple-openid_connect-signed_non_repudiation-plain_fapi-plain_response-iBCVE4uBgdJaQ-26-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-openid_connect-plain_fapi-lAM5vh5bWvv6u-26-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-plain_oauth-fapi_client_credentials_grant-cuumrV2XJn1Sh-26-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-plain_oauth-plain_fapi-DJi1vNB1L1Ccm-26-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-openid_connect-plain_fapi-oiPHbIUnIy6ua-26-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-plain_oauth-fapi_client_credentials_grant-NV24KmXHVGjX3-26-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-plain_oauth-plain_fapi-ZNjVO1aTk5QMJ-26-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-openid_connect-plain_fapi-WLt7N8PgfF8hT-26-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-plain_oauth-fapi_client_credentials_grant-BIyLD62Pns0Gq-26-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-plain_oauth-plain_fapi-rY72VWZzxM7C6-26-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-openid_connect-plain_fapi-YCaY28vc1be4g-26-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-plain_oauth-fapi_client_credentials_grant-IpoG9gv6TAdXd-26-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-plain_oauth-plain_fapi-T7sX48IRZ34GB-26-Jun-2026.zip`
- `oidcc-basic-certification-test-plan-discovery-static_client-GWLxnaolcAPZl-26-Jun-2026.zip`
- `oidcc-config-certification-test-plan--JjJ4TO9vBkYVM-26-Jun-2026.zip`

## Verification Commands

## Notes

- The record intentionally excludes plan configuration bodies, suite logs, API
  tokens, private client keys, certificates, runner paths, and credentials.
- The official runner wrote all summaries and result archives, then left a
  residual process that did not exit by itself. The residual process was
  terminated after the completed log and 16 official exported plan archives
  were independently verified.
- This is a conformance evidence record for the deployed branch build. It does
  not replace the OpenID Foundation certification listing.
