# 2026-06-27 PR 15 Official OIDF Full Matrix

## Outcome

OpenID Foundation Conformance Suite official full-matrix regression for PR 15
after the security-findings hardening branch had been deployed to the public
Hostinger service at `https://auth.nazo.run`.

The official suite completed all configured 16 plans with `0 failures` and
`0 warnings`.

| Field | Value |
| --- | --- |
| Result | Passed |
| Pull request | <https://github.com/bymoye/NazoAuth/pull/15> |
| Current PR head at verification time | `bac10af902e574d4bd98741eaa2ce0121278608c` |
| Runtime implementation commit | `be7ef9f6a9197520235a59d42866a0918a293014` |
| Branch | `codex/security-findings-20260625` |
| Public issuer under test | `https://auth.nazo.run` |
| Deployment host | `ssh hostinger` |
| Deployment mode | Podman |
| Service image | `localhost/nazo-oauth-server:main-be7ef9f` |
| Conformance server | `https://www.certification.openid.net/` |
| Export directory | `oidf-official-results/run-20260627T002306Z` |
| Exported plan archives | `16` |
| Final line | `All tests ran to completion. See above for any test condition failures.` |

The current PR head differs from the deployed runtime commit only by test and
documentation commits. No runtime OAuth/OIDC behavior was changed after
`be7ef9f6a9197520235a59d42866a0918a293014`.

## Security Boundary

The run preserves the intended request-object boundary:

- Baseline OIDC advertises `none` for unsigned Request Object compatibility.
- FAPI2 Security Profile Final and FAPI2 Message Signing Final remain
  fail-closed for unsigned Request Objects.
- Clients that require PAR request objects or holder-bound tokens still require
  signed Request Objects.
- DPoP, mTLS sender constraint, `private_key_jwt`, PAR, JAR, JARM, PKCE,
  redirect URI, audience, issuer, nonce, state, and authorization code replay
  constraints remain covered by the official matrix.

## Official OIDF Suite

Run command, executed on `ssh hostinger`:

```bash
python3 scripts/run_oidf_conformance.py \
  --suite-dir oidf-conformance-suite \
  --conformance-server https://www.certification.openid.net/ \
  --plan-set-json-file runtime/oidf/oidf-plan-set.json \
  --config-json-file runtime/oidf/oidf-plan-configs.json \
  --target-issuer https://auth.nazo.run \
  --export-dir oidf-official-results/run-20260627T002306Z \
  --timeout-seconds 10800 \
  --monitor-interval-seconds 10
```

Representative final summaries printed by the official runner:

```text
Overall totals: ran 71 test modules. Conditions: 6679 successes, 0 failures, 0 warnings. 492.0 seconds
Overall totals: ran 71 test modules. Conditions: 6233 successes, 0 failures, 0 warnings. 496.1 seconds
All tests ran to completion. See above for any test condition failures.
```

The first line above corresponds to the signed non-repudiation JARM message
signing plan. The second line corresponds to the signed non-repudiation plain
response message signing plan. The complete run exported all 16 plan archives
listed below.

Official plan detail URLs:

- <https://www.certification.openid.net/plan-detail.html?plan=Srk6iaVDVcqO5>
- <https://www.certification.openid.net/plan-detail.html?plan=fGiz8QZYR1LVy>
- <https://www.certification.openid.net/plan-detail.html?plan=Gcyx5n8lhHHfF>
- <https://www.certification.openid.net/plan-detail.html?plan=2EUyk3qiTDGGr>
- <https://www.certification.openid.net/plan-detail.html?plan=QKu4ihkeDdDWi>
- <https://www.certification.openid.net/plan-detail.html?plan=5YeTZYm5qbwKK>
- <https://www.certification.openid.net/plan-detail.html?plan=pCEGdWvXDQsHv>
- <https://www.certification.openid.net/plan-detail.html?plan=wQ2oJV2eyjW00>
- <https://www.certification.openid.net/plan-detail.html?plan=RgYL32tFjclUu>
- <https://www.certification.openid.net/plan-detail.html?plan=ivH6w0GYLkDPM>
- <https://www.certification.openid.net/plan-detail.html?plan=KTKlUUDhu6bGV>
- <https://www.certification.openid.net/plan-detail.html?plan=epCWdqDUqTr0L>
- <https://www.certification.openid.net/plan-detail.html?plan=11enFcEfoqqYu>
- <https://www.certification.openid.net/plan-detail.html?plan=YLf935w5iRIlg>
- <https://www.certification.openid.net/plan-detail.html?plan=ECNeWrfSegaaN>
- <https://www.certification.openid.net/plan-detail.html?plan=cya7t5spbdgtX>

## Coverage

Profiles and protocol features covered by this official run:

- OIDC Basic OP certification plan
- OIDC Config OP certification plan
- FAPI2 Security Profile Final
- FAPI2 Message Signing Final
- `private_key_jwt`
- mTLS client authentication
- DPoP sender constraint
- mTLS sender constraint
- PAR
- signed request objects / JAR
- unsigned Request Object compatibility for baseline OIDC
- JARM and plain authorization responses
- OpenID Connect and plain OAuth modes
- FAPI2 client credentials grant variants

## Official Exported Artifact Filenames

Artifact contents in `oidf-official-results/run-20260627T002306Z`:

- `fapi2-message-signing-final-test-plan-private_key_jwt-dpop-simple-openid_connect-signed_non_repudiation-plain_fapi-jarm-Gcyx5n8lhHHfF-27-Jun-2026.zip`
- `fapi2-message-signing-final-test-plan-private_key_jwt-dpop-simple-openid_connect-signed_non_repudiation-plain_fapi-plain_response-2EUyk3qiTDGGr-27-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-openid_connect-plain_fapi-QKu4ihkeDdDWi-27-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-plain_oauth-fapi_client_credentials_grant-5YeTZYm5qbwKK-27-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-plain_oauth-plain_fapi-pCEGdWvXDQsHv-27-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-openid_connect-plain_fapi-wQ2oJV2eyjW00-27-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-plain_oauth-fapi_client_credentials_grant-RgYL32tFjclUu-27-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-plain_oauth-plain_fapi-ivH6w0GYLkDPM-27-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-openid_connect-plain_fapi-KTKlUUDhu6bGV-27-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-plain_oauth-fapi_client_credentials_grant-epCWdqDUqTr0L-27-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-plain_oauth-plain_fapi-11enFcEfoqqYu-27-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-openid_connect-plain_fapi-YLf935w5iRIlg-27-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-plain_oauth-fapi_client_credentials_grant-ECNeWrfSegaaN-27-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-plain_oauth-plain_fapi-cya7t5spbdgtX-27-Jun-2026.zip`
- `oidcc-basic-certification-test-plan-discovery-static_client-Srk6iaVDVcqO5-27-Jun-2026.zip`
- `oidcc-config-certification-test-plan--fGiz8QZYR1LVy-27-Jun-2026.zip`

## Verification Commands

Result directory verification:

```bash
find oidf-official-results/run-20260627T002306Z -maxdepth 1 -name "*.zip" | wc -l
find oidf-official-results/run-20260627T002306Z -maxdepth 1 -name "*.zip" -printf "%f\n" | sort
```

GitHub PR verification:

```bash
gh pr checks 15 --repo bymoye/NazoAuth
```

## Notes

- The record intentionally excludes plan configuration bodies, suite logs, API
  tokens, private client keys, certificates, and local credentials.
- The official runner terminal printed the final suite completion line, and the
  exported result directory was independently verified to contain 16 official
  plan archives.
- This is a conformance evidence record for the deployed runtime behavior and
  the PR 15 verification window. It is not an OpenID Foundation certification
  listing.
