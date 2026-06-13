# 2026-06-13 Real Public UI OIDF Regression

## Outcome

OpenID Foundation Conformance Suite regression run after removing the previous
test-only frontend interaction pages. The suite process ran locally, but every
authorization and protocol request targeted the public deployment at
`https://auth.nazo.run`.

| Field | Value |
| --- | --- |
| Result | Passed |
| Failures | `0` across all plans |
| Warnings | `0` across all plans |
| Implementation commit before local edits | `297294eaf14ce17a620b48f242d141ae20f1d201` |
| Public issuer under test | `https://auth.nazo.run` |
| Public deployment image | `localhost/nazo-oauth-server:main-297294e-real-ui-20260613T132751Z` |
| Conformance server | `https://localhost.emobix.co.uk:8443` |
| Suite location | `/root/oauth2_server/oidf-conformance-suite` |
| Started | `2026-06-13T13:32Z` |
| Completed | `2026-06-13T13:37:00Z` |
| Export directory | `runtime/oidf/results-real-public-full-20260613T1332Z` |
| Runner mode | Local suite runner, public `auth.nazo.run` target |

The runner completed with:

```text
All tests ran to completion. See above for any test condition failures.
```

Every printed plan summary reported `0 failures` and `0 warnings`.

## Real Environment Checks

The regression intentionally avoids local DNS overrides or hidden OIDF-specific
browser pages.

| Check | Result |
| --- | --- |
| Suite container DNS for `auth.nazo.run` | `153.92.208.166 auth.nazo.run` |
| Suite container public health request | `{"status":"正常"}` |
| Public discovery issuer | `https://auth.nazo.run` |
| Remote container | `nazo-oauth-server localhost/nazo-oauth-server:main-297294e-real-ui-20260613T132751Z Up` |
| Remote `/opt/nazo-oauth/ui` marker scan | no `oidf_conformance`, `OIDF_USER`, or `conformance login` matches |

Browser automation used the same public React UI that users see:

- login page: `https://auth.nazo.run/ui/auth`
- consent page: `https://auth.nazo.run/ui/consent`
- stable real UI element IDs: `nazo-login-email`, `nazo-login-password`,
  `nazo-login-submit`, `nazo-consent-approve`, `nazo-consent-deny`

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

The exported zip filenames below identify the 16 completed plans.

| # | Suite / profile | Client auth | Sender constraint | Mode | Variant | Plan ID | Result |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | OIDC Basic OP certification | static client | n/a | OpenID Connect | discovery | `IHbFGoQih6yVy` | Passed |
| 2 | OIDC Config OP certification | n/a | n/a | OpenID Connect | server metadata | `7NVxj6lrpxTdV` | Passed |
| 3 | FAPI2 Message Signing Final | `private_key_jwt` | `dpop` | OpenID Connect | JARM | `kY1X8rUCAhjQa` | Passed |
| 4 | FAPI2 Message Signing Final | `private_key_jwt` | `dpop` | OpenID Connect | plain response / JAR | `idlVoL9XGt5PK` | Passed |
| 5 | FAPI2 Security Profile Final | `mtls` | `dpop` | OpenID Connect | plain FAPI | `J2AemhebP9QIs` | Passed |
| 6 | FAPI2SP Client Credentials | `mtls` | `dpop` | plain OAuth | client credentials | `TLfSTSFosy6Xw` | Passed |
| 7 | FAPI2 Security Profile Final | `mtls` | `dpop` | plain OAuth | plain FAPI | `H9Io4kBM6S87h` | Passed |
| 8 | FAPI2 Security Profile Final | `mtls` | `mtls` | OpenID Connect | plain FAPI | `5NumIKhR9OTLY` | Passed |
| 9 | FAPI2SP Client Credentials | `mtls` | `mtls` | plain OAuth | client credentials | `BwXKVdQ7cOjsu` | Passed |
| 10 | FAPI2 Security Profile Final | `mtls` | `mtls` | plain OAuth | plain FAPI | `jhSQFQ6R13wrk` | Passed |
| 11 | FAPI2 Security Profile Final | `private_key_jwt` | `dpop` | OpenID Connect | plain FAPI | `ktvrxQseVp0Po` | Passed |
| 12 | FAPI2SP Client Credentials | `private_key_jwt` | `dpop` | plain OAuth | client credentials | `VoI8Oa1mlKzn0` | Passed |
| 13 | FAPI2 Security Profile Final | `private_key_jwt` | `dpop` | plain OAuth | plain FAPI | `t0tH4ZVfINwUD` | Passed |
| 14 | FAPI2 Security Profile Final | `private_key_jwt` | `mtls` | OpenID Connect | plain FAPI | `4NsXtMLLVfVAW` | Passed |
| 15 | FAPI2SP Client Credentials | `private_key_jwt` | `mtls` | plain OAuth | client credentials | `VEpsPjtjTt2JE` | Passed |
| 16 | FAPI2 Security Profile Final | `private_key_jwt` | `mtls` | plain OAuth | plain FAPI | `4vrK6GYhsH1ed` | Passed |

## Exported Artifact Filenames

Artifact contents in `runtime/oidf/results-real-public-full-20260613T1332Z`:

- `oidcc-basic-certification-test-plan-discovery-static_client-IHbFGoQih6yVy-13-Jun-2026.zip`
- `oidcc-config-certification-test-plan--7NVxj6lrpxTdV-13-Jun-2026.zip`
- `fapi2-message-signing-final-test-plan-private_key_jwt-dpop-simple-openid_connect-signed_non_repudiation-plain_fapi-jarm-kY1X8rUCAhjQa-13-Jun-2026.zip`
- `fapi2-message-signing-final-test-plan-private_key_jwt-dpop-simple-openid_connect-signed_non_repudiation-plain_fapi-plain_response-idlVoL9XGt5PK-13-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-openid_connect-plain_fapi-J2AemhebP9QIs-13-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-plain_oauth-fapi_client_credentials_grant-TLfSTSFosy6Xw-13-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-plain_oauth-plain_fapi-H9Io4kBM6S87h-13-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-openid_connect-plain_fapi-5NumIKhR9OTLY-13-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-plain_oauth-fapi_client_credentials_grant-BwXKVdQ7cOjsu-13-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-plain_oauth-plain_fapi-jhSQFQ6R13wrk-13-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-openid_connect-plain_fapi-ktvrxQseVp0Po-13-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-plain_oauth-fapi_client_credentials_grant-VoI8Oa1mlKzn0-13-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-plain_oauth-plain_fapi-t0tH4ZVfINwUD-13-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-openid_connect-plain_fapi-4NsXtMLLVfVAW-13-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-plain_oauth-fapi_client_credentials_grant-VEpsPjtjTt2JE-13-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-plain_oauth-plain_fapi-4vrK6GYhsH1ed-13-Jun-2026.zip`

## Command

The run command was:

```bash
python3 scripts/run_oidf_conformance.py \
  --suite-dir ../oidf-conformance-suite \
  --conformance-server https://localhost.emobix.co.uk:8443 \
  --no-api-token \
  --disable-ssl-verify \
  --config-json-file runtime/oidf/oidf-plan-configs.json \
  --config-file-name oidf-plan-configs.json \
  --plan-set-json-file runtime/oidf/oidf-plan-set.json \
  --export-dir runtime/oidf/results-real-public-full-20260613T1332Z \
  --timeout-seconds 10800 \
  --monitor-interval-seconds 30
```

## Notes

- This is a local regression record, not an OpenID Foundation certification
  statement.
- The target issuer was the deployed public service, not a locally mapped
  `auth.nazo.run`.
- The frontend deployed to `/ui/` was the normal React application, not a
  conformance-only login or consent page.
- The runner stores credentials only in suite configuration or environment
  variables and drives visible real UI controls.
