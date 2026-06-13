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

## Official Workflow Rerun

After the real-UI changes were committed, the full GitHub Actions OIDF workflow
was submitted against the same public issuer and completed successfully.

| Field | Value |
| --- | --- |
| Result | Passed |
| Workflow | `oidf-conformance-full` |
| Workflow run | <https://github.com/bymoye/NazoAuth/actions/runs/27468700891> |
| Job URL | <https://github.com/bymoye/NazoAuth/actions/runs/27468700891/job/81195546195> |
| Workflow event | `workflow_dispatch` |
| Head branch | `main` |
| Implementation commit | `98105ae30d8b83c3e93c17ef3ae787fbd592dad3` |
| Public issuer under test | `https://auth.nazo.run` |
| Conformance server | `https://www.certification.openid.net/` |
| Started | `2026-06-13T13:54:04Z` |
| Completed | `2026-06-13T14:06:14Z` |
| Runtime | 12m 10s |
| Artifact | `oidf-conformance-results-full` |
| Artifact ID | `7611429377` |
| Artifact digest | `sha256:bea5e602edb98524cefb57368a33b9e8e0f2d6f5dad74cb7fb7d8ec83e465afd` |
| Artifact size | `15654042` bytes |
| Artifact created | `2026-06-13T14:06:11Z` |
| Artifact expires | `2026-09-11T13:54:05Z` |
| Runner mode | Official workflow runner, public `auth.nazo.run` target |

GitHub reported the `Run full OIDF matrix` step and the artifact upload step as
`success`. This is workflow evidence for the committed real-UI changes; it is
not a new OpenID Foundation certification statement.

## Real Environment Checks

The regression intentionally avoids local DNS overrides or hidden OIDF-specific
browser pages.

| Check | Result |
| --- | --- |
| Suite container DNS for `auth.nazo.run` | `153.92.208.166 auth.nazo.run` |
| Suite container public health request | `{"status":"正常"}` |
| Public discovery issuer | `https://auth.nazo.run` |
| Local public container | `nazo-oauth-server localhost/nazo-oauth-server:main-297294e-real-ui-20260613T132751Z Up` |
| Local `/opt/nazo-oauth/ui` marker scan | no `oidf_conformance`, `OIDF_USER`, or `conformance login` matches |

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

## JSON-only Backend and `prompt=login` Regression

After converting backend authorization errors to JSON-only responses, the local
full OIDF matrix was rerun against the same public issuer on this host. The run
also verifies that `prompt=login` performs a fresh authentication and returns a
new `auth_time` instead of reusing a recently authenticated session.

| Field | Value |
| --- | --- |
| Result | Passed |
| Failures | `0` across all plans |
| Warnings | `0` across all plans |
| Implementation base commit | `98105ae30d8b83c3e93c17ef3ae787fbd592dad3` |
| Public issuer under test | `https://auth.nazo.run` |
| Local public deployment image | `localhost/nazo-oauth-server:main-json-only-reauth-20260613T1518Z` |
| Local public container | `nazo-oauth-server localhost/nazo-oauth-server:main-json-only-reauth-20260613T1518Z 127.0.0.1:8000->8000/tcp Up` |
| Conformance server | `https://localhost.emobix.co.uk:8443` |
| Suite location | `/root/oauth2_server/oidf-conformance-suite` |
| Started | `2026-06-13T15:04:28Z` |
| Completed | `2026-06-13T15:09:03Z` |
| Export directory | `runtime/oidf/results-json-only-public-full-20260613T1505Z` |
| Runner mode | Local suite runner, public `auth.nazo.run` target |

The runner completed with:

```text
All tests ran to completion. See above for any test condition failures.
```

The public authorization error response was also checked directly:

```text
HTTP/2 401
content-type: application/json

{"error":"unauthorized_client","error_description":"Request failed."}
```

The exported zip filenames below identify the 16 completed plans:

- `oidcc-basic-certification-test-plan-discovery-static_client-ZF95Zk5p5dLdj-13-Jun-2026.zip`
- `oidcc-config-certification-test-plan--k3p4qhatc0DMC-13-Jun-2026.zip`
- `fapi2-message-signing-final-test-plan-private_key_jwt-dpop-simple-openid_connect-signed_non_repudiation-plain_fapi-jarm-sKDfseHmOfjhe-13-Jun-2026.zip`
- `fapi2-message-signing-final-test-plan-private_key_jwt-dpop-simple-openid_connect-signed_non_repudiation-plain_fapi-plain_response-aLdouvmwVVXST-13-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-openid_connect-plain_fapi-aw6watON6gLaJ-13-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-plain_oauth-fapi_client_credentials_grant-e2GJ7EO3OdQt8-13-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-plain_oauth-plain_fapi-XKgI9MNewCCaT-13-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-openid_connect-plain_fapi-xJe3Cpe5u5FRK-13-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-plain_oauth-fapi_client_credentials_grant-5ZJWLvjvno6p6-13-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-plain_oauth-plain_fapi-YyBjvFbBaCxKT-13-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-openid_connect-plain_fapi-drv4USmp87BNH-13-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-plain_oauth-fapi_client_credentials_grant-jqh7nMFxICuKr-13-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-plain_oauth-plain_fapi-rVmbJ9SQXA8yF-13-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-openid_connect-plain_fapi-B3lDXAltFcGiy-13-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-plain_oauth-fapi_client_credentials_grant-NmRNR5WegeSyV-13-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-plain_oauth-plain_fapi-fV0hzLi2ReF7L-13-Jun-2026.zip`

Run command:

```bash
python3 scripts/run_oidf_conformance.py \
  --suite-dir ../oidf-conformance-suite \
  --conformance-server https://localhost.emobix.co.uk:8443 \
  --no-api-token \
  --disable-ssl-verify \
  --config-json-file runtime/oidf/oidf-plan-configs.json \
  --config-file-name oidf-plan-configs.json \
  --plan-set-json-file runtime/oidf/oidf-plan-set.json \
  --export-dir runtime/oidf/results-json-only-public-full-20260613T1505Z \
  --timeout-seconds 10800 \
  --monitor-interval-seconds 30
```

## Follow-up Official Workflow Boundary

The follow-up official GitHub Actions run for the JSON-only backend response
change was submitted after commit `a6c3319d140ffc67939c9cb51b251567391aa0ad`.
It is not recorded as a passing official workflow run.

| Field | Value |
| --- | --- |
| Workflow run | <https://github.com/bymoye/NazoAuth/actions/runs/27470527340> |
| Job URL | <https://github.com/bymoye/NazoAuth/actions/runs/27470527340/job/81200506418> |
| Workflow event | `workflow_dispatch` |
| Head branch | `main` |
| Implementation commit | `a6c3319d140ffc67939c9cb51b251567391aa0ad` |
| Public issuer under test | `https://auth.nazo.run` |
| Conformance server | `https://www.certification.openid.net/` |
| Started | `2026-06-13T15:11:18Z` |
| Completed | `2026-06-13T15:17:29Z` |
| GitHub conclusion | `failure` |
| Artifact | `oidf-conformance-results-full` |
| Artifact ID | `7611946039` |
| Artifact digest | `sha256:24fd9b9c35002b1b8abd94b5d3703495ef9a55b04c075a4aed8c46642ac8e964` |
| Artifact size | `6946375` bytes |
| Artifact created | `2026-06-13T15:17:26Z` |
| Artifact expires | `2026-09-11T15:11:19Z` |

The failure was at the workflow runner boundary, not accepted here as a passing
official matrix record. The OIDF browser runner still had the stale task name
`Capture authorization error page` and waited for the removed HTML marker
`oidf_conformance_interaction`. The public service correctly returned a JSON
authorization error response with `content-type: application/json`, so the
browser task timed out in `oidcc-ensure-registered-redirect-uri`.

The runner configuration now normalizes the old task name to
`Capture authorization error response` before submitting plans. A future
official workflow success after that runner fix should be recorded as a new
passing official workflow record rather than overwriting the successful
`27468700891` real-UI evidence above.
