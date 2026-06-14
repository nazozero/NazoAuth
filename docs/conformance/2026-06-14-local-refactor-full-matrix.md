# 2026-06-14 Local Refactor OIDF Full Matrix

## Outcome

Local OpenID Foundation Conformance Suite full matrix run after the Rust
structure and test-organization refactor work. The suite ran in local Podman
containers and targeted the public issuer at `https://auth.nazo.run`.

| Field | Value |
| --- | --- |
| Result | Passed |
| Test modules | `71` |
| Successes | `6375` |
| Failures | `0` |
| Warnings | `0` |
| Implementation tree under test | `27066087989034ba3909bc9f36a5401ef4df1906` |
| Public issuer under test | `https://auth.nazo.run` |
| Conformance server | `https://localhost.emobix.co.uk:8443` |
| Suite location | `/root/oauth2_server/oidf-conformance-suite` |
| Export directory | `runtime/oidf/results-local-full-20260614T120216Z` |
| Runner mode | Local suite runner, public `auth.nazo.run` target |

The latest runner process exited successfully after exporting 16 plan archives
and reported:

```text
Overall totals: ran 71 test modules. Conditions: 6375 successes, 0 failures, 0 warnings.
```

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

## Exported Artifact Filenames

Artifact contents in `runtime/oidf/results-local-full-20260614T120216Z`:

- `fapi2-message-signing-final-test-plan-private_key_jwt-dpop-simple-openid_connect-signed_non_repudiation-plain_fapi-jarm-oYqCYN8ZHXIGD-14-Jun-2026.zip`
- `fapi2-message-signing-final-test-plan-private_key_jwt-dpop-simple-openid_connect-signed_non_repudiation-plain_fapi-plain_response-ujy0t8JNW6jnQ-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-openid_connect-plain_fapi-Tey8zOJPTsl5J-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-plain_oauth-fapi_client_credentials_grant-DBGXmYKqEfXoc-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-plain_oauth-plain_fapi-rDQAc9HWeywYW-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-openid_connect-plain_fapi-Os09rAbP06daU-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-plain_oauth-fapi_client_credentials_grant-lXgJuS1GsDVRy-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-plain_oauth-plain_fapi-F4UKxIcfYH07K-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-openid_connect-plain_fapi-Hcc3yv1GHPphK-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-plain_oauth-fapi_client_credentials_grant-j1W6qXFMEyzQ5-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-plain_oauth-plain_fapi-e7PxsltrYhg8r-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-openid_connect-plain_fapi-lY6KG2HL4Qtlu-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-plain_oauth-fapi_client_credentials_grant-2zbXt2mMUgwtk-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-plain_oauth-plain_fapi-F34vPo3d2f0Bi-14-Jun-2026.zip`
- `oidcc-basic-certification-test-plan-discovery-static_client-VQG5mKOe3Y3vA-14-Jun-2026.zip`
- `oidcc-config-certification-test-plan--oYVURa97jczD1-14-Jun-2026.zip`

## Verification Commands

```bash
python3 scripts/run_oidf_conformance.py \
  --suite-dir ../oidf-conformance-suite \
  --conformance-server https://localhost.emobix.co.uk:8443 \
  --no-api-token \
  --disable-ssl-verify \
  --config-json-file runtime/oidf/oidf-plan-configs.json \
  --config-file-name oidf-plan-configs.json \
  --plan-set-json-file runtime/oidf/oidf-plan-set.json \
  --export-dir runtime/oidf/results-local-full-20260614T120216Z \
  --timeout-seconds 10800 \
  --monitor-interval-seconds 30

grep -R '"result"[[:space:]]*:[[:space:]]*"\(FAILED\|WARNING\|INTERRUPTED\|SKIPPED\)"' \
  runtime/oidf/results-local-full-20260614T120216Z
```

## Notes

- This is a local regression record, not an OpenID Foundation certification
  statement.
- The record intentionally excludes plan configuration bodies and suite logs
  that may contain private client keys, certificates, or local credentials.
