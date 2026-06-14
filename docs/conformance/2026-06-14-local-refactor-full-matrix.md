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
| Implementation tree under test | `c24c18205456ecae4172f2c1be99412533088a27` |
| Public issuer under test | `https://auth.nazo.run` |
| Conformance server | `https://localhost.emobix.co.uk:8443` |
| Suite location | `/root/oauth2_server/oidf-conformance-suite` |
| Export directory | `runtime/oidf/results-local-full-20260614T112525Z` |
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

Artifact contents in `runtime/oidf/results-local-full-20260614T112525Z`:

- `fapi2-message-signing-final-test-plan-private_key_jwt-dpop-simple-openid_connect-signed_non_repudiation-plain_fapi-jarm-cBLTIfVdP4Ku7-14-Jun-2026.zip`
- `fapi2-message-signing-final-test-plan-private_key_jwt-dpop-simple-openid_connect-signed_non_repudiation-plain_fapi-plain_response-DuxlA7WkLR10X-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-openid_connect-plain_fapi-vc6RPo0FLdqTA-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-plain_oauth-fapi_client_credentials_grant-HTFkTEigqDfLL-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-plain_oauth-plain_fapi-75C6tlgTdeZSN-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-openid_connect-plain_fapi-OXB4yfsCtR4Z2-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-plain_oauth-fapi_client_credentials_grant-dkFW7ZEkg8x2H-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-plain_oauth-plain_fapi-fUm3OfVlO85go-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-openid_connect-plain_fapi-D2Dvq97tm1JhP-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-plain_oauth-fapi_client_credentials_grant-RBTUS5iLpWrgu-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-plain_oauth-plain_fapi-Hqlhmb9RO9F5H-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-openid_connect-plain_fapi-q4j4qAD2X1owY-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-plain_oauth-fapi_client_credentials_grant-we8drC7ntD3mv-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-plain_oauth-plain_fapi-BQA5A6tkTzd2L-14-Jun-2026.zip`
- `oidcc-basic-certification-test-plan-discovery-static_client-ViOi27eYIgJia-14-Jun-2026.zip`
- `oidcc-config-certification-test-plan--zflLvVMlAXqsn-14-Jun-2026.zip`

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
  --export-dir runtime/oidf/results-local-full-20260614T112525Z \
  --timeout-seconds 10800 \
  --monitor-interval-seconds 30

grep -R '"result"[[:space:]]*:[[:space:]]*"\(FAILED\|WARNING\|INTERRUPTED\|SKIPPED\)"' \
  runtime/oidf/results-local-full-20260614T112525Z
```

## Notes

- This is a local regression record, not an OpenID Foundation certification
  statement.
- The record intentionally excludes plan configuration bodies and suite logs
  that may contain private client keys, certificates, or local credentials.
