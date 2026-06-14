# 2026-06-14 Local Refactor OIDF Full Matrix

## Outcome

Local OpenID Foundation Conformance Suite full matrix runs after the Rust
structure, test-organization, and security-invariant coverage work. The suite
ran in local Podman containers and targeted the public issuer at
`https://auth.nazo.run`.

| Field | Value |
| --- | --- |
| Result | Passed |
| Test modules | `71` |
| Successes | `6375` |
| Failures | `0` |
| Warnings | `0` |
| Implementation tree under test | Working tree after `5d7dd35fec831a89af7146d9b2744dcb02ee9790` coverage/test split changes |
| Public issuer under test | `https://auth.nazo.run` |
| Conformance server | `https://localhost.emobix.co.uk:8443` |
| Suite location | `/root/oauth2_server/oidf-conformance-suite` |
| Export directory | `runtime/oidf/results-local-full-20260614T125017Z` |
| Runner mode | Local suite runner, public `auth.nazo.run` target |
| Official GitHub Actions run | `27498378863` |
| Official run URL | `https://github.com/bymoye/NazoAuth/actions/runs/27498378863` |
| Official run head SHA | `5d7dd35fec831a89af7146d9b2744dcb02ee9790` |
| Official run result | Passed |

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

Artifact contents in `runtime/oidf/results-local-full-20260614T125017Z`:

- `fapi2-message-signing-final-test-plan-private_key_jwt-dpop-simple-openid_connect-signed_non_repudiation-plain_fapi-jarm-XfH78dmBXMINz-14-Jun-2026.zip`
- `fapi2-message-signing-final-test-plan-private_key_jwt-dpop-simple-openid_connect-signed_non_repudiation-plain_fapi-plain_response-lspO8vfyppQL9-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-openid_connect-plain_fapi-6jy27RmvBmxiY-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-plain_oauth-fapi_client_credentials_grant-QScDCT8lpskQl-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-plain_oauth-plain_fapi-oaOAe6o8K2gQV-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-openid_connect-plain_fapi-YXwaNZsBkFE9v-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-plain_oauth-fapi_client_credentials_grant-tigzkbtTdCXah-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-plain_oauth-plain_fapi-FAEiX0BZn0v9u-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-openid_connect-plain_fapi-mur82jmYMhTXm-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-plain_oauth-fapi_client_credentials_grant-X0wbbzn56m0RX-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-plain_oauth-plain_fapi-rMqfP489Df6cu-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-openid_connect-plain_fapi-YLwVIBGpN21xy-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-plain_oauth-fapi_client_credentials_grant-w4ax9Vnd8wZ95-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-plain_oauth-plain_fapi-2lXPD4cUKkv2h-14-Jun-2026.zip`
- `oidcc-basic-certification-test-plan-discovery-static_client-ha4f3PEsSwsiK-14-Jun-2026.zip`
- `oidcc-config-certification-test-plan--Pew5YKW7VNwKn-14-Jun-2026.zip`

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
  --export-dir runtime/oidf/results-local-full-20260614T125017Z \
  --timeout-seconds 10800 \
  --monitor-interval-seconds 30

grep -R '"result"[[:space:]]*:[[:space:]]*"\(FAILED\|WARNING\|INTERRUPTED\|SKIPPED\)"' \
  runtime/oidf/results-local-full-20260614T125017Z
```

## Notes

- This is a local regression record, not an OpenID Foundation certification
  statement.
- The official `oidf-conformance-full` workflow also passed on
  `2026-06-14T12:19:34Z` for head SHA
  `5d7dd35fec831a89af7146d9b2744dcb02ee9790`:
  `https://github.com/bymoye/NazoAuth/actions/runs/27498378863`.
- The record intentionally excludes plan configuration bodies and suite logs
  that may contain private client keys, certificates, or local credentials.
