# 2026-06-25 PR 13 Security Hardening OIDF Full Matrix

## Outcome

OpenID Foundation Conformance Suite full-matrix regression after PR 13 security
hardening was deployed to the public Hostinger service at
`https://auth.nazo.run`.

The same deployed commit was verified in two stages:

1. Hostinger-local Conformance Suite against the public issuer.
2. Official OpenID Foundation Conformance Suite against the public issuer.

Both stages completed all configured 16 plans with `0 failures` and
`0 warnings`.

| Field | Value |
| --- | --- |
| Result | Passed |
| Implementation commit | `49467e3474b32c17603ed77ba63b570d07e794b2` |
| Branch | `codex/security-findings-hardening` |
| Public issuer under test | `https://auth.nazo.run` |
| Public health check | `{"status":"正常"}` |
| Deployment host | `ssh hostinger` |
| Deployment mode | Podman Compose |
| Service HEAD after deployment | `49467e3474b3` |
| Discovery request-object algorithms | `none`, `EdDSA`, `RS256`, `ES256`, `PS256` |

## Security Boundary

The baseline OIDC metadata advertises `none` in
`request_object_signing_alg_values_supported` to support the OIDC compatibility
path for unsigned Request Objects. This does not loosen the FAPI/JAR security
boundary.

Unsigned Request Objects remain rejected fail closed for high-security
profiles, including FAPI2 Security Profile Final, FAPI2 Message Signing Final,
clients requiring PAR request objects, and holder-bound token clients. Those
paths require signed Request Objects or reject the input.

## Hostinger Local Suite

| Field | Value |
| --- | --- |
| Result | Passed |
| Conformance server | `https://localhost:8443` |
| Target issuer | `https://auth.nazo.run` |
| Export directory | `oidf-local-results/run-20260625T230539Z` |
| Runner log | `runtime/oidf/oidf-run-local-full-20260625T230539Z.log` |
| Exported plan archives | `16` |
| Plan summaries | `16` |
| Final line | `All tests ran to completion. See above for any test condition failures.` |
| Largest plan summary | `Overall totals: ran 71 test modules. Conditions: 6464 successes, 0 failures, 0 warnings. 335.0 seconds` |

Run command:

```bash
python3 scripts/run_oidf_conformance.py \
  --suite-dir oidf-conformance-suite \
  --conformance-server https://localhost:8443 \
  --plan-set-json-file runtime/oidf/oidf-plan-set.json \
  --config-json-file runtime/oidf/oidf-plan-configs.json \
  --target-issuer https://auth.nazo.run \
  --no-api-token \
  --disable-ssl-verify \
  --export-dir oidf-local-results/run-20260625T230539Z \
  --timeout-seconds 10800 \
  --monitor-interval-seconds 10
```

## Official OIDF Suite

| Field | Value |
| --- | --- |
| Result | Passed |
| Conformance server | `https://www.certification.openid.net/` |
| Target issuer | `https://auth.nazo.run` |
| Export directory | `oidf-official-results/run-20260625T152222Z` |
| Runner log | `runtime/oidf/oidf-run-official-full-20260625T152222Z.log` |
| Exported plan archives | `16` |
| Plan summaries | `16` |
| Final line | `All tests ran to completion. See above for any test condition failures.` |

Every printed plan summary reported `0 failures` and `0 warnings`:

```text
Overall totals: ran 2 test modules. Conditions: 38 successes, 0 failures, 0 warnings. 1.7 seconds
Overall totals: ran 6 test modules. Conditions: 194 successes, 0 failures, 0 warnings. 14.8 seconds
Overall totals: ran 11 test modules. Conditions: 333 successes, 0 failures, 0 warnings. 25.0 seconds
Overall totals: ran 10 test modules. Conditions: 1034 successes, 0 failures, 0 warnings. 48.7 seconds
Overall totals: ran 15 test modules. Conditions: 1167 successes, 0 failures, 0 warnings. 56.0 seconds
Overall totals: ran 36 test modules. Conditions: 1926 successes, 0 failures, 0 warnings. 218.0 seconds
Overall totals: ran 32 test modules. Conditions: 1662 successes, 0 failures, 0 warnings. 350.7 seconds
Overall totals: ran 42 test modules. Conditions: 2231 successes, 0 failures, 0 warnings. 377.4 seconds
Overall totals: ran 38 test modules. Conditions: 2502 successes, 0 failures, 0 warnings. 384.0 seconds
Overall totals: ran 41 test modules. Conditions: 3425 successes, 0 failures, 0 warnings. 415.6 seconds
Overall totals: ran 48 test modules. Conditions: 3200 successes, 0 failures, 0 warnings. 421.6 seconds
Overall totals: ran 51 test modules. Conditions: 3922 successes, 0 failures, 0 warnings. 439.8 seconds
Overall totals: ran 47 test modules. Conditions: 4526 successes, 0 failures, 0 warnings. 451.5 seconds
Overall totals: ran 57 test modules. Conditions: 5136 successes, 0 failures, 0 warnings. 479.4 seconds
Overall totals: ran 71 test modules. Conditions: 6679 successes, 0 failures, 0 warnings. 513.1 seconds
Overall totals: ran 71 test modules. Conditions: 6233 successes, 0 failures, 0 warnings. 516.6 seconds
```

Official plan detail URLs:

- <https://www.certification.openid.net/plan-detail.html?plan=61lTGAiOozYOM>
- <https://www.certification.openid.net/plan-detail.html?plan=oV6ljcuKS2Oh8>
- <https://www.certification.openid.net/plan-detail.html?plan=TqaPjQMrPv5YC>
- <https://www.certification.openid.net/plan-detail.html?plan=gzToqvr0uF8Rv>
- <https://www.certification.openid.net/plan-detail.html?plan=wceHDPdEWLDrx>
- <https://www.certification.openid.net/plan-detail.html?plan=oU9F4NGcPa4Kb>
- <https://www.certification.openid.net/plan-detail.html?plan=eKk1w21AKomk6>
- <https://www.certification.openid.net/plan-detail.html?plan=agL0mYu7WRHTC>
- <https://www.certification.openid.net/plan-detail.html?plan=daFhIMh7crcEN>
- <https://www.certification.openid.net/plan-detail.html?plan=SVQZ3U1QXTNdV>
- <https://www.certification.openid.net/plan-detail.html?plan=hHnIBqm9q2s5q>
- <https://www.certification.openid.net/plan-detail.html?plan=WvDwjH19fAu9s>
- <https://www.certification.openid.net/plan-detail.html?plan=tj0FiaRXeZfxv>
- <https://www.certification.openid.net/plan-detail.html?plan=ot9OFKuYaSkFv>
- <https://www.certification.openid.net/plan-detail.html?plan=LsGNCfzS1mxft>
- <https://www.certification.openid.net/plan-detail.html?plan=FuDOv484VEkUm>

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

## Official Exported Artifact Filenames

Artifact contents in `oidf-official-results/run-20260625T152222Z`:

- `fapi2-message-signing-final-test-plan-private_key_jwt-dpop-simple-openid_connect-signed_non_repudiation-plain_fapi-jarm-gzToqvr0uF8Rv-25-Jun-2026.zip`
- `fapi2-message-signing-final-test-plan-private_key_jwt-dpop-simple-openid_connect-signed_non_repudiation-plain_fapi-plain_response-wceHDPdEWLDrx-25-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-openid_connect-plain_fapi-daFhIMh7crcEN-25-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-plain_oauth-fapi_client_credentials_grant-TqaPjQMrPv5YC-25-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-plain_oauth-plain_fapi-FuDOv484VEkUm-25-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-openid_connect-plain_fapi-agL0mYu7WRHTC-25-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-plain_oauth-fapi_client_credentials_grant-eKk1w21AKomk6-25-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-plain_oauth-plain_fapi-hHnIBqm9q2s5q-25-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-openid_connect-plain_fapi-oU9F4NGcPa4Kb-25-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-plain_oauth-fapi_client_credentials_grant-ot9OFKuYaSkFv-25-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-plain_oauth-plain_fapi-WvDwjH19fAu9s-25-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-openid_connect-plain_fapi-SVQZ3U1QXTNdV-25-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-plain_oauth-fapi_client_credentials_grant-tj0FiaRXeZfxv-25-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-plain_oauth-plain_fapi-LsGNCfzS1mxft-25-Jun-2026.zip`
- `oidcc-basic-certification-test-plan-discovery-static_client-61lTGAiOozYOM-25-Jun-2026.zip`
- `oidcc-config-certification-test-plan--oV6ljcuKS2Oh8-25-Jun-2026.zip`

## Verification Commands

Deployment verification:

```bash
git rev-parse --short=12 HEAD
curl -fsS https://auth.nazo.run/health
curl -fsS https://auth.nazo.run/.well-known/openid-configuration
```

Hostinger result verification:

```bash
find oidf-local-results/run-20260625T230539Z -name "*.zip" | wc -l
grep -c "Overall totals:" runtime/oidf/oidf-run-local-full-20260625T230539Z.log
tail -n 8 runtime/oidf/oidf-run-local-full-20260625T230539Z.log

find oidf-official-results/run-20260625T152222Z -name "*.zip" | wc -l
grep -c "Overall totals:" runtime/oidf/oidf-run-official-full-20260625T152222Z.log
tail -n 5 runtime/oidf/oidf-run-official-full-20260625T152222Z.log
```

## Notes

- The record intentionally excludes plan configuration bodies, suite logs, API
  tokens, private client keys, certificates, and local credentials.
- The official runner wrote all summaries and result archives, then left a
  residual process that did not exit by itself. The residual process was
  terminated after the completed log and 16 official exported plan archives
  were independently verified.
- This is a conformance evidence record for the deployed PR 13 build. It does
  not replace the OpenID Foundation certification listing.
