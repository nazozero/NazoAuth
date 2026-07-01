# 2026-07-01 TP/PS OIDF Full Matrix

## Outcome

Hostinger-local OpenID Foundation Conformance Suite full-matrix regression for
the TP/PS hardening work deployed to `https://auth.nazo.run`.

The run used the repository full matrix, not the temporary targeted plan-set.
It completed all 16 plans with `0 failures` and `0 warnings`.

| Field | Value |
| --- | --- |
| Result | Passed |
| Runtime implementation commit | `32429d5` |
| Commit title | `Tighten FAPI TP metadata coverage` |
| Public issuer under test | `https://auth.nazo.run` |
| Deployment host | `ssh hostinger` |
| Deployment mode | Podman |
| Service image | `localhost/nazo-oauth-server:main-32429d5` |
| Conformance server | `https://localhost:8443` on `hostinger` |
| Plan set | `runtime/oidf/oidf-plan-set.json` |
| Result directory | `runtime/oidf/oidf-results-full-32429d5-20260701T050436Z` |
| Runner log | `runtime/oidf/oidf-run-full-32429d5-20260701T050436Z.log` |
| Exported plan archives | `16` |
| Final line | `All tests ran to completion. See above for any test condition failures.` |

## Matrix Scope

The run covered the full [OIDF 16-plan matrix](oidf-full-matrix.md):

- OIDC Basic OP
- OIDC Config OP
- FAPI2 Message Signing with `private_key_jwt`, DPoP, OpenID Connect, JARM
- FAPI2 Message Signing with `private_key_jwt`, DPoP, OpenID Connect, plain response
- FAPI2 Security Profile combinations across mTLS and `private_key_jwt` client authentication
- DPoP and mTLS sender constraints
- OpenID Connect, plain OAuth, and client credentials variants

The TP/PS changes are covered by the existing matrix through provider metadata
truth checks and FAPI2 PAR/auth-request modules, including:

- `fapi2-security-profile-final-ensure-unsigned-authorization-request-without-using-par-fails`
- `fapi2-security-profile-final-ensure-redirect-uri-in-authorization-request`
- `fapi2-security-profile-final-par-attempt-reuse-request_uri`
- `fapi2-security-profile-final-par-attempt-to-use-expired-request_uri`
- `fapi2-security-profile-final-par-attempt-to-use-request_uri-for-different-client`
- `fapi2-security-profile-final-par-authorization-request-containing-request_uri-form-param`
- `fapi2-security-profile-final-par-authorization-request-containing-request_uri`
- `fapi2-security-profile-final-par-without-duplicate-parameters`

## Summary

Parsed runner totals:

| Metric | Value |
| --- | --- |
| Plan summaries | `16` |
| Test modules | `578` |
| Successes | `43034` |
| Failures | `0` |
| Warnings | `0` |
| Completion marker | `true` |

Per-plan module counts:

| # | Modules | Successes | Failures | Warnings |
| --- | ---: | ---: | ---: | ---: |
| 1 | 2 | 29 | 0 | 0 |
| 2 | 6 | 188 | 0 | 0 |
| 3 | 11 | 325 | 0 | 0 |
| 4 | 10 | 1028 | 0 | 0 |
| 5 | 15 | 1159 | 0 | 0 |
| 6 | 36 | 1821 | 0 | 0 |
| 7 | 32 | 1656 | 0 | 0 |
| 8 | 42 | 2223 | 0 | 0 |
| 9 | 38 | 2388 | 0 | 0 |
| 10 | 41 | 3419 | 0 | 0 |
| 11 | 48 | 3054 | 0 | 0 |
| 12 | 51 | 3914 | 0 | 0 |
| 13 | 47 | 4385 | 0 | 0 |
| 14 | 57 | 4963 | 0 | 0 |
| 15 | 71 | 6018 | 0 | 0 |
| 16 | 71 | 6464 | 0 | 0 |

## Verification Commands

Commands executed after the run:

```bash
python3 scripts/run_oidf_conformance.py \
  --suite-dir oidf-conformance-suite \
  --conformance-server https://localhost:8443 \
  --config-json-file runtime/oidf/oidf-plan-configs.json \
  --plan-set-json-file runtime/oidf/oidf-plan-set.json \
  --target-issuer https://auth.nazo.run \
  --no-api-token \
  --disable-ssl-verify \
  --verbose \
  --timeout-seconds 5400 \
  --monitor-interval-seconds 30 \
  --export-dir runtime/oidf/oidf-results-full-32429d5-20260701T050436Z
```

```bash
find runtime/oidf/oidf-results-full-32429d5-20260701T050436Z -maxdepth 1 -name "*.zip" | wc -l
```

The result directory contained `16` exported plan archives.

## Notes

- The earlier `oidf-plan-set-tp-ps-32429d5.json` file was a temporary targeted
  development run and is not part of the durable matrix.
- The full regression record intentionally excludes plan configuration bodies,
  suite logs, private keys, certificates, and local credentials.
