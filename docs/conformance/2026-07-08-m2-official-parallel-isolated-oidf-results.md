# 2026-07-08 M2 Official Parallel-Isolated OIDF Results

## Environment

| Field | Value |
| --- | --- |
| Target issuer | `https://issuer.example` |
| Branch | `codex/m2-fapi2-default-security` |
| Workflow | `oidf-conformance-full.yml` |
| Run URL | `https://github.com/nazozero/NazoAuth/actions/runs/28953799865` |
| Workflow head SHA | `7ddc6b3354799f2401071d44c616b0deb224753c` |
| Started | `2026-07-08T15:15:42Z` |
| Completed | `2026-07-08T15:32:49Z` |
| Result | `success` |

## Deployment Boundary

This record omits deployment topology and local seeding details. The durable evidence is the official workflow run against the configured public issuer.

## Isolation Model

The workflow executed the repository's 20-plan public OIDF matrix in the
18+2 form:

| Job | Coverage | Isolation | Result |
| --- | --- | --- | --- |
| `oidf-conformance-full` | 18 non-browser-sensitive plans | Single workflow job, runner invoked without `--no-parallel`, export path `oidf-results/concurrent` | `success` |
| `oidf-conformance-browser-isolated (frontchannel...)` | `oidcc-frontchannel-rp-initiated-logout` | Separate matrix job/runner/browser session, invoked with `--no-parallel` | `success` |
| `oidf-conformance-browser-isolated (session-management...)` | `oidcc-session-management-rp-initiated-logout` | Separate matrix job/runner/browser session, invoked with `--no-parallel` | `success` |

## Plan Results

The raw artifact contains 20 official suite zip archives:

| Plan archive stem | Plan ID |
| --- | --- |
| `oidcc-basic-certification-test-plan-discovery-static_client` | `ORT8zDZamO97K` |
| `oidcc-basic-certification-test-plan-discovery-dynamic_client` | `0S20s7X0rWmEU` |
| `oidcc-config-certification-test-plan` | `BP1OFiWpIE91t` |
| `oidcc-frontchannel-rp-initiated-logout-certification-test-plan-code-static_client` | `vpW6TtyHeFvQh` |
| `oidcc-session-management-certification-test-plan-code-static_client` | `gf7tew2weA5bu` |
| `fapi-ciba-id1-test-plan-private_key_jwt-poll-plain_fapi-static_client` | `fNq3taHvxGEmt` |
| `fapi2-message-signing-final-test-plan-private_key_jwt-dpop-simple-openid_connect-signed_non_repudiation-plain_fapi-jarm` | `8avIDwXDEAMgV` |
| `fapi2-message-signing-final-test-plan-private_key_jwt-dpop-simple-openid_connect-signed_non_repudiation-plain_fapi-plain_response` | `UJYkCq5qNdgjV` |
| `fapi2-security-profile-final-test-plan-mtls-dpop-simple-openid_connect-plain_fapi` | `2WYQAERUGxktN` |
| `fapi2-security-profile-final-test-plan-mtls-dpop-simple-plain_oauth-fapi_client_credentials_grant` | `13KAjqTSbXumY` |
| `fapi2-security-profile-final-test-plan-mtls-dpop-simple-plain_oauth-plain_fapi` | `RXGQw827xjACC` |
| `fapi2-security-profile-final-test-plan-mtls-mtls-simple-openid_connect-plain_fapi` | `s43bOB9xI46DV` |
| `fapi2-security-profile-final-test-plan-mtls-mtls-simple-plain_oauth-fapi_client_credentials_grant` | `OQpgnoE8bT6fY` |
| `fapi2-security-profile-final-test-plan-mtls-mtls-simple-plain_oauth-plain_fapi` | `LzKFW5Ctliawn` |
| `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-openid_connect-plain_fapi` | `wGT3hkQHew2QV` |
| `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-plain_oauth-fapi_client_credentials_grant` | `x31i2Eh0LoJ0k` |
| `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-plain_oauth-plain_fapi` | `5cwuRPhmCXdvy` |
| `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-openid_connect-plain_fapi` | `faYEI9SUBG49C` |
| `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-plain_oauth-fapi_client_credentials_grant` | `2RJY7wHny50V8` |
| `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-plain_oauth-plain_fapi` | `ZCB2hsvMfujwa` |

## Artifacts

GitHub Actions artifact metadata from run `28953799865`:

| Artifact | ID | Size | Digest | Expires |
| --- | --- | ---: | --- | --- |
| `oidf-conformance-results-concurrent` | `8173443670` | 17845251 bytes | `sha256:fcd9bf5fef4fd704d2d9c11c847bddab6d7352e1f601f8505ac1227af4d848ac` | `2026-10-06T15:15:44Z` |
| `oidf-conformance-results-frontchannel` | `8172968104` | 31016 bytes | `sha256:153b5fb778e3b23ccad9a09df708f5b4fe45dea6aba12293af16c5347d1928d3` | `2026-10-06T15:15:44Z` |
| `oidf-conformance-results-session-management` | `8172970101` | 26215 bytes | `sha256:cd461503c9f67a7b75702ff7ee72eda91942cadfcde235db92b611336085b403` | `2026-10-06T15:15:44Z` |
| `oidf-public-plan-configs` | `8172961528` | 51435 bytes | `sha256:bdeb062a0a7a8633434a7877fbdf5ab11fa05980f901324be908d76d4bd5dda2` | `2026-10-06T15:15:44Z` |

The raw artifacts include official suite outputs and rendered public test
configuration. Keep only metadata and digests in git; do not commit raw
archives or rendered configuration.

## Acceptance

This run is the M2 official full-matrix regression for the deployed
`fapi2-security` and FAPI2 Message Signing profile boundary work. It covers
the repository's 20 public OIDF plans in the requested 18+2
`parallel-isolated` layout and completed with all three GitHub Actions jobs in
`success`.
