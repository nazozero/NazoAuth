# 2026-07-03 NI-007 Public FAPI-CIBA OIDF Results

## Environment

| Field | Value |
| --- | --- |
| Target issuer | `https://issuer.example` |
| Deployment host | Details intentionally omitted |
| Branch | `codex/ni-006-011-oidc-profiles` |
| Workflow | `oidf-conformance.yml` |
| Run URL | `https://github.com/nazozero/NazoAuth/actions/runs/28636561869` |
| Job URL | `https://github.com/nazozero/NazoAuth/actions/runs/28636561869/job/84924080071` |
| Workflow head SHA | `0374141ae7aec76c573b06dc8406b10819915309` |
| Official suite ref | `33a724c7d809a6f9db05cbb513ff2a77cbac905e` |
| Exported suite version | `5.1.45` |
| Result artifact | Deleted on 2026-07-19 because the archive contained credential material |

Full OIDF result archives are not public evidence. They can contain rendered
temporary client configuration, browser credentials, tokens, or private test
keys. Current workflows retain only redacted logs and the public result summary;
they do not upload complete runner exports.

## Plan

`fapi-ciba-id1-test-plan[client_auth_type=private_key_jwt][fapi_ciba_profile=plain_fapi][ciba_mode=poll][client_registration=static_client]`

Configuration file:

`oidf-fapi-ciba-plain-private-key-jwt-poll-plan-config.json`

Plan ID: `yzxGGbP1vXpgH`

## Result

| Source | Result |
| --- | --- |
| GitHub Actions run | `success` |
| JSON module exports | 35 `PASSED`, 0 failed, 0 skipped |
| JSON condition results | 2768 `SUCCESS`, 0 `FAILURE`, 0 `WARNING` |
| Runner log totals | 36 test modules run; 2768 successes, 0 failures, 0 warnings |
| Early-stop monitor | disabled |

The 35 JSON module exports are all `FINISHED` and `PASSED`. The runner log also
prints one aggregate module in its total, hence the log total of 36 modules.

## Root Cause

The failed public CIBA path had three separate invariants that were not being
held at the same time:

1. The public issuer must be reachable through a stable reverse-proxy target.
   The previous live path depended on mutable deployment networking and
   ambiguous proxy routing.
2. The public test database must be seeded from public-only OIDF plan configs
   that match the exact client IDs and client constraints used by the official
   plan.
3. The official `fapi-ciba-id1` plan requires both CIBA clients to include
   `acr_value`. The repository public plan template had `acr_value` missing for
   the second CIBA client, so the suite failed in
   `FAPICIBAAddAcrValuesToAuthorizationEndpointRequest` with
   `Couldn't find acr_value in configuration`.

The CIBA application code was not the root cause of the final public failure.
The failing condition was a test input completeness failure.

## Deployment Boundary

This record keeps only public conformance inputs and results. Deployment topology details are intentionally omitted from conformance evidence.

## Correct Public OIDF Test Path

1. Deploy through the private live deployment path and verify public health:
   `https://issuer.example/health`.
2. Export public-only OIDF seed configs. Do not copy raw rendered plan configs
   containing passwords, browser automation secrets, private keys, or mTLS keys.
3. Upload the sanitized seed bundle to the private live deployment host and
   seed the live app database through the app container network.
4. Set the targeted GitHub variables:
   `OIDF_PLAN_EXPRESSION` to the CIBA plan above and
   `OIDF_MONITOR_INTERVAL_SECONDS=0`.
5. Run `oidf-conformance.yml` on
   `codex/ni-006-011-oidc-profiles`.
6. Verify the workflow conclusion and redacted runner log totals. Do not upload
   complete suite exports.

## Follow-up Boundary

This record closes the public targeted NI-007 FAPI-CIBA failure. It is not a
fresh full 20-plan public matrix run after the CIBA fix.
