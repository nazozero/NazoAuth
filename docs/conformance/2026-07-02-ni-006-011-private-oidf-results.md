# 2026-07-02 NI-006~NI-011 Private OIDF Results

## Environment

| Field | Value |
| --- | --- |
| Target issuer | `https://auth.nazo.run` |
| Repository path | `/root/oauth2_server/NazoAuth` |
| Suite path | `/root/oauth2_server/oidf-conformance-suite` |
| Suite commit | `edbf2514e1e5c850ccf28544953608bda50daf4d` |
| Branch | `codex/ni-006-011-oidc-profiles` |
| Latest runtime/config commit | `6b9badf` |
| Latest backend image code commit | `6b9badf` |
| Runner | `scripts/run_oidf_conformance.py --no-api-token --disable-ssl-verify` |

The service health check in the private conformance environment returned
`{"status":"正常"}` before the final NI-007 rerun.

## Matrix Coverage

| Task | Official suite mapping | Matrix action |
| --- | --- | --- |
| NI-006 RFC 7523 | No dedicated official plan was found for third-party JWT bearer grant assertion trust. Existing OIDC/FAPI plans cover `private_key_jwt` client assertions, not the bounded self-asserted JWT bearer grant implemented here. | No OIDF plan added. Keep local RFC 7523 grant tests and metadata truth tests. |
| NI-007 OpenID Connect CIBA / FAPI CIBA | `fapi-ciba-id1-test-plan` exists for FAPI-CIBA AS. | Added as plan 20 in the repository OIDF matrix and executed in the private conformance environment. Latest targeted run passed with no failures, warnings, or module-level skips. |
| NI-008 OpenID Connect Front-Channel Logout | `oidcc-frontchannel-rp-initiated-logout-certification-test-plan` exists. | Added as plan 18 and executed in the private conformance environment. Isolated run passed. |
| NI-009 OpenID Connect Session Management | `oidcc-session-management-certification-test-plan` exists. | Added as plan 19 and executed in the private conformance environment. Run passed. |
| NI-010 OpenID Federation 1.1 / OpenID Federation for OpenID Connect 1.1 | Historical suite lookup found Federation alpha plans, including deployed entity and joined-to-test-federation OP/RP plans; the current specifications are OpenID Federation 1.1 and OpenID Federation for OpenID Connect 1.1. | Not added to the must-pass matrix. The project no longer implements `/.well-known/openid-federation` or a self-issued entity statement, and should not advertise Federation OP/RP support without a full 1.1 trust-chain implementation. |
| NI-011 OpenID Connect Native SSO | No official Native SSO / `device_secret` OP plan was found. | No OIDF plan added. Keep local device-secret lifecycle, `ds_hash`, token exchange, and refresh-family tests. |

## Private Runs

| Task | Plan | Plan ID | Export directory | Module result | Log result summary |
| --- | --- | --- | --- | --- | --- |
| NI-008 | `oidcc-frontchannel-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]` | `HRYo5vZ393grD` | `/root/oauth2_server/NazoAuth/oidf-results-ni-008-fee362d-20260702T072615Z` | 2 passed, 0 failed, 0 module skipped | 84 success, 0 failure, 0 warning, 5 informational optional-condition skips |
| NI-009 | `oidcc-session-management-certification-test-plan[response_type=code][client_registration=static_client]` | `PKnVhX4DiBC6T` | `/root/oauth2_server/NazoAuth/oidf-results-ni-008-009-fee362d-20260702T072550Z` | 2 passed, 0 failed, 0 module skipped | 58 success, 0 failure, 0 warning, 5 informational optional-condition skips |
| NI-007 | `fapi-ciba-id1-test-plan[client_auth_type=private_key_jwt][fapi_ciba_profile=plain_fapi][ciba_mode=poll][client_registration=static_client]` | `Uc3kj8RHeZydk` | `/root/oauth2_server/NazoAuth/oidf-results-ni-007-6b9badf-public-ciba-token-fapi` | 35 passed, 0 failed, 0 module skipped | 2660 success, 0 failure, 0 warning |

The NI-008 and NI-009 evidence above uses the passing isolated/targeted results.
An earlier combined NI-008+NI-009 run caused browser/session interference for
the front-channel logout plan because both plans reused the same test user and
browser session. Future browser-sensitive logout/session plans should be run in
isolation or with distinct users and aliases.

## SKIPPED Interpretation

The official module final states in the latest NI-008, NI-009, and NI-007
exports contain no `SKIPPED` module results.

The exported JSON logs do contain informational messages whose text starts with
`Skipped evaluation due to ...`. These are optional-condition checks inside a
module, not module-level `SKIPPED` results:

- NI-008 and NI-009: static logout/session plans did not configure client JWKs
  or encrypted ID Tokens, so optional client-JWK and ID Token encryption checks
  logged five informational skipped evaluations.
- NI-007: the latest targeted rerun did not report module-level skips,
  failures, or warnings.

Therefore NI-007, NI-008, and NI-009 satisfy `0 failures`, `0 warnings`, and
`0 skipped modules`. The informational optional-condition messages in the
logout/session JSON logs are not module-level suite skips. Enabling optional
client JWK / ID Token encryption only to remove those informational messages
would broaden the advertised profile surface and is not required for these
logout/session profiles.

## NI-007 Result Summary

FAPI-CIBA now passes the targeted official suite in the private conformance
environment at runtime commit `6b9badf`. The rerun specifically covers the
previously failing positive backchannel authentication request, signed
backchannel request-object negative cases, refresh-token polling path, and
mTLS holder-of-key token-polling error precedence.

## Local Verification

- `cargo test bootstrap::tests --lib`
- `cargo test oidc_logout --lib`
- `cargo test id_token_sid --lib`
- `cargo test session_management --lib`
- `rtk proxy cargo test native_sso --lib`
- `rtk proxy cargo test ciba --lib`
- `rtk proxy cargo check --lib`
- `cargo fmt --check`
- `rtk proxy cargo fmt --check`
- `python -m compileall -q scripts tests/unit`
- `python -m unittest tests.unit.test_setup_local_oidf_podman`
