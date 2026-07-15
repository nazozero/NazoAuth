# FAPI-CIBA mTLS and Ping Local and Official OIDF Matrix

Date: 2026-07-15

## Result

The FAPI-CIBA matrix passed both required conformance gates against the
deployed public issuer `https://auth.nazo.run`:

| Gate | Result |
| --- | --- |
| Hostinger local official-suite matrix | `success` |
| GitHub official parallel-isolated matrix | `success` |
| Matrix layout | 23 concurrency-safe plans + front-channel logout + session management |
| Local module results | 787 total: 770 `PASSED`, 9 allowed `REVIEW`, 8 expected `SKIPPED`, 0 `WARNING`, 0 `FAILED` |
| Official module results | 787 total: 748 `PASSED`, 22 bounded `WARNING`, 9 allowed `REVIEW`, 8 expected `SKIPPED`, 0 `FAILED` |
| Local condition results | 59,904 `SUCCESS`, 0 `WARNING`, 0 `FAILURE` |
| Official condition results | 59,878 `SUCCESS`, 26 bounded `WARNING`, 0 `FAILURE` |

This run adds official-suite evidence for all four orthogonal FAPI-CIBA
combinations:

| Client authentication | Delivery mode | Local result | Official result |
| --- | --- | --- | --- |
| `private_key_jwt` | poll | 36 modules, 2,777 success, 0 warning/failure | 35 modules, 2,777 success, 0 warning/failure |
| mTLS | poll | 34 modules, 2,536 success, 0 warning/failure | 33 modules, 2,536 success, 0 warning/failure |
| `private_key_jwt` | ping | 41 modules, 3,470 success, 0 warning/failure | 40 modules, 3,457 success, 13 bounded warnings, 0 failure |
| mTLS | ping | 39 modules, 3,190 success, 0 warning/failure | 38 modules, 3,177 success, 13 bounded warnings, 0 failure |

The local module count includes the locally generated discovery instance for
each CIBA plan. The exported official archives contain the corresponding plan
modules and condition results shown above.

The nine `REVIEW` modules are the three expected screenshot-review modules
`oidcc-prompt-login`, `oidcc-max-age-1`, and
`oidcc-ensure-registered-redirect-uri` in the static, dynamic-registration,
and Form Post OIDC plans. The eight expected skips are the exact `alg: none`
compatibility instances documented in
[`oidf-full-matrix.md`](oidf-full-matrix.md#expected-skip-policy). There were no
unexpected review states or skips.

## Tested Deployment

| Field | Value |
| --- | --- |
| Runtime implementation commit | `e5bed9261aa238f4eb62e89ce44c8b4c68be0959` |
| Official workflow head | `8d2ec0ec3269b298918f4735a538ba76dd90e0b5` |
| Pull request | [#59](https://github.com/nazozero/NazoAuth/pull/59) |
| Backend image | `localhost/nazo-oauth-server:ciba-e5bed92` |
| Public issuer | `https://auth.nazo.run` |
| Hostinger result directory | `/root/oauth2_server/oidf-matrix-e5bed92-v5.2.0` |
| Suite version | `5.2.0` |
| Suite commit | `dee9a25160e789f0f80517674693ef7989ab9fa1` |
| Official workflow | [`oidf-conformance-full` run 29445723200](https://github.com/nazozero/NazoAuth/actions/runs/29445723200) |
| Main official job | [`oidf-conformance-full`](https://github.com/nazozero/NazoAuth/actions/runs/29445723200/job/87455572967) |
| Front-channel job | [`frontchannel`](https://github.com/nazozero/NazoAuth/actions/runs/29445723200/job/87455572991) |
| Session-management job | [`session-management`](https://github.com/nazozero/NazoAuth/actions/runs/29445723200/job/87455572965) |
| Official mTLS CA SHA-256 | `5cc604d46bb9b348c12fbd9465a8a1bf920ea21ff45b433d68e83be8aa09dd98` |

The deployed discovery document advertised both `poll` and `ping`, the CIBA
backchannel endpoint and signing algorithms, and
`tls_client_certificate_bound_access_tokens=true`. Push delivery remains
explicitly unsupported because the FAPI-CIBA profile prohibits it.

## FAPI-CIBA Plan IDs

| Profile | Hostinger local | Official |
| --- | --- | --- |
| `private_key_jwt` / poll | `SmKGkyROnSCwF` | [`hLo7pVeEdnw6v`](https://www.certification.openid.net/plan-detail.html?plan=hLo7pVeEdnw6v) |
| mTLS / poll | `wdA0Ww8lolVVx` | [`tQ5AR14JGHGAy`](https://www.certification.openid.net/plan-detail.html?plan=tQ5AR14JGHGAy) |
| `private_key_jwt` / ping | `ufsv0jX35Pyz9` | [`EqUEoOMoQQKTc`](https://www.certification.openid.net/plan-detail.html?plan=EqUEoOMoQQKTc) |
| mTLS / ping | `PUVBIX13MnPUi` | [`anoFWADUcSCsy`](https://www.certification.openid.net/plan-detail.html?plan=anoFWADUcSCsy) |
| Front-Channel Logout | `AHMUqtv8gmtIo` | [`ux2Ed93E8ksDV`](https://www.certification.openid.net/plan-detail.html?plan=ux2Ed93E8ksDV) |
| Session Management | `D6XnFC13XWNM6` | [`RpKUiCWP3Zaso`](https://www.certification.openid.net/plan-detail.html?plan=RpKUiCWP3Zaso) |

The remaining OIDC, FAPI2 Security, and FAPI2 Message Signing plans also
completed in both 25-plan runs. Their exported archives are retained in the
main result artifact.

## Bounded Official TLS Warnings

The 26 official warnings are all the suite condition
`EnsureIncomingTls13`: 13 in the `private_key_jwt` ping plan and 13 in the
mTLS ping plan, spread across 22 modules. They are not general warning
allowances. The repository contract
[`oidf-official-expected-warnings.json`](../../tests/contracts/oidf-official-expected-warnings.json)
matches the configuration filename, complete variant, module, block,
condition, and result for every record. An extra warning, a changed context,
or a missing expected record fails the workflow.

The official callback ingress negotiated TLS 1.2 with the recommended
BCP 195 cipher, so the companion suite condition
`EnsureIncomingTls12WithSecureCipherOrTls13` passed. Direct verification
showed that `www.certification.openid.net:443` rejected a TLS 1.3 ClientHello
with a protocol-version alert while accepting TLS 1.2. The same NazoAuth
runtime negotiated TLS 1.3 with the Hostinger local official-suite ingress;
the local 25-plan run consequently reported zero warnings. NazoAuth's ping
client offers TLS 1.3, permits TLS 1.2 as the FAPI-CIBA minimum, validates the
configured trust roots, rejects redirects, and fails closed.

This is a bounded upstream-ingress observation, not a waiver for a NazoAuth
protocol or transport failure.

## Official Artifacts

| Artifact | ID | Size | SHA-256 digest | Expires |
| --- | --- | ---: | --- | --- |
| `oidf-conformance-results-concurrent` | `8355633867` | 22,068,817 bytes | `9aa8f962f40b3b5af5250a0c40ae0ee7951c1ce0dc71c3c7b2e4daf34df35c26` | 2026-10-13 |
| `oidf-conformance-results-frontchannel` | `8355380582` | 31,131 bytes | `f8d0e94c6667ab8abf89d0788b10d075b9eb636da91e6e06db0369fafe1b87fa` | 2026-10-13 |
| `oidf-conformance-results-session-management` | `8355375554` | 26,312 bytes | `309387e71ed2bab01732b93897ddc9d469f780d600ca6170c43ecbcb527e7850` | 2026-10-13 |
| `oidf-public-plan-configs` | `8355377342` | 79,018 bytes | `40b521c408724c6320f3c6d65cd9473e4773fa915f13bf9d4af64936ce3dc4a7` | 2026-10-13 |

## Claim Boundary

This record proves that the deployed implementation completed the repository's
25-plan local and official-suite regression matrices, including the four
FAPI-CIBA combinations. It does not by itself claim that OpenID Foundation has
issued or published a formal FAPI-CIBA certification for NazoAuth. Formal
certification remains a separate submission and review process.
