# 2026-07-19 Public Black-Box Full OIDF Results

## Summary

This record covers the production protocol revision
`1df7e6c2947833ae4faad15d1699526efa8bb8ec`. Both the operator-run public
suite and the OpenID Foundation public suite tested the externally reachable
service surface. The public repository uses `https://issuer.example` as a
sanitized placeholder; operators must supply their own issuer and suite origin.

| Gate | Result |
| --- | --- |
| Production deployment revision | `1df7e6c2947833ae4faad15d1699526efa8bb8ec` |
| Public production health | `success` |
| Operator-run public black-box OIDC / FAPI / FAPI-CIBA matrix | `25 / 25` |
| Operator-run public black-box OpenID4VC matrix | `17 / 17` |
| Official OIDC / FAPI / FAPI-CIBA workflow | `success` |
| Official OpenID4VC Final / HAIP workflow | `success` |
| Failed modules / conditions | `0` |

The official workflows executed 42 plans:

- 25 OIDC / FAPI / FAPI-CIBA plans;
- 17 OpenID4VC Final / HAIP plans.

No private endpoint, private DNS name, suite-internal callback address, private
reverse-proxy address, or repository-owned default issuer is accepted as
evidence. Client onboarding and trust-anchor approval use the same public
administrative flows available to a production integrator.

## Public black-box gate

Before the official workflows were requested, the same deployed revision passed
the operator-run public suite:

| Matrix | Result | Execution boundary |
| --- | --- | --- |
| OIDC / FAPI main matrix | `19 / 19` | Bounded concurrent groups against the public issuer |
| FAPI-CIBA | `4 / 4` | poll and ping with `private_key_jwt` and mTLS client authentication |
| Front-Channel Logout | `1 / 1` | Browser-isolated |
| Session Management | `1 / 1` | Browser-isolated |
| OpenID4VC Final / HAIP | `17 / 17` | Public issuer, public wallet/verifier callbacks |

The operator-run suite source was pinned to OpenID Foundation Conformance Suite
commit `dee9a25160e789f0f80517674693ef7989ab9fa1`. Protocol and assertion source
trees were unchanged. The only runner-side adaptation was the repository-owned
terminal/export integration used to automate result collection; it cannot alter
protocol assertions, result classification, or pass criteria.

## Official OIDC / FAPI / FAPI-CIBA matrix

| Item | Value |
| --- | --- |
| Workflow | [`oidf-conformance-full`](https://github.com/nazozero/NazoAuth/actions/runs/29672914368) |
| Head SHA | `1df7e6c2947833ae4faad15d1699526efa8bb8ec` |
| Result | `success` |
| Main job | [`oidf-conformance-full`](https://github.com/nazozero/NazoAuth/actions/runs/29672914368/job/88155023034) |
| Front-channel job | [`frontchannel`](https://github.com/nazozero/NazoAuth/actions/runs/29672914368/job/88155023069) |
| Session-management job | [`session-management`](https://github.com/nazozero/NazoAuth/actions/runs/29672914368/job/88155023070) |
| Plans | `25` |
| Module instances | `787` |
| Module results | `748 PASSED`, `22 WARNING`, `9 REVIEW`, `8 SKIPPED` |
| Condition successes | `56,988` |
| Condition failures | `0` |
| Condition warnings | `26` |

The 22 `WARNING` module results are confined to the two FAPI-CIBA ping plans.
They contain 26 occurrences of the official ingress advisory
`Client doesn't support TLS 1.3`. The operator-run public suite negotiated TLS
1.3 and did not produce this warning, so it is recorded as an official-ingress
condition rather than a product transport exception.

The nine `REVIEW` results are the bounded browser checks for `prompt=login`,
`max_age=1`, and registered redirect-URI error presentation in the Basic static,
Basic dynamic-registration, and Form Post plans. The eight `SKIPPED` results are
the exact unsigned JWT compatibility cases documented in
[`oidf-full-matrix.md`](oidf-full-matrix.md#expected-skip-policy). The service
does not advertise or accept `alg: none`; an additional or mismatched skip is a
failure.

Artifacts:

- `oidf-conformance-results-concurrent`
- `oidf-conformance-results-frontchannel`
- `oidf-conformance-results-session-management`
- `oidf-public-plan-configs`

## Official OpenID4VC Final / HAIP matrix

| Item | Value |
| --- | --- |
| Workflow | [`openid4vc-conformance`](https://github.com/nazozero/NazoAuth/actions/runs/29672915479) |
| Head SHA | `1df7e6c2947833ae4faad15d1699526efa8bb8ec` |
| Result | `success` |
| Job | [`official-openid4vc-matrix`](https://github.com/nazozero/NazoAuth/actions/runs/29672915479/job/88155025116) |
| Plans | `17` |
| Module instances | `391` |
| Module results | `384 PASSED`, `7 SKIPPED` |
| Condition successes | `40,041` |
| Condition failures | `0` |
| Condition warnings | `4` |

The four warnings are the bounded HAIP refresh-token advisory. The seven skips
are the plan-defined optional paths recorded by the OpenID4VC matrix contract;
there were no unexpected skips. These upstream OpenID4VC plan families are
official-suite regression plans, not an OpenID Foundation certification claim.

Artifact:

- `openid4vc-conformance-1df7e6c2947833ae4faad15d1699526efa8bb8ec`

## Combined official result

| Metric | Value |
| --- | ---: |
| Official public workflows | `2` |
| Plan executions | `42` |
| Module instances | `1,178` |
| Passed module results | `1,132` |
| Warning module results | `22` |
| Review module results | `9` |
| Expected skipped module results | `15` |
| Condition successes | `97,029` |
| Condition failures | `0` |
| Condition warnings | `30` |

## Evidence boundary

This record is evidence for the tested production protocol revision, not a
substitute for an OpenID Foundation certification listing. A diagnostic run that
depends on private connectivity, internal callback origins, direct database
seeding, a suite-only product branch, or relaxed protocol behavior is not
production-equivalent evidence and must not be used for a conformance claim.

The repeatable process, including real onboarding, trust-anchor approval,
bounded concurrency, official-suite submission, result classification, and
cleanup, is defined in the
[`OIDF public black-box conformance runbook`](oidf-public-black-box-runbook.md).
