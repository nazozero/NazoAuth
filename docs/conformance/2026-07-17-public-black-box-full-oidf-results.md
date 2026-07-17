# 2026-07-17 Public Black-Box Full OIDF Results

## Summary

This record is the current conformance evidence for the production deployment.
It only counts public black-box official-suite runs against
`https://auth.nazo.run`.

| Gate | Result |
|---|---|
| Production deployment revision | `ae19cc50af4cc50f3f35f678a3a1c38332d475e2` |
| Public production health | `success` |
| OIDC / FAPI / FAPI-CIBA official public matrix | `success` |
| OpenID4VC Final / HAIP official public matrix | `success` |
| Failed modules / conditions | `0` |

The two official runs cover 42 plan executions in total:

- 25 OIDC / FAPI / FAPI-CIBA plans from `oidf-conformance-full`
- 17 OpenID4VC Final / HAIP alpha plans from `openid4vc-conformance`

Both workflows ran from GitHub Actions against the public production origin. No
local Podman DNS name, loopback endpoint, internal reverse proxy, private test
CA, or `https://nginx:8443` endpoint is accepted as evidence in this record.

## Tested revision and production boundary

| Item | Value |
|---|---|
| Tested commit | `ae19cc50af4cc50f3f35f678a3a1c38332d475e2` |
| Tested origin | `https://auth.nazo.run` |
| Production health | `{"status":"正常"}` |
| Production OCI revision | `ae19cc50af4cc50f3f35f678a3a1c38332d475e2` |
| Local suite TLS override | Not present (`SSL_CERT_FILE` unset) |
| Local/internal markers in production container | None found for `nginx`, `8443`, or `oidf-local` |

Testing is production. The acceptable test target is the public service surface
that external clients use. Local official-suite attempts that depended on
internal addresses, private Podman DNS, locally trusted CAs, or suite-local
callback origins are intentionally excluded from this evidence.

## OIDC / FAPI / FAPI-CIBA official public matrix

| Item | Value |
|---|---|
| Workflow | [`oidf-conformance-full`](https://github.com/nazozero/NazoAuth/actions/runs/29543012193) |
| Head SHA | `ae19cc50af4cc50f3f35f678a3a1c38332d475e2` |
| Result | `success` |
| Main matrix job | [`oidf-conformance-full`](https://github.com/nazozero/NazoAuth/actions/runs/29543012193/job/87768979875) |
| Front-channel job | [`frontchannel`](https://github.com/nazozero/NazoAuth/actions/runs/29543012193/job/87768979854) |
| Session-management job | [`session-management`](https://github.com/nazozero/NazoAuth/actions/runs/29543012193/job/87768979855) |
| Plans | `25` (`23` concurrent + `2` browser-isolated) |
| Finished modules | `787` |
| Condition successes | `59,738` |
| Condition failures | `0` |
| Bounded warnings | `26` |
| Expected skips | `8` |
| Review entries | `104` |

The 26 warnings are all the known FAPI-CIBA ping callback condition
`Client doesn't support TLS 1.3` observed at the official public suite ingress.
They are bounded by the repository warning contract and do not represent a
NazoAuth transport or protocol failure. The eight skips are the exact optional
`alg: none` compatibility instances documented in
[`oidf-full-matrix.md`](oidf-full-matrix.md#expected-skip-policy).

Artifacts:

- `oidf-conformance-results-concurrent`
- `oidf-conformance-results-frontchannel`
- `oidf-conformance-results-session-management`
- `oidf-public-plan-configs`

## OpenID4VC Final / HAIP official public matrix

| Item | Value |
|---|---|
| Workflow | [`openid4vc-conformance`](https://github.com/nazozero/NazoAuth/actions/runs/29545407427) |
| Head SHA | `ae19cc50af4cc50f3f35f678a3a1c38332d475e2` |
| Result | `success` |
| Job | [`official-openid4vc-matrix`](https://github.com/nazozero/NazoAuth/actions/runs/29545407427/job/87776518188) |
| Plans | `17` |
| Finished modules | `391` |
| Condition successes | `41,781` |
| Condition failures | `0` |
| Bounded warnings | `4` |
| Expected skips | `7` |
| Review entries | `32` |

The four warnings are the expected HAIP refresh-token advisory: the server
supports refresh tokens generally, but the bounded HAIP client policy does not
issue one in those flows. The OpenID4VC upstream plan families are still alpha
regression plans; this record is official-suite regression evidence, not an
OpenID Foundation certification claim for OpenID4VC.

Artifact:

- `openid4vc-conformance-ae19cc50af4cc50f3f35f678a3a1c38332d475e2`

## Combined result

| Metric | Value |
|---|---:|
| Official public workflows | `2` |
| Plan executions | `42` |
| Finished modules | `1,178` |
| Condition successes | `101,519` |
| Condition failures | `0` |
| Bounded warnings | `30` |
| Expected skips | `15` |
| Review entries | `136` |

## Evidence boundary

This record deliberately does not cite local Hostinger suite runs as passing
evidence. Local execution can still be useful for debugging, but conformance
claims for this project must be based on public black-box runs against
`https://auth.nazo.run` using the same externally reachable issuer, redirect
surfaces, callback paths, TLS configuration, and client-visible metadata that a
real deployment exposes.

If a future run requires local endpoints, private DNS, local CA injection, or
suite-only callbacks to pass, that run is not production-equivalent evidence and
must not be used to claim OIDF conformance.
