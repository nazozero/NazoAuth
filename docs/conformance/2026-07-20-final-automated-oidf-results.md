# 2026-07-20 Final Automated OIDF Results

## Summary

This record supersedes the 2026-07-19 `1df7e6c2` run set as the latest
production-equivalent conformance evidence. The final deployed revision is
`0a747b42228962e562af012638297c56e3af5505`. The official OpenID4VC run tested
`0bea51247913d7f6535374ad2de7d121c9234859`; the only changes between that
revision and the final deployment are in `scripts/run_oidf_conformance.py` and
its unit tests, not in protocol implementation code.

The operator public black-box runs used source commit
`a6b75bbac5f6d8b40c01b14cce13d3edb99c8800`. Its Git tree
`9ad1c8e715b5cfa95589310fb6aa297ac38c3544` is identical to merged commit
`0bea5124`. Public documentation uses `https://issuer.example` as the sanitized
placeholder for the production issuer.

| Gate | Result |
| --- | --- |
| Operator public OIDC / FAPI / FAPI-CIBA | `25 / 25` plans completed, exit status `0` |
| Operator public OpenID4VC Final / HAIP | `17 / 17` plans completed; every non-pass result matched an exact registry entry |
| Official OIDC / FAPI / FAPI-CIBA | [`29705159845`](https://github.com/nazozero/NazoAuth/actions/runs/29705159845) `success` |
| Official OpenID4VC Final / HAIP | [`29700527789`](https://github.com/nazozero/NazoAuth/actions/runs/29700527789) `success` |
| Final PR checks | PR #84: `11 passed`, `0 failed` |
| Public discovery | HTTP `200` after the final deployment |

## Suite revisions

The operator-controlled pristine suite checkout was pinned to
`946451d1ce29965c9ab7aee05f5003552233160e`; exported modules report suite
version `5.2.0`. Official workflows were pinned to
`dee9a25160e789f0f80517674693ef7989ab9fa1`. Neither path modified upstream
protocol assertions or acceptance conditions.

## Operator public OIDC / FAPI / FAPI-CIBA

Execution ran from `2026-07-19T18:51:57Z` through `2026-07-19T19:15:27Z`.

| Metric | Value |
| --- | ---: |
| Plan archives / plan IDs | `25 / 25` |
| Module instances | `787` |
| `PASSED` | `769` |
| Bounded `REVIEW` | `9` |
| Expected `SKIPPED` | `8` |
| Exactly registered `WARNING` | `1` |
| `SUCCESS` conditions | `57,013` |
| `FAILURE` conditions | `0` |
| `WARNING` conditions | `1` |

The sole warning is `UnregisterDynamicallyRegisteredClient` in
`oidcc-3rd_party-init-login`. RFC 7592 permits registration access-token
rotation on client read; the upstream module does not adopt the rotated token
for its best-effort cleanup DELETE. Run-scoped product cleanup independently
deactivates that client. The exception is bound to the exact configuration,
variant, module, and condition rather than a wildcard.

Plan IDs:

```text
0VBaoLcjdljI1 3LjN5Zv35t5na 4S9mdwDHWaW8J 9E2DRM0zP5i4O 9RHzwF98I0NRi
BFIyCz1dNhmGq O9tjhWWY1DTXw RcmHDC3dhpuTQ WPBThJvTR71ac WpgsS8LIVgD4U
XNaM8OaI69bIx ZJlvF4WueIYH2 ZVueIMnS64m8M ZcKFUpDHmktBI b4v9c8betyYQP
bHhRnodzPBXi6 gV0CwYNtbYBYU kinHfkVmKHPjS n94lHtAX42Duh oPgTG25FdVf6y
sLVib9Ll4ALoN tgseyORV7HmO6 vnQBWCP6cUU2x wnkPco7geO2lt zMcoevPTpxdt2
```

Credential-free evidence manifest SHA-256:
`b563075afff6c981ca5bb7f0e7942d80f8522a809eb7f76a75f3d80ff5362b14`.

## Operator public OpenID4VC Final / HAIP

Execution ran from `2026-07-19T18:42:34Z` through `2026-07-19T18:50:28Z`.

| Metric | Value |
| --- | ---: |
| Plan archives / plan IDs | `17 / 17` |
| Module instances | `391` |
| `PASSED` | `382` |
| Exactly registered `FAILED` | `2` |
| Expected `SKIPPED` | `7` |
| `SUCCESS` conditions | `39,792` |
| Exactly registered `FAILURE` conditions | `2` |
| Bounded `WARNING` conditions | `4` |

Both failed modules are the issuer-initiated pre-authorized-code variants of
`oid4vci-1_0-issuer-happy-flow-multiple-clients`, for `mdoc` and `sd_jwt_vc`.
The upstream module asks a second client to redeem the same pre-authorized code,
while OpenID4VCI 1.0 Final section 4.1.1 requires one-time use. The implementation
keeps the normative behavior; the exception is bound only to those two variants.

Plan IDs:

```text
8L9yFwEaEJoOL 8dbkHQITlLas9 MsFyeilZbXvju O8sq0teuI3AKt OLfJGeGp0wd4T
QHmgRZanz00Pc QitMgPJe9x2CU TLbjTMdIUjLFN bBs47fevUm9BW d0Chz3Af3eQLE
hPXaLs8sCpVij jNn82eNaqaSEA mwvNvZXu1Ztp0 npeY755k4EDvp oFPlC6rX06wnr
xKVCHbrBKYJSO zKcE2UkP2CElp
```

Credential-free evidence manifest SHA-256:
`35298a395edb0b32a87b134a402d50e84a8f0945ef9fea30b33923ac04314e91`.

## Official runs

### OIDC / FAPI / FAPI-CIBA

| Item | Value |
| --- | --- |
| Workflow | [`oidf-conformance-full`](https://github.com/nazozero/NazoAuth/actions/runs/29705159845) |
| Head SHA | `0a747b42228962e562af012638297c56e3af5505` |
| Main matrix job | [`oidf-conformance-full`](https://github.com/nazozero/NazoAuth/actions/runs/29705159845/job/88240803466) `success` |
| Front-Channel job | [`frontchannel`](https://github.com/nazozero/NazoAuth/actions/runs/29705159845/job/88240803484) `success` |
| Session Management job | [`session-management`](https://github.com/nazozero/NazoAuth/actions/runs/29705159845/job/88240803467) `success` |
| Execution window | `2026-07-19T21:53:23Z` to `2026-07-19T22:41:05Z` |

This pre-sanitizer workflow did not upload an Actions artifact. Its durable
evidence is the workflow/job terminal state, pinned suite revision, exact
expected-result contracts, and the production-equivalent operator manifest.
No official module totals are inferred where no export exists.

### OpenID4VC Final / HAIP

| Item | Value |
| --- | --- |
| Workflow | [`openid4vc-conformance`](https://github.com/nazozero/NazoAuth/actions/runs/29700527789) |
| Head SHA | `0bea51247913d7f6535374ad2de7d121c9234859` |
| Job | [`official-openid4vc-matrix`](https://github.com/nazozero/NazoAuth/actions/runs/29700527789/job/88228721614) `success` |
| Execution window | `2026-07-19T19:24:34Z` to `2026-07-19T19:45:01Z` |

The old workflow uploaded raw suite ZIPs rather than genuinely redacted
evidence. After discovering that raw exports include browser configuration, the
artifact was deleted on 2026-07-20 and is not used as durable evidence. The
workflow/job terminal state remains; module-level statistics come from the
operator public manifest against the same protocol tree.

## Evidence-retention boundary

Raw suite ZIPs contain `testInfo.config` and log bodies and can therefore carry
browser credentials, client secrets, tokens, or private keys. They must never
be committed or uploaded as general artifacts. This run's raw ZIPs were deleted
after successful manifest generation.

The manifest retains only archive names and source SHA-256 values, plan/module
identifiers, variants, terminal results, signature-file presence, and condition
result counts. It excludes configuration, log bodies, operator identity, and
secret values. Future workflows upload only `evidence-manifest.json`. Because
Actions artifacts still expire, this record durably preserves implementation
and suite SHAs, run/job URLs, counts, plan IDs, and manifest digests.

