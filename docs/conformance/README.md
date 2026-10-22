# Protocol regression and certification

This directory maintains NazoAuth protocol regression contracts. Formal OIDF
certification is linked to its public register and identified product version. It does not introduce validator-specific
server routes, schema, configuration, credentials, orchestration or runtime
evidence formats.

The [RFC 9967 SCIM SET matrix](rfc9967-scim-set-matrix.md) is a project-owned
executable black-box contract.

Third-party validators are ordinary external clients; they do not create a
server-side protocol or evidence exception.

## Normative requirements and external results

Protocol behavior follows the applicable specification and its selected
profile. A Suite result is evidence to investigate, not an authority that
overrides either. Reproduce a discrepancy using the request, response, and
signed material; identify the specification edition and clause before changing
the implementation or reporting a validator defect.

For HAIP issuance, [client policy](../protocol/composable-capability-policy.md)
requires PAR independently of the wallet's client authentication method.
For mdoc presentations, [issuer verification](../operations/mdoc-shared-state.md#issuer-verification)
checks certificate validity at the MSO signing time. A happy-flow fixture that
violates that requirement must still be rejected. Do not relax verification,
rewrite a signed credential, or turn the resulting Suite failure into a pass
or an expected skip. Retain the original outcome and report the discrepancy
separately.

## OpenID certification

The OpenID Foundation's public registers list `NazoAuth / Nazo Auth Server
0.2.0` for 29 conformance profiles across OpenID Provider, logout, FAPI 2.0,
FAPI-CIBA, OID4VCI 1.0 + HAIP 1.0, and OID4VP 1.0 + HAIP 1.0. The
[README certification table](../../README.md#openid-certified) links each
official register and lists the complete profiles and registration dates.

## Run-specific evidence

Keep candidate runs, manual review, acceptance logs, and artifact digests in
release assets, CI artifacts or the associated issue/PR. A successful external test run applies
to the identified artifact and is not a certification for later versions.
Maintained commands and evidence formats belong to the controller's
[OIDF guide](https://github.com/nazozero/NazoAuthCtl/blob/main/docs/oidf.md).

## Public OIDF regression

[NazoAuth v0.3.5 release results](https://github.com/nazozero/NazoAuth/releases/tag/v0.3.5)
link every plan in the latest published run on the official OIDF Suite.
The [complete module index](https://gist.github.com/bymoye/d83684c532e98bd76d5dc7a6684592fa)
records all 1,169 module outcomes, variants, public log URLs, the tested server
image digest, controller version, input identity and anonymous-access checks.
The Suite links expose the test records themselves; the index is a project-owned
snapshot, not an OIDF-signed attestation. The source report SHA-256 identifies
the private source used to generate it.

For this run, `matrix_expectations_satisfied` is true, while `suite_pass` and
`acceptance_pass` are false: 40 modules remain REVIEW and 8 are SKIPPED. These
outcomes are not counted as PASSED. All 1,169 modules were instantiated and
reached terminal states, with zero failed or incomplete modules.

Use these records to track regression results for the identified release.
A single run does not prove uninterrupted success across later commits or
releases; compare subsequent published runs and retain their original outcomes.
The historical certification registers above remain the authority for certified
versions and profiles. Publishing a run does not submit a new certification.
