# Protocol regression and certification

This directory maintains NazoAuth protocol regression contracts. Formal OIDF
certification is linked to its public register and identified product version. It does not introduce validator-specific
server routes, schema, configuration, credentials, orchestration or runtime
evidence formats.

The [RFC 9967 SCIM SET matrix](rfc9967-scim-set-matrix.md) is a project-owned
executable black-box contract.

Third-party validators are ordinary external clients; they do not create a
server-side protocol or evidence exception.

## OpenID certification

The OpenID Foundation's public registers list `NazoAuth / Nazo Auth Server
0.2.0` for 29 conformance profiles across OpenID Provider, logout, FAPI 2.0,
FAPI-CIBA, OID4VCI 1.0 + HAIP 1.0, and OID4VP 1.0 + HAIP 1.0. The
[README certification table](../../README.md#openid-certified) links each
official register and lists the complete profiles and registration dates.

## Run-specific evidence

Keep candidate runs, manual review, acceptance logs, and artifact digests in
CI artifacts or the associated issue/PR. A successful external test run applies
to the identified artifact and is not a certification for later versions.
Maintained commands and evidence formats belong to the controller's
[OIDF artifact guide](https://github.com/nazozero/NazoAuthCtl/blob/main/docs/oidf-artifacts.md).
