# Product-owned black-box records

This directory retains NazoAuth protocol regression contracts and Markdown
evidence from external black-box validation. OIDF evidence belongs with the
product whose behavior it verifies. It does not introduce validator-specific
server routes, schema, configuration, credentials, orchestration or runtime
evidence formats.

The RFC 9967 SCIM SET matrix is a project-owned executable black-box contract.

Third-party validators are ordinary external clients; they do not create a
server-side protocol or evidence exception.

## OpenID certification

The OpenID Foundation's public registers list `NazoAuth / Nazo Auth Server
0.2.0` for 29 conformance profiles across OpenID Provider, logout, FAPI 2.0,
FAPI-CIBA, OID4VCI 1.0 + HAIP 1.0, and OID4VP 1.0 + HAIP 1.0. The
[README certification table](../../README.md#openid-certified) links each
official register and lists the complete profiles and registration dates.

## Product regression evidence

- [2026-09-06 Direct TLS and trusted proxy candidate acceptance](oidf-2026-09-06-dual-mode-candidate.md)
  records the candidate's binary identities, original outcomes, manual review,
  cleanup, certificate lifecycle, and signed evidence digests.
- [2026-09-06 official-release acceptance](oidf-2026-09-06-official-release.md)
  records the distributed artifacts and black-box result. It is engineering
  acceptance for the identified artifacts, not an OIDF certification claim.
