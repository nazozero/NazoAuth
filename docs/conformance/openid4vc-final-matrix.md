# OpenID4VC Final conformance matrix

NazoAuth implements the **Credential Issuer** role from OpenID for Verifiable
Credential Issuance 1.0 Final and the **Verifier** role from OpenID for
Verifiable Presentations 1.0 Final. It does not implement or advertise a Wallet
role.

The implementation is split into four protocol boundaries:

- `nazo-digital-credentials`: DCQL, SD-JWT VC, ISO mdoc, JOSE/COSE and trust ports.
- `nazo-openid4vci`: issuer metadata, offers, proof validation contracts,
  immediate/batch/deferred issuance, nonces and notifications.
- `nazo-openid4vp`: verifier request policy, transaction state and DCQL-bound
  presentation verification.
- `nazo-openid4vc-http-actix`: HTTP transport and management adapters only.

Persistence, key management, subject data and HTTP are adapters behind those
domain ports. Tests live under each crate's `tests/` directory; static CI
rejects test code in the production source trees.

## Supported final boundary

The issuer supports `dc+sd-jwt` and `mso_mdoc`, authorization-code and
pre-authorized-code grants, wallet- and issuer-initiated flows, credential
offers by value or reference, S256/DPoP and client-attestation HAIP paths,
one-time proof nonces, JWT and key-attestation proofs, immediate and deferred
issuance, batch issuance, notifications, signed metadata, and ECDH-ES/A256GCM
credential request/response encryption with optional `DEF` compression.

The verifier supports DCQL for `dc+sd-jwt` and `mso_mdoc`, `redirect_uri`,
`x509_san_dns`, and `x509_hash` Client Identifier Prefixes,
`direct_post`/`direct_post.jwt`, URL-query and signed request-URI retrieval
(GET and POST), encrypted responses with per-transaction keys, transaction
data, SD-JWT KB-JWT verification, and the final OpenID4VP mdoc session
transcript. HAIP is restricted to `x509_hash`, a signed request URI, and
`direct_post.jwt`.

Unsupported optional mechanisms are not advertised: Wallet behavior,
Digital Credentials API transport, DID client identifiers, verifier
attestation client identifiers, and unbound mdoc credentials.

## OIDF suite coverage

The repository pins OIDF Conformance Suite commit
`dee9a25160e789f0f80517674693ef7989ab9fa1` (v5.2.0) and runs these upstream
plans:

- `oid4vci-1_0-issuer-test-plan`
- `oid4vci-1_0-issuer-haip-test-plan`
- `oid4vp-1final-verifier-test-plan`
- `oid4vp-1final-verifier-haip-test-plan`

The bounded registry is
[`tests/contracts/openid4vc-oidf-matrix.json`](../../tests/contracts/openid4vc-oidf-matrix.json).
It expands the plans into 18 executions covering both credential formats and
the supported security/transport axes. Management automation can only create
offers or presentation transactions; it cannot inspect protocol persistence,
so results are black-box evidence.

The upstream plan display names explicitly call these tests **alpha** and say
they are incomplete/incorrect or not currently part of the certification
program. A green run is therefore official-suite regression evidence: it is
not an OpenID Foundation certification claim. No documentation or UI may use the
OpenID Certified mark on the basis of these runs.

Normative sources:

- [OpenID4VCI 1.0 Final](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html)
- [OpenID4VP 1.0 Final](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html)
- [OpenID4VC HAIP 1.0 Final](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html)
