# Experimental FAPI 2.0 HTTP Signatures

## Decision and source boundary

NazoAuth implements a bounded, experimental resource profile against the
[OpenID FAPI 2.0 HTTP Signatures working draft](https://openid.bitbucket.io/fapi/fapi-2_0-http-signatures.html)
built on 2026-06-26. It is separate from the FAPI 2.0 Security Profile and
FAPI 2.0 Message Signing Final Specifications.
The implementation uses RFC 9421 HTTP Message Signatures and RFC 9530
`Content-Digest` primitives. A newer working draft, Implementer's Draft, or
Final Specification requires a normative delta audit before changing this
claim or behavior.

## Product and threat boundary

The intended user is a registered confidential resource client that needs
application-layer evidence binding an access-token exchange to the exact
method, target URI, selected Authorization/DPoP fields, and body. The feature
addresses intermediary or application-layer mutation, replay, wrong-client or
wrong-key use, and unsigned-response downgrade. It does not replace TLS,
sender-constrained tokens, access-token audience checks, or authorization.

The only runtime gate is the explicit persisted `http_message_signatures`
module desired state, default disabled; the only affected route is `/fapi/resource`. No discovery, authorization-server,
protected-resource, registration, or algorithm metadata is advertised.
Existing OAuth/OIDC, FAPI2 Security, Message Signing, CIBA, and SCIM behavior
is unchanged while the gate is off.

Operators own client public-key provisioning and revocation, server signing
key custody and rotation, clock synchronization, Valkey durability and
availability for atomic replay consumption, log redaction, incident handling,
and signed-evidence retention. Key lookup is bound to the access token's tenant
and `client_id`; request `keyid` never selects another client's key.

## Cryptographic and protocol limits

The accepted request and generated response algorithms are:

- `ed25519` with an Ed25519 OKP key;
- `rsa-v1_5-sha256` with an RSA public key of at least 2048 bits;
- `ecdsa-p256-sha256` with a P-256 public key.

Private JWK members, a JWK `use` other than the string `sig`, any present
`key_ops` value other than the exact one-element string array `["verify"]`,
unsupported curves, key/alg
mismatch, ambiguous fields or keys, malformed structured fields, missing
required covered components, invalid body digests, stale/future creation times,
and replay all fail closed. The required profile components are validated as a
set while safe, unique ordinary header components may be selected explicitly
and are reconstructed in received RFC 9421 identifier order. Responses cover
status, physical response digest, final `Content-Type` and
`X-Fapi-Interaction-Id` values when present, request method and target URI, the
semantic request digest when present, and the exact received request
`Signature-Input` and `Signature` fields. Signing or replay-store failure cannot
downgrade to an unsigned success, and external signer stderr is not logged.
Reserved `Signature` and `Signature-Input` fields cannot be selected as extras,
preventing self-referential signature bases. The server captures safe request
header context once per request using lowercase unique names and valid
control-free text; ambiguous or non-text values are unavailable to component
reconstruction and therefore fail closed if selected.

## Evidence and conformance status

The Rust crate is the canonical canonicalization and cryptographic-vector
implementation. Its request and response tests cover GET/POST,
structured-field ambiguity, digest, time, algorithm/key policy, replay
fingerprints, request binding, response binding, and altered inputs. The
Actix resource-route tests cover the default-off boundary and its HTTP
integration. No separate Python wire-vector runner is a current source of
cryptographic truth or external-conformance evidence.

These tests are bounded implementation evidence, not certification. The
experiment is not covered by certification of other FAPI profiles.

## Specification update policy

For every newer publication, compare covered components, structured-field
rules, time and replay requirements, key discovery, algorithm requirements,
response/request binding, error signing, and metadata. Any
normative delta requires new failing tests, updated operational ownership, and
fresh real-HTTP evidence before adoption.
