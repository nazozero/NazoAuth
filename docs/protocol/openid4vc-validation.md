# OpenID4VC validation boundaries

The issuer uses [OpenID4VCI 1.0 Final Appendices D and F](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-proof-types).
JWT proofs require a scalar Credential Issuer audience; a supplied issuer must
be a string matching the credential authorization's client. Anonymous
pre-authorized provenance is not yet represented in that proof-validation
contract, so the anonymous flow's mandatory omission of `iss` remains an open
conformance item. A placeholder client identifier is not provenance evidence.

An embedded key attestation must attest the actual JWT signing key even when
attestation is optional. Its algorithm must be in the selected configuration's
advertised list. This issuer advertises a Nonce Endpoint, so standalone and
embedded attestations both carry the issued nonce. Embedded attestations also
require expiration. Standalone `attestation` contains exactly one JWT; multiple
keys inside that JWT still produce a bounded credential batch.

Configuration identifiers and credential identifiers are separate selectors.
A credential identifier must exactly match an authorized identifier and map
to its authorized configuration. A scope-granted configuration cannot be used
as a credential identifier. The deferred wire request ignores unknown
extensions; known fields keep their type checks and management commands keep
their strict input contracts.

Immediate and deferred response status is selected from the issuance outcome
before encryption, persisted with the wire body, and restored on replay.
Encrypted initial deferred responses therefore retain HTTP 202. An unsupported
stored status fails closed with a server error. Historical encrypted deferred
records incorrectly stored as HTTP 200 cannot be repaired by inspecting opaque
ciphertext; their existing status is preserved and this fix applies to newly
recorded outcomes.

The presentation verifier classifies completion-store errors as HTTP 503;
invalid presentation/state responses retain HTTP 400. The current verifier
profile requires cryptographic holder binding and rejects DCQL requests that
explicitly waive it. Supporting that waiver requires a dedicated credential
verification profile; ordinary holder-signature verification remains required.

## Evidence and remaining work

Signed proof regressions use actual ES256 signatures and trusted attestation
keys. Encryption regressions encrypt and decrypt real compact JWE, retain
the status through storage/replay helpers, and assert the HTTP presenter uses
the semantic status for both encodings. The live deferred fixture also replays
the initial encrypted response through PostgreSQL. The completion-failure
fixture is a semantic store-port injection, not a PostgreSQL driver fault.
These source tests require designated CNB execution at an exact SHA before
acceptance. No conformance/certification or failover result follows from source
inspection alone.

Deferred readiness/lease classification, stable authorization identity across
refresh, notification retry idempotency, authenticated certificate AKI matching,
individual invalid-presentation filtering and DCQL extensions remain separate
open findings. They are not closed by these wire/proof changes.
