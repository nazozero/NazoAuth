# M7 Encrypted Response OIDF Coverage Check

Date: 2026-07-11

## Scope

M7 adds per-client response protection for two existing protocol surfaces:

- OIDC UserInfo responses can remain JSON, be signed as JWS, be encrypted as
  compact JWE, or be signed and then encrypted as a nested JWT.
- JARM authorization responses can use a per-client signing algorithm and can
  be signed and then encrypted as a nested compact JWE.

The implemented JWE policy is deliberately narrow:
`alg=RSA-OAEP-256`, `enc=A256GCM`, a public RSA JWK with `use=enc`, and a
non-empty `kid`. Unsupported, incomplete, or unusable metadata is rejected at
registration or fails closed with no JSON/plain authorization-response
fallback.

RFC 7517 does not require `kid` on a JWK. Dynamic registration therefore
accepts the OIDF suite's bounded single-key form only when the JWKS contains
exactly one signing key and that key is otherwise valid. A `private_key_jwt`
assertion without `kid` can select only that sole kidless, algorithm-matching
key. Multiple signing keys, any ambiguous selection, and every encryption key
without `kid` remain rejected.

## OIDF Suite Mapping

The OpenID Foundation conformance-suite source was checked on 2026-07-11 at
snapshot `f326f6aa25d6a2b8f1ae30a6ec80a57e342333ce`.

`OIDCCDynamicTestPlan` includes `OIDCCUserInfoRS256` (`oidcc-userinfo-rs256`).
The repository full matrix therefore adds:

```text
oidcc-dynamic-certification-test-plan[response_type=code] oidf-oidcc-dynamic-crypto-plan-config.json
```

This plan exercises dynamic registration of
`userinfo_signed_response_alg=RS256`, the signed UserInfo content type, and
signed UserInfo claims. The generated configuration uses a distinct alias so
it can run concurrently with the existing OIDC dynamic-registration plan.

No OP/authorization-server plan or module was found that requests encrypted
UserInfo responses or encrypted JARM responses from the implementation under
test. The suite contains encryption helpers for tests where the suite acts as
an authorization server or client, but those are not evidence for this
project's OP response-encryption implementation. Existing FAPI2 Message
Signing JARM plans continue to cover signed JARM only.

## Local Coverage Required for the OIDF Gap

- UserInfo JSON compatibility, JWS, encryption-only JWE, nested JWS/JWE,
  claim minimization, wrong-key decryption, and fail-closed key failures.
- JARM nested JWS/JWE decryption, wrong-key rejection, and proof that signing
  or encryption failures never expose a code, state, or plain query fallback.
- DCR/admin metadata persistence and rejection of `none`, symmetric signing,
  incomplete JWE pairs, unsupported algorithms, missing keys, private key
  material, and encryption keys without `kid`.
- Discovery assertions for exactly the implemented signing and encryption
  algorithm families.

The official full matrix remains a regression gate, but the local negative
tests above are the authoritative coverage for encrypted UserInfo and encrypted
JARM until the OIDF suite adds corresponding OP plans.
