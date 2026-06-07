# Resource Server Verifier

Resource servers must not reuse authorization-server internals that deliberately skip audience validation for `/userinfo` or `/introspect`. The public verifier API in `src/resource_server.rs` is the stable core for Rust resource servers and future Actix Web, Axum/Tower, and tonic adapters.

## Validation Contract

The verifier requires:

- JWT header `typ=at+jwt`.
- Allowed signing algorithm: `EdDSA`, `RS256`, `ES256`, or `PS256` by default.
- `kid` lookup against the configured JWKS.
- JWK `use=sig`, matching `alg`, no private key material, and expected key shape.
- `token_use=access`.
- Exact issuer match.
- At least one configured audience in the JWT `aud` string or array.
- `exp` and optional `nbf` validation with bounded clock skew.
- Required scope checks.
- Optional sender-constraint policy for DPoP `cnf.jkt`, mTLS `cnf.x5t#S256`, or either sender constraint.

The verifier returns structured errors such as `AudienceMismatch`, `MissingScope`, `WrongTokenType`, `DpopBindingMismatch`, and `MtlsBindingMismatch`. Application adapters should map these to RFC 6750 `WWW-Authenticate` responses without leaking token contents.

## Core Usage

```rust
use nazo_oauth_server::resource_server::{
    ConfirmationPolicy, ResourceServerVerifier, ResourceServerVerifierConfig,
};
use serde_json::Value;

fn build_verifier(jwks: Value) -> ResourceServerVerifier {
    let mut config = ResourceServerVerifierConfig::new(
        "https://issuer.example",
        "https://api.example",
        jwks,
    );
    config.required_scopes = vec!["orders:read".to_owned()];
    config.confirmation = ConfirmationPolicy::RequireAnySenderConstraint;
    ResourceServerVerifier::new(config).expect("resource-server verifier config must be valid")
}

fn authorize(verifier: &ResourceServerVerifier, access_token: &str) {
    let claims = verifier.verify(access_token).expect("token must be valid");
    assert!(claims.scopes.iter().any(|scope| scope == "orders:read"));
}
```

## DPoP Boundary

`ConfirmationPolicy::RequireDpopJkt(expected_jkt)` verifies the token binding material in the JWT access token. A full DPoP-protected resource request must also validate the DPoP proof JWT for:

- `typ=dpop+jwt`
- proof signature against the embedded JWK
- proof `jti` replay cache
- `htu` and `htm`
- `ath` matching the presented access token
- nonce policy when configured

The verifier intentionally keeps these two checks separate so framework adapters can bind proof validation to the actual HTTP method, URI, headers, and replay store.

## mTLS Boundary

`ConfirmationPolicy::RequireMtlsThumbprint(expected_x5t_s256)` verifies the token binding material in the JWT access token. A full mTLS-protected resource request must also compare it with a verified client certificate thumbprint from the local TLS listener or from the trusted proxy boundary described in `docs/deployment.md`.

Forwarded certificate metadata must only be accepted from trusted proxy CIDRs and after duplicate or conflicting forwarded certificate headers have been rejected.

## Introspection Fallback

JWT validation is the local fast path. Resource servers may fall back to token introspection when:

- the `kid` is unknown and JWKS refresh still cannot find it,
- local revocation freshness requirements are stricter than the JWT lifetime,
- an opaque token profile is introduced by a future deployment,
- or policy extensions require authorization-server-side state.

Fallback must not override a local protocol invariant failure such as wrong issuer, wrong audience, wrong `typ`, unsupported algorithm, or sender-constraint mismatch.

## Framework Adapter Requirements

Future Actix Web, Axum/Tower, and tonic adapters must all call the same core verifier and preserve these invariants:

- Reject query-string access tokens.
- Reject requests that present multiple token transport methods.
- Map missing or invalid tokens to `401` with `WWW-Authenticate`.
- Map malformed requests to `400`.
- Run DPoP proof validation before accepting DPoP-bound tokens.
- Run mTLS certificate binding before accepting mTLS-bound tokens.
- Expose extension points only after issuer, audience, expiry, scope, and sender-constraint checks succeed.
