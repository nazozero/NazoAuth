use super::*;

#[test]
fn federation_entity_statement_claims_are_self_issued_and_short_lived() {
    let claims = federation_entity_statement_claims(
        "https://issuer.example",
        json!({"keys": []}),
        1_000,
        86_400,
    );

    assert_eq!(claims.iss, "https://issuer.example");
    assert_eq!(claims.sub, "https://issuer.example");
    assert_eq!(claims.iat, 1_000);
    assert_eq!(claims.exp, 87_400);
    assert_eq!(
        claims.metadata["openid_provider"]["authorization_endpoint"],
        "https://issuer.example/authorize"
    );
    assert_eq!(claims.jwks, json!({"keys": []}));
}
