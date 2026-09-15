use serde_json::json;

use super::*;

#[test]
fn jwks_never_publishes_private_members() {
    let algorithm = nazo_crypto::jwt::Algorithm::EdDSA;
    let private = nazo_crypto::signature::generate_private_key(algorithm).unwrap();
    let mut public_jwk = nazo_crypto::signature::public_jwk(algorithm, &private).unwrap();
    let prepared = crate::model::PreparedVerification {
        algorithm,
        key: nazo_crypto::jwt::VerificationKey::from_ed_components(
            public_jwk["x"].as_str().unwrap(),
        )
        .unwrap(),
    };
    public_jwk["d"] = json!("private");
    public_jwk["kid"] = json!("public-only");
    public_jwk["alg"] = json!("EdDSA");
    public_jwk["use"] = json!("sig");
    let jwks = public_jwks(
        &[VerificationKey {
            kid: "public-only".to_owned(),
            public_jwk,
            prepared,
            signing_purposes: Default::default(),
            retire_at: None,
        }],
        &json!({
            "kty": "RSA", "use": "enc", "alg": "RSA-OAEP-256",
            "kid": "request-object", "n": "public", "e": "AQAB"
        }),
    );
    assert!(jwks["keys"][0].get("d").is_none());
    assert_eq!(jwks["keys"][1]["use"], "enc");
}
