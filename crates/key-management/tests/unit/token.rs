use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_auth::{IntrospectionSignInput, TokenSignerPort};
use serde_json::json;

use crate::KeyManager;

#[tokio::test]
async fn introspection_response_uses_registered_algorithm() {
    let manager = KeyManager::for_test_with_auxiliary(jsonwebtoken::Algorithm::PS256);
    let token = manager
        .sign_introspection_response(IntrospectionSignInput {
            issuer: "https://issuer.example",
            audience: "client",
            body: &json!({"active": true}),
            signing_algorithm: Some("PS256"),
        })
        .await
        .expect("PS256 introspection response");
    let header = jsonwebtoken::decode_header(&token).expect("JWT header");

    assert_eq!(header.alg, jsonwebtoken::Algorithm::PS256);
    assert_eq!(header.typ.as_deref(), Some("token-introspection+jwt"));
}

#[tokio::test]
async fn decode_rejects_a_header_algorithm_outside_the_keys_prepared_algorithm() {
    let manager = KeyManager::for_test(jsonwebtoken::Algorithm::EdDSA);
    let kid = manager.snapshot().active_kid.clone();
    // The token names the EdDSA key but declares RS256: it must be rejected
    // before signature verification under a mismatched algorithm.
    let header = json!({"alg":"RS256","typ":"at+jwt","kid":kid});
    let token = format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&json!({"iss":"https://issuer.example"})).unwrap()),
        URL_SAFE_NO_PAD.encode([0_u8; 8]),
    );
    assert!(
        manager
            .decode_access_token("https://issuer.example", &token)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        manager
            .decode_id_token("https://issuer.example", &token)
            .await
            .unwrap()
            .is_none()
    );
}
