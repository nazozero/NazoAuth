use super::*;

#[tokio::test]
async fn credential_decrypts_a_valid_encrypted_request_before_access_validation() {
    let issuer = operations(true).await;
    let request = credential_request();
    let mut jwk = issuer.request_encryption.public_jwk();
    jwk["alg"] = json!("ECDH-ES");
    jwk["kid"] = json!("openid4vci-request-encryption");
    let encrypted = encrypt_ecdh_es(
        &serde_json::to_vec(&request).expect("credential request should serialize"),
        &jwk,
        Some("application/json"),
    )
    .expect("credential request should encrypt");
    let error = issuer
        .credential(request_context(), CredentialRequestBody::Jwt(encrypted))
        .await
        .expect_err("valid encrypted request should then reach access validation");
    assert_error(error, 401, "invalid_token", "Access token is invalid.");
}
