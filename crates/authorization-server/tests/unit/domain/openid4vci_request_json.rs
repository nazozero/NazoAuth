use super::{CredentialRequestBody, EphemeralEncryptionKey, request_json};
use nazo_digital_credentials::encrypt_ecdh_es;
use serde_json::{Value, json};

#[test]
fn request_json_accepts_json_and_rejects_invalid_encrypted_request() {
    let encryption = EphemeralEncryptionKey::derive(&[0x51; 32], b"credential-request-encryption")
        .expect("fixture encryption key should derive");
    let request = json!({"credential_configuration_id": "unit"});
    assert_eq!(
        request_json(&encryption, CredentialRequestBody::Json(request.clone()))
            .expect("JSON request should pass through"),
        request
    );

    let error = request_json::<Value>(
        &encryption,
        CredentialRequestBody::Jwt("not-a-jwe".to_owned()),
    )
    .expect_err("malformed encrypted request must fail closed");
    assert_eq!(error.status, 400);
    assert_eq!(error.error, "invalid_encryption_parameters");

    let mut jwk = encryption.public_jwk();
    jwk["alg"] = json!("ECDH-ES");
    jwk["kid"] = json!("openid4vci-request-encryption");
    let malformed = encrypt_ecdh_es(b"not-json", &jwk, Some("application/json"))
        .expect("fixture request JWE should encrypt");
    let error = request_json::<Value>(&encryption, CredentialRequestBody::Jwt(malformed))
        .expect_err("encrypted non-JSON request must fail closed");
    assert_eq!(error.status, 400);
    assert_eq!(error.error, "invalid_credential_request");
    assert_eq!(
        error.description,
        "Encrypted credential request is malformed."
    );
}
