use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_auth::{DpopStateFuture, DpopStateStoreError, DpopStateStorePort};

struct UnavailableDpopState;

impl DpopStateStorePort for UnavailableDpopState {
    fn consume_replay<'a>(&'a self, _: &'a str, _: &'a str, _: u64) -> DpopStateFuture<'a, bool> {
        Box::pin(async { Err(DpopStateStoreError) })
    }

    fn issue_nonce<'a>(&'a self, _: &'a str, _: u64) -> DpopStateFuture<'a, ()> {
        Box::pin(async { Err(DpopStateStoreError) })
    }

    fn validate_nonce<'a>(&'a self, _: &'a str) -> DpopStateFuture<'a, bool> {
        Box::pin(async { Err(DpopStateStoreError) })
    }
}

#[test]
fn dpop_nonce_generation_fails_closed_when_nonce_state_is_unavailable() {
    futures_executor::block_on(async {
        let access = CredentialAccess {
            token_id: Uuid::now_v7(),
            tenant_id: Uuid::now_v7(),
            subject_id: Uuid::now_v7(),
            client_id: "unit-client".to_owned(),
            configuration_ids: vec!["unit-config".to_owned()],
            credential_identifiers: Vec::new(),
            dpop_jkt: Some("unit-dpop-thumbprint".to_owned()),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
        };
        let error = next_dpop_nonce(&UnavailableDpopState, &access)
            .await
            .expect_err("unavailable DPoP nonce state must fail closed");
        assert_error(
            error,
            503,
            "server_error",
            "DPoP nonce issuance is unavailable.",
        );
    });
}

fn assert_error(error: CredentialHttpError, status: u16, code: &str, description: &str) {
    assert_eq!(error.status, status);
    assert_eq!(error.error, code);
    assert_eq!(error.description, description);
}
#[test]
fn finish_response_supports_json_ecdh_and_deflate_and_rejects_unsupported_parameters() {
    let request_encryption =
        EphemeralEncryptionKey::derive(&[0x51; 32], b"credential-request-encryption")
            .expect("fixture encryption key");
    let response = CredentialResponse {
        credentials: Some(vec![nazo_openid4vci::IssuedCredential {
            credential: json!("unit-credential"),
        }]),
        transaction_id: None,
        notification_id: None,
        interval: None,
    };

    assert!(matches!(
        finish_response(response.clone(), None).expect("unencrypted response should be JSON"),
        CredentialResponseBody::Json(_)
    ));

    let mut jwk = request_encryption.public_jwk();
    jwk["alg"] = json!("ECDH-ES");
    jwk["kid"] = json!("openid4vci-request-encryption");
    for zip in [None, Some("DEF".to_owned())] {
        let encrypted = finish_response(
            response.clone(),
            Some(&CredentialResponseEncryption {
                jwk: jwk.clone(),
                enc: "A256GCM".to_owned(),
                zip: zip.clone(),
            }),
        )
        .expect("supported ECDH response encryption should succeed");
        let compact = match encrypted {
            CredentialResponseBody::Jwt(value) => value,
            CredentialResponseBody::Json(_) => {
                panic!("encrypted response must use compact JWE")
            }
        };
        let parts = compact.split('.').collect::<Vec<_>>();
        assert_eq!(parts.len(), 5);
        assert!(parts[1].is_empty(), "ECDH-ES uses direct key agreement");
        let protected: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(parts[0])
                .expect("protected header should be base64url"),
        )
        .expect("protected header should be JSON");
        assert_eq!(protected["alg"], "ECDH-ES");
        assert_eq!(protected["enc"], "A256GCM");
        assert_eq!(protected["kid"], "openid4vci-request-encryption");
        assert_eq!(protected["cty"], "application/json");
        assert_eq!(protected.get("zip").and_then(Value::as_str), zip.as_deref());

        let plaintext = request_encryption
            .decrypt_credential_request(&compact, "openid4vci-request-encryption")
            .expect("recipient private key should decrypt the response");
        assert_eq!(
            plaintext,
            serde_json::to_vec(&response).expect("credential response should serialize")
        );

        // The protected header is authenticated as the JWE AAD.  Changing it
        // while retaining ciphertext must therefore invalidate decryption.
        let mut changed_protected = protected;
        changed_protected["aad-test"] = json!("tampered");
        let changed_header = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&changed_protected).expect("header should serialize"));
        let tampered = format!(
            "{changed_header}.{}.{}.{}.{}",
            parts[1], parts[2], parts[3], parts[4]
        );
        assert!(
            request_encryption
                .decrypt_credential_request(&tampered, "openid4vci-request-encryption")
                .is_err()
        );
    }

    for (jwk, enc, zip) in [
        (json!({"alg":"RSA-OAEP"}), "A256GCM", None),
        (json!({"alg":"ECDH-ES"}), "A128GCM", None),
        (json!({"alg":"ECDH-ES"}), "A256GCM", Some("GZIP".to_owned())),
    ] {
        let error = finish_response(
            response.clone(),
            Some(&CredentialResponseEncryption {
                jwk,
                enc: enc.to_owned(),
                zip,
            }),
        )
        .expect_err("unsupported response encryption must fail closed");
        assert_eq!(error.status, 400);
        assert_eq!(error.error, "invalid_encryption_parameters");
    }

    let error = finish_response(
        response,
        Some(&CredentialResponseEncryption {
            jwk: json!({"alg":"ECDH-ES"}),
            enc: "A256GCM".to_owned(),
            zip: None,
        }),
    )
    .expect_err("an incomplete ECDH key must fail during encryption");
    assert_error(
        error,
        400,
        "invalid_encryption_parameters",
        "Credential response encryption key is invalid.",
    );
}
