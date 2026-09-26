use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_auth::{AuthorizationPortError, AuthorizationRequestError};
use serde_json::{Value, json};

fn nested_request_object(claims: &Value) -> (String, ClientRow) {
    let algorithm = nazo_crypto::jwt::Algorithm::EdDSA;
    let key = nazo_crypto::signature::generate_private_key(algorithm).unwrap();
    let signing_key = nazo_crypto::signature::PreparedSigningKey::new(algorithm, &key).unwrap();
    let mut jwk = nazo_crypto::signature::public_jwk(algorithm, &key).unwrap();
    jwk["kid"] = json!("jar-client-key");
    jwk["alg"] = json!("EdDSA");
    jwk["use"] = json!("sig");
    let mut client = crate::test_support::authorization::client(true);
    client.registration.jwks = Some(json!({"keys": [jwk]}));
    client.registration.request_object_signing_alg = Some("EdDSA".into());
    client.registration.request_object_encryption_alg = Some("RSA-OAEP-256".into());
    client.registration.request_object_encryption_enc = Some("A256GCM".into());
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","kid":"jar-client-key"}"#);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
    let signed = format!("{header}.{payload}");
    let signature = URL_SAFE_NO_PAD.encode(signing_key.sign(signed.as_bytes()).unwrap());
    (format!("{signed}.{signature}"), client)
}

fn encrypt_request_object(keys: &nazo_key_management::KeyManager, signed: &str) -> String {
    let jwk = keys.snapshot().request_object_encryption_jwk.clone();
    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "alg": "RSA-OAEP-256", "enc": "A256GCM", "cty": "JWT", "kid": jwk["kid"],
        }))
        .unwrap(),
    );
    let cek = rand::random::<[u8; 32]>();
    let encrypted_key = nazo_crypto::key_wrap::rsa_oaep256_encrypt(
        &URL_SAFE_NO_PAD.decode(jwk["n"].as_str().unwrap()).unwrap(),
        &URL_SAFE_NO_PAD.decode(jwk["e"].as_str().unwrap()).unwrap(),
        &cek,
    )
    .unwrap();
    let iv = rand::random::<[u8; 12]>();
    let encrypted =
        nazo_crypto::aead::encrypt(&cek, &iv, header.as_bytes(), signed.as_bytes()).unwrap();
    let (ciphertext, tag) = encrypted.split_at(encrypted.len() - 16);
    format!(
        "{header}.{}.{}.{}.{}",
        URL_SAFE_NO_PAD.encode(encrypted_key),
        URL_SAFE_NO_PAD.encode(iv),
        URL_SAFE_NO_PAD.encode(ciphertext),
        URL_SAFE_NO_PAD.encode(tag),
    )
}

fn request_claims() -> Value {
    let now = Utc::now().timestamp();
    json!({
        "client_id": "client-1", "iss": "client-1", "aud": "https://issuer.example",
        "exp": now + 120, "nbf": now, "response_type": "code", "scope": "openid",
        "redirect_uri": "https://client.example/callback",
        "code_challenge": "a".repeat(43), "code_challenge_method": "S256",
    })
}

#[test]
fn prepared_encrypted_jar_still_requires_registered_algorithms_signature_and_claims() {
    futures_executor::block_on(async {
        let fixture = crate::test_support::authorization::Fixture::new(Ok(None), Ok(None));
        let application = fixture.make_application();
        let context = application.context();
        for failure in [
            None,
            Some("encryption"),
            Some("signing"),
            Some("signature"),
            Some("audience"),
            Some("expiry"),
        ] {
            let mut claims = request_claims();
            match failure {
                Some("audience") => claims["aud"] = json!("https://other.example"),
                Some("expiry") => claims["exp"] = json!(Utc::now().timestamp() - 1),
                _ => {}
            }
            let (mut signed, mut client) = nested_request_object(&claims);
            match failure {
                Some("encryption") => client.registration.request_object_encryption_alg = None,
                Some("signing") => {
                    client.registration.request_object_signing_alg = Some("PS256".into())
                }
                Some("signature") => {
                    let index = signed.rfind('.').unwrap() + 1;
                    let replacement = if signed.as_bytes()[index] == b'A' {
                        "B"
                    } else {
                        "A"
                    };
                    signed.replace_range(index..index + 1, replacement);
                }
                _ => {}
            }
            let encrypted = encrypt_request_object(&fixture.keys, &signed);
            let mut outer = HashMap::from([("request".into(), encrypted.clone())]);
            let prepared = prepare_par_request_object_client_id(&fixture.keys, &mut outer);
            assert!(prepared.is_some());
            assert_eq!(outer["client_id"], "client-1");
            let result =
                apply_request_object_with_context(&context, &mut outer, &mut client, prepared)
                    .await;
            if let Some(failure) = failure {
                let error = result.expect_err(failure);
                let OAuthEndpointError::Json(fields) = error else {
                    panic!("JSON error expected");
                };
                assert_eq!(fields.error, "invalid_request_object", "{failure}");
                assert_eq!(
                    outer["request"], encrypted,
                    "failure must not expand untrusted claims"
                );
            } else {
                result.unwrap();
                assert_eq!(outer["response_type"], "code");
                assert_eq!(outer["redirect_uri"], "https://client.example/callback");
                assert_eq!(
                    outer["request"], encrypted,
                    "normalization preserves the original envelope; PAR removes it before persistence"
                );
            }
        }
        assert!(fixture.ports.calls().is_empty());
    });
}

#[test]
fn encrypted_jar_without_outer_client_id_survives_par_preparation() {
    use crate::authorization::par::ParRequestFacts;
    use crate::contracts::request_facts::DpopRequestFacts;
    use crate::contracts::token_client_auth::{
        BasicAuthorizationCredentials, TokenClientAuthTransportFacts,
    };
    use crate::token::client_auth::ClientAuthRequestFacts;
    use nazo_runtime_modules::{ActiveModuleSnapshot, ModuleId, ModuleRevision};

    futures_executor::block_on(async {
        let (signed, mut client) = nested_request_object(&request_claims());
        client.registration.client_type = "public".into();
        client.registration.token_endpoint_auth_method = "none".into();
        let fixture = crate::test_support::authorization::Fixture::new(Ok(Some(client)), Ok(None));
        *fixture.ports.par_rate.lock().unwrap() = Some(Ok(1));
        *fixture.ports.par_write.lock().unwrap() = Some(Ok(()));
        fixture
            .snapshots
            .compare_and_publish(
                ModuleRevision::new(1),
                ActiveModuleSnapshot {
                    revision: ModuleRevision::new(2),
                    accepting: [ModuleId::RequestObjects].into(),
                    draining: Default::default(),
                },
            )
            .unwrap();
        let encrypted = encrypt_request_object(&fixture.keys, &signed);
        let application = fixture.make_application();
        let prepared = application
            .begin_par("192.0.2.1")
            .await
            .unwrap()
            .prepare_parameters(HashMap::from([("request".into(), encrypted)]), false, None)
            .unwrap();
        assert_eq!(prepared.client_id(), "client-1");
        let transport = TokenClientAuthTransportFacts::from_parts(
            BasicAuthorizationCredentials::Absent,
            Some(prepared.client_id().into()),
            None,
            None,
            None,
        );
        let response = prepared
            .prepare_client(&transport, false, false)
            .await
            .unwrap()
            .par(
                ParRequestFacts {
                    client_auth: ClientAuthRequestFacts::new("/par", None),
                    dpop: DpopRequestFacts {
                        method: http::Method::POST,
                        path: "/par",
                        proof: Ok(None),
                        proof_present: false,
                    },
                    mtls_thumbprint: None,
                    attestation: None,
                },
                None,
            )
            .await
            .unwrap();
        let stored = fixture.ports.stored_par.lock().unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(response["request_uri"], stored[0].0);
        assert_eq!(stored[0].1.client_id, "client-1");
        assert_eq!(stored[0].1.params["response_type"], "code");
        assert!(!stored[0].1.params.contains_key("request"));
    });
}

fn assert_error(error: OAuthEndpointError, status: StatusCode, code: &str, description: &str) {
    let OAuthEndpointError::Json(fields) = error else {
        panic!("JSON error expected")
    };
    assert_eq!(fields.status, status);
    assert_eq!(fields.error, code);
    assert_eq!(fields.description, description);
}
#[test]
fn verification_errors_preserve_existing_oauth_contract() {
    for (error, description) in [
        (
            RequestObjectVerificationError::InvalidCompact,
            "request object 无效.",
        ),
        (
            RequestObjectVerificationError::InvalidHeader,
            "request object header 无效.",
        ),
        (
            RequestObjectVerificationError::InvalidClaims,
            "request object claims 无效.",
        ),
        (
            RequestObjectVerificationError::InvalidAlgorithm,
            "request object 签名算法无效.",
        ),
        (
            RequestObjectVerificationError::MissingKeyId,
            "request object 缺少 kid.",
        ),
        (
            RequestObjectVerificationError::InvalidKey,
            "request object 签名密钥无效.",
        ),
        (
            RequestObjectVerificationError::InvalidSignature,
            "request object 验签失败.",
        ),
    ] {
        assert_error(
            request_object_verification_error(error),
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            description,
        );
    }
}

#[test]
fn policy_and_replay_errors_preserve_status_code_and_body() {
    for (error, status, code, description) in [
        (
            AuthorizationRequestError::OuterClientIdConflict,
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "request object 与外层 client_id 冲突.",
        ),
        (
            AuthorizationRequestError::InvalidRequestObjectReplay,
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            "request object jti 已使用.",
        ),
        (
            AuthorizationRequestError::Dependency(AuthorizationPortError::Unavailable),
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "request object 防重放状态不可用.",
        ),
    ] {
        assert_error(
            request_object_policy_error(error),
            status,
            code,
            description,
        );
    }
}
