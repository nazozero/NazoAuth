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

async fn credential_access_token(fixture: &LiveEndpointFixture, configuration_id: &str) -> String {
    let offer = fixture.issuer.create_offer(CreateCredentialOfferRequest { subject_id: fixture.subject_id, credential_configuration_ids: vec![configuration_id.to_owned()], grant_types: vec![nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT.to_owned()], tx_code: None, expires_in: 300 }).await.unwrap();
    fixture.issuer.pre_authorized_token(PreAuthorizedTokenRequest { pre_authorized_code: pre_authorized_code(&offer), tx_code: None, client_id: Some(fixture.wallet_client_id.clone()), dpop_jkt: None, mtls_x5t_s256: None }).await.unwrap().access_token
}

#[actix_web::test]
async fn live_http_attestation_holder_limit_precedes_nonce_claim_for_immediate_and_deferred() {
    use actix_web::{App, web, test, http::StatusCode};
    for deferred in [false, true] {
        let configuration_id = format!("attestation-limit-{}", Uuid::now_v7());
        let attester = crate::test_support::client_signing_fixture(jsonwebtoken::Algorithm::ES256);
        let validator = Openid4vcProofValidator::new(json!({"keys": [attester.public_jwk("batch-attester")]})).unwrap();
        let mut configuration = live_configuration(&configuration_id).1;
        let metadata = configuration.proof_types_supported.remove("jwt").unwrap();
        configuration.proof_types_supported.insert("attestation".to_owned(), metadata);
        let Some(fixture) = LiveEndpointFixture::new_with_configuration(&configuration_id, deferred, None, None, Some(configuration), Some(validator)).await else { return; };
        let token = credential_access_token(&fixture, &configuration_id).await;
        let nonce = fixture.issuer.nonce(None).await.unwrap();
        let keys: Vec<Value> = (0..11).map(|_| crate::test_support::client_signing_fixture(jsonwebtoken::Algorithm::ES256).public_jwk("holder")).collect();
        let attest = |keys: &[Value]| {
            let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
            header.typ = Some("key-attestation+jwt".to_owned()); header.kid = Some("batch-attester".to_owned());
            json!(attester.encode_jwt(&header, &json!({"iat": chrono::Utc::now().timestamp(), "nonce": nonce, "attested_keys": keys})))
        };
        let mut request = CredentialRequest { credential_identifier: None, credential_configuration_id: Some(configuration_id.clone()), proofs: None, credential_response_encryption: None, extensions: BTreeMap::new() };
        let operations: Arc<dyn CredentialIssuerOperations> = fixture.issuer.operations.clone();
        let app = test::init_service(App::new().app_data(web::Data::new(nazo_openid4vc_http_actix::CredentialIssuerEndpoint::new(operations, vec![1;32])))
            .route("/openid4vci/credential", web::post().to(nazo_openid4vc_http_actix::credential))
            .route("/openid4vci/deferred_credential", web::post().to(nazo_openid4vc_http_actix::deferred_credential))).await;
        for proofs in [vec![attest(&keys)], vec![attest(&keys[..6]), attest(&keys[6..])]] {
            request.proofs = Some(nazo_openid4vci::Proofs(BTreeMap::from([("attestation".to_owned(), proofs)])));
            let response = test::call_service(&app, test::TestRequest::post().uri("/openid4vci/credential").insert_header(("authorization", format!("Bearer {token}"))).set_json(&request).to_request()).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let body: Value = test::read_body_json(response).await; assert_eq!(body["error"], "invalid_proof");
        }
        // Reusing the same real nonce at the exact bound proves both rejected
        // expansions left its single-use lease untouched.
        request.proofs = Some(nazo_openid4vci::Proofs(BTreeMap::from([("attestation".to_owned(), vec![attest(&keys[..10])])])));
        let response = test::call_service(&app, test::TestRequest::post().uri("/openid4vci/credential").insert_header(("authorization", format!("Bearer {token}"))).set_json(&request).to_request()).await;
        assert_eq!(response.status(), if deferred { StatusCode::ACCEPTED } else { StatusCode::OK });
        let mut body: Value = test::read_body_json(response).await;
        if deferred {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            let response = test::call_service(&app, test::TestRequest::post().uri("/openid4vci/deferred_credential").insert_header(("authorization", format!("Bearer {token}"))).set_json(&DeferredCredentialRequest { transaction_id: body["transaction_id"].as_str().unwrap().to_owned(), credential_response_encryption: None }).to_request()).await;
            assert_eq!(response.status(), StatusCode::OK); body = test::read_body_json(response).await;
        }
        assert_eq!(body["credentials"].as_array().unwrap().len(), 10);
        fixture.cleanup().await;
    }
}

#[actix_web::test]
async fn live_http_no_proof_configuration_issues_without_a_nonce_and_rejects_stray_proofs() {
    use actix_web::{App, web, test, http::StatusCode};
    for deferred in [false, true] {
        let configuration_id = format!("unbound-http-{}", Uuid::now_v7());
        let mut configuration = live_configuration(&configuration_id).1;
        configuration.proof_types_supported.clear(); configuration.cryptographic_binding_methods_supported.clear();
        let Some(fixture) = LiveEndpointFixture::new_with_configuration(&configuration_id, deferred, None, None, Some(configuration), None).await else { return; };
        let token = credential_access_token(&fixture, &configuration_id).await;
        let operations: Arc<dyn CredentialIssuerOperations> = fixture.issuer.operations.clone();
        let app = test::init_service(App::new().app_data(web::Data::new(nazo_openid4vc_http_actix::CredentialIssuerEndpoint::new(operations, vec![1;32])))
            .route("/openid4vci/credential", web::post().to(nazo_openid4vc_http_actix::credential))
            .route("/openid4vci/deferred_credential", web::post().to(nazo_openid4vc_http_actix::deferred_credential))).await;
        let mut request = jwt_credential_request(&configuration_id, &fixture.issuer.issuer, "no-issued-nonce");
        let response = test::call_service(&app, test::TestRequest::post().uri("/openid4vci/credential").insert_header(("authorization", format!("Bearer {token}"))).set_json(&request).to_request()).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST); let error: Value = test::read_body_json(response).await; assert_eq!(error["error"], "invalid_proof");
        request.proofs = None;
        let response = test::call_service(&app, test::TestRequest::post().uri("/openid4vci/credential").insert_header(("authorization", format!("Bearer {token}"))).set_json(&request).to_request()).await;
        assert_eq!(response.status(), if deferred { StatusCode::ACCEPTED } else { StatusCode::OK });
        let mut body: Value = test::read_body_json(response).await;
        if deferred {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            let response = test::call_service(&app, test::TestRequest::post().uri("/openid4vci/deferred_credential").insert_header(("authorization", format!("Bearer {token}"))).set_json(&DeferredCredentialRequest { transaction_id: body["transaction_id"].as_str().unwrap().to_owned(), credential_response_encryption: None }).to_request()).await;
            assert_eq!(response.status(), StatusCode::OK); body = test::read_body_json(response).await;
        }
        assert_eq!(body["credentials"].as_array().unwrap().len(), 1);
        fixture.cleanup().await;
    }
    let configuration_id = format!("bound-http-{}", Uuid::now_v7());
    let Some(fixture) = LiveEndpointFixture::new(&configuration_id, false).await else { return; };
    let token = credential_access_token(&fixture, &configuration_id).await;
    let mut request = jwt_credential_request(&configuration_id, &fixture.issuer.issuer, "no-issued-nonce"); request.proofs = None;
    let error = fixture.issuer.credential(CredentialRequestContext { bearer_token: token, ..request_context() }, CredentialRequestBody::Json(request)).await.unwrap_err();
    assert_eq!(error.status, 400); assert_eq!(error.error, "invalid_proof");
    fixture.cleanup().await;
}
