use super::*;

#[tokio::test]
async fn deferred_decrypts_a_valid_encrypted_request_before_access_validation() {
    let issuer = operations(true).await;
    let request = DeferredCredentialRequest {
        transaction_id: "unit-transaction".to_owned(),
        credential_response_encryption: None,
    };
    let mut jwk = issuer.request_encryption.public_jwk();
    jwk["alg"] = json!("ECDH-ES");
    jwk["kid"] = json!("openid4vci-request-encryption");
    let encrypted = encrypt_ecdh_es(
        &serde_json::to_vec(&request).expect("deferred request should serialize"),
        &jwk,
        Some("application/json"),
    )
    .expect("deferred request should encrypt");
    let error = issuer
        .deferred(request_context(), CredentialRequestBody::Jwt(encrypted))
        .await
        .expect_err("valid encrypted request should then reach access validation");
    assert_error(error, 401, "invalid_token", "Access token is invalid.");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_deferred_credential_claim_response_replay_and_notification() {
    let Some(fixture) = LiveEndpointFixture::new("unit-live-deferred", true).await else {
        return;
    };
    let offer = fixture
        .issuer
        .create_offer(CreateCredentialOfferRequest {
            subject_id: fixture.subject_id,
            credential_configuration_ids: vec!["unit-live-deferred".to_owned()],
            grant_types: vec![nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT.to_owned()],
            tx_code: None,
            expires_in: 300,
        })
        .await
        .expect("live deferred offer should persist");
    let access = fixture
        .issuer
        .pre_authorized_token(PreAuthorizedTokenRequest {
            pre_authorized_code: pre_authorized_code(&offer),
            tx_code: None,
            client_id: Some(fixture.wallet_client_id.clone()),
            dpop_jkt: None,
            mtls_x5t_s256: None,
        })
        .await
        .expect("live deferred pre-authorized token should be issued");
    let nonce = fixture
        .issuer
        .nonce(None)
        .await
        .expect("live deferred credential nonce should be issued");
    let request = jwt_credential_request("unit-live-deferred", &fixture.issuer.issuer, &nonce);
    let mut context = request_context();
    context.bearer_token = access.access_token;
    let pending = fixture
        .issuer
        .credential(context.clone(), CredentialRequestBody::Json(request))
        .await
        .expect("live deferred credential should return a transaction");
    let transaction_id = match pending.body {
        CredentialResponseBody::Json(CredentialResponse {
            transaction_id: Some(transaction_id),
            credentials: None,
            ..
        }) => transaction_id,
        _ => panic!("live deferred response should contain a transaction id"),
    };

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let deferred_request = DeferredCredentialRequest {
        transaction_id,
        credential_response_encryption: None,
    };
    let deferred_context = CredentialRequestContext {
        request_url: "/openid4vci/deferred_credential".to_owned(),
        ..context
    };
    let response = fixture
        .issuer
        .deferred(
            deferred_context.clone(),
            CredentialRequestBody::Json(deferred_request.clone()),
        )
        .await
        .expect("live deferred credential should be released");
    let notification_id = match &response.body {
        CredentialResponseBody::Json(body) => body
            .notification_id
            .clone()
            .expect("deferred response notification id"),
        CredentialResponseBody::Jwt(_) => panic!("live fixture requests JSON response"),
    };
    assert!(matches!(
        &response.body,
        CredentialResponseBody::Json(CredentialResponse {
            credentials: Some(_),
            transaction_id: None,
            ..
        })
    ));

    let replay = fixture
        .issuer
        .deferred(
            deferred_context.clone(),
            CredentialRequestBody::Json(deferred_request),
        )
        .await
        .expect("identical deferred request should replay");
    assert_eq!(replay.body, response.body);
    assert_eq!(replay.dpop_nonce, response.dpop_nonce);

    fixture
        .issuer
        .notify(
            CredentialRequestContext {
                request_url: "/openid4vci/notification".to_owned(),
                ..deferred_context
            },
            NotificationRequest {
                notification_id,
                event: nazo_openid4vci::NotificationEvent::CredentialAccepted,
                event_description: Some("live deferred completed".to_owned()),
            },
        )
        .await
        .expect("live deferred notification should be recorded");
    fixture.cleanup().await;
}
