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
    let wallet = nazo_digital_credentials::EphemeralEncryptionKey::derive(
        &[0x67; 32],
        b"live-wallet-response",
    )
    .unwrap();
    let mut jwk = wallet.public_jwk();
    jwk["alg"] = json!("ECDH-ES");
    let mut request = jwt_credential_request("unit-live-deferred", &fixture.issuer.issuer, &nonce);
    request.credential_response_encryption = Some(nazo_openid4vci::CredentialResponseEncryption {
        jwk,
        enc: "A256GCM".to_owned(),
        zip: Some("DEF".to_owned()),
    });
    let mut context = request_context();
    context.bearer_token = access.access_token;
    let plain_error=fixture.issuer.credential(context.clone(),CredentialRequestBody::Json(request.clone()))
        .await.expect_err("response encryption is only accepted in encrypted requests");
    assert_eq!((plain_error.status,plain_error.error),(400,"invalid_encryption_parameters"));
    let metadata=fixture.issuer.metadata().await.unwrap();
    let issuer_request_jwk=&metadata.credential_request_encryption.as_ref().unwrap().jwks.as_ref().unwrap()["keys"][0];
    let encrypted_request=nazo_digital_credentials::encrypt_ecdh_es(&serde_json::to_vec(&request).unwrap(),issuer_request_jwk,Some("application/json")).unwrap();
    let pending = fixture
        .issuer
        .credential(context.clone(), CredentialRequestBody::Jwt(encrypted_request.clone()))
        .await
        .expect("live deferred credential should return a transaction");
    assert_eq!(pending.status, nazo_openid4vci::application::CredentialResponseStatus::Deferred);
    let replay = fixture.issuer.credential(context.clone(), CredentialRequestBody::Jwt(encrypted_request))
        .await.expect("initial encrypted response is replayed from durable storage");
    assert_eq!(replay, pending);
    let CredentialResponseBody::Jwt(encoded) = pending.body else {
        panic!("expected encrypted deferred response");
    };
    let decoded: CredentialResponse =
        serde_json::from_slice(&wallet.decrypt(&encoded).unwrap()).unwrap();
    assert!(decoded.credentials.is_none());
    let transaction_id = decoded
        .transaction_id
        .expect("encrypted response retains transaction id");

    let transaction_hash = nazo_oauth_server::crypto::blake3_hex(&transaction_id);
    let mut connection = nazo_postgres::get_conn(&fixture.pool).await.unwrap();
    assert_eq!(sql_query("UPDATE openid4vci_deferred_transactions SET ready_at=clock_timestamp()+interval '60 seconds' WHERE transaction_hash=$1 AND token_id IN (SELECT token_id FROM openid4vci_access_grants WHERE subject_id=$2)")
        .bind::<Text, _>(&transaction_hash).bind::<SqlUuid, _>(fixture.subject_id)
        .execute(&mut connection).await.unwrap(), 1);
    drop(connection);
    let deferred_request = DeferredCredentialRequest {
        transaction_id,
        credential_response_encryption: None,
    };
    let deferred_context = CredentialRequestContext {
        request_url: "/openid4vci/deferred_credential".to_owned(),
        ..context
    };
    let mut waiting_request = deferred_request.clone();
    waiting_request.credential_response_encryption = request.credential_response_encryption.clone();
    let waiting_jwe = nazo_digital_credentials::encrypt_ecdh_es(
        &serde_json::to_vec(&waiting_request).unwrap(), issuer_request_jwk, Some("application/json"),
    ).unwrap();
    let waiting = fixture.issuer.deferred(
        deferred_context.clone(), CredentialRequestBody::Jwt(waiting_jwe),
    ).await.expect("a valid unready transaction remains pending");
    assert_eq!(waiting.status, nazo_openid4vci::application::CredentialResponseStatus::Deferred);
    let CredentialResponseBody::Jwt(waiting_body) = waiting.body else {
        panic!("this poll selects encrypted response parameters");
    };
    let waiting_body: CredentialResponse = serde_json::from_slice(&wallet.decrypt(&waiting_body).unwrap()).unwrap();
    assert_eq!(waiting_body.transaction_id.as_deref(), Some(deferred_request.transaction_id.as_str()));
    assert!(waiting_body.credentials.is_none() && waiting_body.interval.is_some_and(|interval| interval > 0));

    // A task-owned existing lease exercises Busy without running a second signer.
    let blocker = Uuid::now_v7().to_string();
    let mut connection = nazo_postgres::get_conn(&fixture.pool).await.unwrap();
    assert_eq!(sql_query("UPDATE openid4vci_deferred_transactions SET ready_at=clock_timestamp(), claim_id=$3, claim_expires_at=clock_timestamp()+interval '60 seconds' WHERE transaction_hash=$1 AND token_id IN (SELECT token_id FROM openid4vci_access_grants WHERE subject_id=$2)")
        .bind::<Text, _>(&transaction_hash).bind::<SqlUuid, _>(fixture.subject_id).bind::<Text, _>(&blocker)
        .execute(&mut connection).await.unwrap(), 1);
    drop(connection);
    let busy = fixture.issuer.deferred(
        deferred_context.clone(), CredentialRequestBody::Json(deferred_request.clone()),
    ).await.expect("a valid leased transaction remains pending");
    assert_eq!(busy.status, nazo_openid4vci::application::CredentialResponseStatus::Deferred);
    let CredentialResponseBody::Json(busy_body) = busy.body else { panic!("this poll requests JSON"); };
    assert_eq!(busy_body.transaction_id.as_deref(), Some(deferred_request.transaction_id.as_str()));
    assert!(busy_body.credentials.is_none() && busy_body.interval.is_some_and(|interval| interval > 0));
    let mut connection = nazo_postgres::get_conn(&fixture.pool).await.unwrap();
    assert_eq!(sql_query("UPDATE openid4vci_deferred_transactions SET claim_id=NULL, claim_expires_at=NULL WHERE transaction_hash=$1 AND claim_id=$3 AND token_id IN (SELECT token_id FROM openid4vci_access_grants WHERE subject_id=$2)")
        .bind::<Text, _>(&transaction_hash).bind::<SqlUuid, _>(fixture.subject_id).bind::<Text, _>(&blocker)
        .execute(&mut connection).await.unwrap(), 1);
    drop(connection);
    // This exact JSON poll previously returned Busy/202. It must now issue,
    // proving waiting results were not cached as the final response.
    let response = fixture
        .issuer
        .deferred(
            deferred_context.clone(),
            CredentialRequestBody::Json(deferred_request.clone()),
        )
        .await
        .expect("live deferred credential should be released");
    assert_eq!(
        response.status,
        nazo_openid4vci::application::CredentialResponseStatus::Issued
    );
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

    let notification_context = CredentialRequestContext {
        request_url: "/openid4vci/notification".to_owned(),
        ..deferred_context
    };
    let notification = NotificationRequest {
        notification_id,
        event: nazo_openid4vci::NotificationEvent::CredentialAccepted,
        event_description: Some("live deferred completed".to_owned()),
    };
    for _ in 0..2 {
        fixture
            .issuer
            .notify(notification_context.clone(), notification.clone())
            .await
            .expect("identical live notification retries retain success");
    }
    let conflicting = NotificationRequest {
        event: nazo_openid4vci::NotificationEvent::CredentialDeleted,
        ..notification
    };
    let error = fixture.issuer.notify(notification_context, conflicting).await.unwrap_err();
    assert_eq!((error.status, error.error), (400, "invalid_notification_id"));
    fixture.cleanup().await;
}
