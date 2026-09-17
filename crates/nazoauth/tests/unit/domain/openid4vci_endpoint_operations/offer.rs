use super::*;

#[tokio::test]
async fn enabled_metadata_is_signed_and_advertises_request_and_response_encryption() {
    let issuer = operations(true).await;
    let metadata = issuer
        .metadata()
        .await
        .expect("enabled issuer metadata should be available");
    assert_eq!(metadata.credential_issuer, issuer.issuer);
    assert_eq!(metadata.authorization_servers, vec![issuer.issuer.clone()]);
    assert_eq!(
        metadata.credential_endpoint,
        "https://issuer.example/openid4vci/credential"
    );
    assert_eq!(
        metadata.deferred_credential_endpoint.as_deref(),
        Some("https://issuer.example/openid4vci/deferred_credential")
    );
    assert_eq!(
        metadata.notification_endpoint.as_deref(),
        Some("https://issuer.example/openid4vci/notification")
    );
    assert!(
        !metadata
            .credential_request_encryption
            .as_ref()
            .expect("request encryption metadata")
            .encryption_required
    );
    assert_eq!(
        metadata
            .credential_response_encryption
            .as_ref()
            .expect("response encryption metadata")
            .alg_values_supported,
        vec!["ECDH-ES".to_owned()]
    );
    assert_eq!(
        metadata
            .credential_response_encryption
            .as_ref()
            .expect("response encryption metadata")
            .zip_values_supported,
        vec!["DEF".to_owned()]
    );
    assert_eq!(
        metadata
            .batch_credential_issuance
            .as_ref()
            .expect("batch metadata")
            .batch_size,
        10
    );
    assert!(metadata.signed_metadata.is_some());
}

#[tokio::test]
async fn disabled_issuer_rejects_every_mutating_endpoint_before_state_access() {
    let issuer = operations(false).await;
    assert_error(
        issuer.metadata().await.expect_err("metadata disabled"),
        404,
        "invalid_request",
        "Credential issuer is disabled.",
    );
    assert_error(
        issuer
            .offer("not-a-uuid")
            .await
            .expect_err("offer disabled"),
        404,
        "invalid_request",
        "Credential issuer is disabled.",
    );
    assert_error(
        issuer.nonce(None).await.expect_err("nonce disabled"),
        404,
        "invalid_request",
        "Credential issuer is disabled.",
    );
    assert_error(
        issuer
            .credential(
                request_context(),
                CredentialRequestBody::Json(credential_request()),
            )
            .await
            .expect_err("credential disabled"),
        503,
        "temporarily_unavailable",
        "Credential issuer is not accepting new requests.",
    );
    assert_error(
        issuer
            .deferred(
                request_context(),
                CredentialRequestBody::Json(DeferredCredentialRequest {
                    transaction_id: "unit-transaction".to_owned(),
                    credential_response_encryption: None,
                }),
            )
            .await
            .expect_err("deferred disabled"),
        503,
        "temporarily_unavailable",
        "Credential issuer is unavailable.",
    );
    assert_error(
        issuer
            .notify(
                request_context(),
                NotificationRequest {
                    notification_id: "unit-notification".to_owned(),
                    event: nazo_openid4vci::NotificationEvent::CredentialFailure,
                    event_description: None,
                },
            )
            .await
            .expect_err("notification disabled"),
        503,
        "temporarily_unavailable",
        "Credential issuer is unavailable.",
    );
    assert_error(
        issuer
            .pre_authorized_token(PreAuthorizedTokenRequest {
                pre_authorized_code: "unit-code".to_owned(),
                tx_code: None,
                client_id: None,
                dpop_jkt: None,
                mtls_x5t_s256: None,
            })
            .await
            .expect_err("pre-authorized token disabled"),
        503,
        "temporarily_unavailable",
        "Credential issuer is unavailable.",
    );
    assert_error(
        issuer
            .create_offer(CreateCredentialOfferRequest {
                subject_id: Uuid::nil(),
                credential_configuration_ids: vec!["unit-config".to_owned()],
                grant_types: vec![nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT.to_owned()],
                tx_code: None,
                expires_in: 300,
            })
            .await
            .expect_err("offer creation disabled"),
        503,
        "temporarily_unavailable",
        "Credential issuer is unavailable.",
    );
}

#[tokio::test]
async fn enabled_issuer_validates_request_shape_before_database_state() {
    let issuer = operations(true).await;
    assert_eq!(
        issuer
            .offer("not-a-uuid")
            .await
            .expect_err("malformed offer identifier")
            .status,
        404
    );
    assert_eq!(
        issuer
            .credential(
                request_context(),
                CredentialRequestBody::Jwt("not-a-jwe".to_owned()),
            )
            .await
            .expect_err("malformed credential JWE")
            .status,
        400
    );
    assert_eq!(
        issuer
            .deferred(
                request_context(),
                CredentialRequestBody::Jwt("not-a-jwe".to_owned()),
            )
            .await
            .expect_err("malformed deferred JWE")
            .status,
        400
    );
    assert_eq!(
        issuer
            .create_offer(CreateCredentialOfferRequest {
                subject_id: Uuid::nil(),
                credential_configuration_ids: vec!["unknown".to_owned()],
                grant_types: vec!["authorization_code".to_owned()],
                tx_code: None,
                expires_in: 300,
            })
            .await
            .expect_err("unknown configuration")
            .status,
        400
    );

    let error = issuer
        .offer(&Uuid::now_v7().to_string())
        .await
        .expect_err("valid offer identifier should reach the state store");
    assert_error(
        error,
        503,
        "server_error",
        "Credential offer state is unavailable.",
    );

    let error = issuer
        .nonce(None)
        .await
        .expect_err("nonce issuance should reach the state store");
    assert_error(
        error,
        503,
        "server_error",
        "Credential nonce state is unavailable.",
    );
}

#[tokio::test]
async fn create_offer_rejects_invalid_grant_shapes_and_subject_before_database_state() {
    let issuer = operations(true).await;
    let base = |grant_types: Vec<String>, tx_code: Option<&str>, subject_id| {
        CreateCredentialOfferRequest {
            subject_id,
            credential_configuration_ids: vec!["unit-config".to_owned()],
            grant_types,
            tx_code: tx_code.map(str::to_owned),
            expires_in: 300,
        }
    };

    for request in [
        base(Vec::new(), None, Uuid::nil()),
        base(vec!["unsupported".to_owned()], None, Uuid::nil()),
        base(
            vec![
                "authorization_code".to_owned(),
                "authorization_code".to_owned(),
            ],
            None,
            Uuid::nil(),
        ),
        base(
            vec!["authorization_code".to_owned()],
            Some("1234"),
            Uuid::nil(),
        ),
    ] {
        let error = issuer
            .create_offer(request)
            .await
            .expect_err("invalid grant shape must be rejected");
        assert_error(
            error,
            400,
            "invalid_request",
            "Credential offer grant types are invalid.",
        );
    }

    let error = issuer
        .create_offer(base(
            vec![nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT.to_owned()],
            None,
            Uuid::nil(),
        ))
        .await
        .expect_err("nil subject must be rejected");
    assert_error(
        error,
        400,
        "invalid_request",
        "Credential subject is invalid.",
    );
}
