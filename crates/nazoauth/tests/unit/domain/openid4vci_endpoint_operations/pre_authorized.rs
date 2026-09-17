use super::*;

/// Credential store test double that deactivates the authenticated
/// `oauth_clients` row inside `persist_pre_authorized_access`, reproducing the
/// window between pre-authorized offer consumption and final grant
/// persistence where a registered client can be deactivated. Every other
/// transition delegates to the real PostgreSQL store unchanged.
struct ClientDeactivatingStore {
    inner: Arc<dyn nazo_persistence::Openid4vciStore>,
    pool: nazo_postgres::DbPool,
}

impl ClientDeactivatingStore {
    async fn deactivate(
        &self,
        tenant_id: Uuid,
        client_id: &str,
    ) -> Result<(), CredentialStoreError> {
        let mut connection = nazo_postgres::get_conn(&self.pool)
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
        sql_query(
            "UPDATE oauth_clients SET is_active = FALSE WHERE tenant_id = $1 AND client_id = $2",
        )
        .bind::<SqlUuid, _>(tenant_id)
        .bind::<Text, _>(client_id)
        .execute(&mut connection)
        .await
        .map_err(|_| CredentialStoreError::Unavailable)?;
        Ok(())
    }
}

impl CredentialStorePort for ClientDeactivatingStore {
    fn upsert_access<'a>(
        &'a self,
        token_hash: &'a str,
        access: &'a CredentialAccess,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        self.inner.upsert_access(token_hash, access)
    }

    fn persist_pre_authorized_access<'a>(
        &'a self,
        token_hash: &'a str,
        access: &'a CredentialAccess,
        registered_client_id: Option<&'a str>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            if let Some(client_id) = registered_client_id {
                self.deactivate(access.tenant_id, client_id).await?;
            }
            self.inner
                .persist_pre_authorized_access(token_hash, access, registered_client_id)
                .await
        })
    }

    fn offer<'a>(
        &'a self,
        tenant_id: Uuid,
        id: Uuid,
        now: chrono::DateTime<chrono::Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<StoredCredentialOffer>, CredentialStoreError>>
    {
        self.inner.offer(tenant_id, id, now)
    }

    fn consume_pre_authorized_offer<'a>(
        &'a self,
        tenant_id: Uuid,
        code_hash: &'a str,
        tx_code: Option<&'a str>,
        client_id: &'a str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<CredentialAuthorization>, CredentialStoreError>>
    {
        self.inner
            .consume_pre_authorized_offer(tenant_id, code_hash, tx_code, client_id, now)
    }

    fn issue_nonce<'a>(
        &'a self,
        nonce: &'a NonceRecord,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        self.inner.issue_nonce(nonce)
    }

    fn claim_nonce<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        self.inner.claim_nonce(nonce_hash, claim_id, now)
    }

    fn finalize_nonce<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        self.inner.finalize_nonce(nonce_hash, claim_id, now)
    }

    fn release_nonce<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        self.inner.release_nonce(nonce_hash, claim_id, now)
    }

    fn finalize_nonce_with_notification<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        handle: &'a NotificationHandle,
        now: chrono::DateTime<chrono::Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        self.inner
            .finalize_nonce_with_notification(nonce_hash, claim_id, handle, now)
    }

    fn find_response<'a>(
        &'a self,
        issuance_id: Uuid,
        token_id: Uuid,
        request_digest: &'a str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<StoredCredentialResponse>, CredentialStoreError>>
    {
        self.inner
            .find_response(issuance_id, token_id, request_digest, now)
    }

    fn finalize_nonce_with_notification_and_response<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        handle: &'a NotificationHandle,
        response: &'a StoredCredentialResponse,
        now: chrono::DateTime<chrono::Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        self.inner.finalize_nonce_with_notification_and_response(
            nonce_hash, claim_id, handle, response, now,
        )
    }

    fn store_response_with_notification<'a>(
        &'a self,
        handle: &'a NotificationHandle,
        response: &'a StoredCredentialResponse,
        now: chrono::DateTime<chrono::Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        self.inner
            .store_response_with_notification(handle, response, now)
    }

    fn resolve_access<'a>(
        &'a self,
        token_hash: &'a str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<CredentialAccess>, CredentialStoreError>> {
        self.inner.resolve_access(token_hash, now)
    }

    fn store_deferred<'a>(
        &'a self,
        credential: &'a DeferredCredential,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        self.inner.store_deferred(credential)
    }

    fn store_deferred_and_finalize_nonce<'a>(
        &'a self,
        credential: &'a DeferredCredential,
        nonce_hash: &'a str,
        claim_id: &'a str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        self.inner
            .store_deferred_and_finalize_nonce(credential, nonce_hash, claim_id, now)
    }

    fn store_deferred_and_finalize_nonce_with_response<'a>(
        &'a self,
        credential: &'a DeferredCredential,
        nonce_hash: &'a str,
        claim_id: &'a str,
        response: &'a StoredCredentialResponse,
        now: chrono::DateTime<chrono::Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        self.inner.store_deferred_and_finalize_nonce_with_response(
            credential, nonce_hash, claim_id, response, now,
        )
    }

    fn store_deferred_with_response<'a>(
        &'a self,
        credential: &'a DeferredCredential,
        response: &'a StoredCredentialResponse,
        now: chrono::DateTime<chrono::Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        self.inner
            .store_deferred_with_response(credential, response, now)
    }

    fn claim_ready_deferred<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<DeferredCredentialClaim>, CredentialStoreError>>
    {
        self.inner
            .claim_ready_deferred(transaction_hash, token_id, claim_id, now)
    }

    fn finalize_deferred<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        self.inner
            .finalize_deferred(transaction_hash, token_id, claim_id, now)
    }

    fn release_deferred<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        self.inner
            .release_deferred(transaction_hash, token_id, claim_id, now)
    }

    fn finalize_deferred_with_notification<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        handle: &'a NotificationHandle,
        now: chrono::DateTime<chrono::Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        self.inner.finalize_deferred_with_notification(
            transaction_hash,
            token_id,
            claim_id,
            handle,
            now,
        )
    }

    fn finalize_deferred_with_notification_and_response<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        handle: &'a NotificationHandle,
        response: &'a StoredCredentialResponse,
        now: chrono::DateTime<chrono::Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        self.inner.finalize_deferred_with_notification_and_response(
            transaction_hash,
            token_id,
            claim_id,
            handle,
            response,
            now,
        )
    }

    fn record_notification<'a>(
        &'a self,
        notification: &'a IssuanceNotification,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        self.inner.record_notification(notification)
    }

    fn issue_notification_handle<'a>(
        &'a self,
        handle: &'a NotificationHandle,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        self.inner.issue_notification_handle(handle)
    }
}

impl nazo_persistence::Openid4vciStore for ClientDeactivatingStore {
    fn insert_offer<'a>(
        &'a self,
        offer: &'a StoredCredentialOffer,
        issuer_state_hash: Option<&'a str>,
        pre_authorized_code_hash: Option<&'a str>,
        tx_code_hash: Option<&'a str>,
    ) -> futures_util::future::BoxFuture<'a, Result<(), CredentialStoreError>> {
        self.inner.insert_offer(
            offer,
            issuer_state_hash,
            pre_authorized_code_hash,
            tx_code_hash,
        )
    }
}

#[derive(diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    total: i64,
}

#[derive(diesel::QueryableByName)]
struct ActiveFlagRow {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    is_active: bool,
}

#[derive(diesel::QueryableByName)]
struct TokenIdRow {
    #[diesel(sql_type = SqlUuid)]
    token_id: Uuid,
}

#[tokio::test]
async fn pre_authorized_token_reaches_offer_state() {
    let issuer = operations(true).await;
    let error = issuer
        .pre_authorized_token(PreAuthorizedTokenRequest {
            pre_authorized_code: "unit-code".to_owned(),
            tx_code: None,
            client_id: None,
            dpop_jkt: None,
            mtls_x5t_s256: None,
        })
        .await
        .expect_err("missing offer state should fail at the persistence boundary");
    assert_error(
        error,
        503,
        "server_error",
        "Credential offer state is unavailable.",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_immediate_offer_pre_authorized_credential_replay_and_notification() {
    let Some(fixture) = LiveEndpointFixture::new("unit-live-immediate", false).await else {
        return;
    };
    let offer = fixture
        .issuer
        .create_offer(CreateCredentialOfferRequest {
            subject_id: fixture.subject_id,
            credential_configuration_ids: vec!["unit-live-immediate".to_owned()],
            grant_types: vec![nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT.to_owned()],
            tx_code: None,
            expires_in: 300,
        })
        .await
        .expect("live immediate offer should persist");
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
        .expect("live pre-authorized token should be issued");
    assert_eq!(access.token_type, "Bearer");
    assert_eq!(access.authorization_details.len(), 1);

    let nonce = fixture
        .issuer
        .nonce(None)
        .await
        .expect("live credential nonce should be issued");
    let request = jwt_credential_request("unit-live-immediate", &fixture.issuer.issuer, &nonce);
    let mut context = request_context();
    context.bearer_token = access.access_token;
    let response = fixture
        .issuer
        .credential(
            context.clone(),
            CredentialRequestBody::Json(request.clone()),
        )
        .await
        .expect("live immediate credential should be issued");
    let notification_id = match &response.body {
        CredentialResponseBody::Json(body) => body
            .notification_id
            .clone()
            .expect("immediate response notification id"),
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
        .credential(context.clone(), CredentialRequestBody::Json(request))
        .await
        .expect("identical immediate credential request should replay");
    assert_eq!(replay.body, response.body);
    assert_eq!(replay.dpop_nonce, response.dpop_nonce);

    fixture
        .issuer
        .notify(
            CredentialRequestContext {
                request_url: "/openid4vci/notification".to_owned(),
                ..context.clone()
            },
            NotificationRequest {
                notification_id: notification_id.clone(),
                event: nazo_openid4vci::NotificationEvent::CredentialAccepted,
                event_description: Some("live immediate completed".to_owned()),
            },
        )
        .await
        .expect("live immediate notification should be recorded");

    let error = fixture
        .issuer
        .notify(
            CredentialRequestContext {
                request_url: "/openid4vci/notification".to_owned(),
                ..context
            },
            NotificationRequest {
                notification_id,
                event: nazo_openid4vci::NotificationEvent::CredentialAccepted,
                event_description: Some("live immediate replay".to_owned()),
            },
        )
        .await
        .expect_err("terminal notification must not be replayed");
    assert_error(
        error,
        400,
        "invalid_notification_id",
        "Notification identifier is invalid or already terminal.",
    );
    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_pre_authorized_uuid_access_resolves_without_generic_issuance_row() {
    let Some(fixture) = LiveEndpointFixture::new("unit-live-standalone-access", false).await else {
        return;
    };
    let offer = fixture
        .issuer
        .create_offer(CreateCredentialOfferRequest {
            subject_id: fixture.subject_id,
            credential_configuration_ids: vec!["unit-live-standalone-access".to_owned()],
            grant_types: vec![nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT.to_owned()],
            tx_code: None,
            expires_in: 300,
        })
        .await
        .expect("standalone offer should persist");
    // Anonymous wallet entry: no registered client identity, so persistence
    // skips the client lock entirely and issues a UUID-subject access token.
    let access = fixture
        .issuer
        .pre_authorized_token(PreAuthorizedTokenRequest {
            pre_authorized_code: pre_authorized_code(&offer),
            tx_code: None,
            client_id: None,
            dpop_jkt: None,
            mtls_x5t_s256: None,
        })
        .await
        .expect("standalone pre-authorized token should be issued");

    let mut connection = nazo_postgres::get_conn(&fixture.pool)
        .await
        .expect("standalone access fixture database connection");
    let grants = sql_query("SELECT token_id FROM openid4vci_access_grants WHERE subject_id = $1")
        .bind::<SqlUuid, _>(fixture.subject_id)
        .load::<TokenIdRow>(&mut connection)
        .await
        .expect("standalone access grant lookup");
    assert_eq!(grants.len(), 1, "exactly one access grant should persist");
    let issuances = sql_query(
        "SELECT count(*) AS total FROM oauth_token_issuances WHERE access_token_jti = $1",
    )
    .bind::<Text, _>(grants[0].token_id.to_string())
    .get_result::<CountRow>(&mut connection)
    .await
    .expect("generic issuance lookup should succeed");
    assert_eq!(
        issuances.total, 0,
        "standalone pre-authorized access must not create a generic issuance row"
    );
    drop(connection);

    fixture
        .issuer
        .access(&CredentialRequestContext {
            bearer_token: access.access_token,
            ..request_context()
        })
        .await
        .expect("UUID subject must resolve without a generic issuance row");
    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_pre_authorized_rejects_inactive_subject_after_offer_consumption() {
    let Some(fixture) = LiveEndpointFixture::new("unit-live-inactive-subject", false).await else {
        return;
    };
    let offer = fixture
        .issuer
        .create_offer(CreateCredentialOfferRequest {
            subject_id: fixture.subject_id,
            credential_configuration_ids: vec!["unit-live-inactive-subject".to_owned()],
            grant_types: vec![nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT.to_owned()],
            tx_code: None,
            expires_in: 300,
        })
        .await
        .expect("inactive-subject offer should persist");
    let code = pre_authorized_code(&offer);
    // Deactivate the subject directly so the still-unconsumed offer reaches the
    // subject-activity check inside the token operation.
    let mut connection = nazo_postgres::get_conn(&fixture.pool)
        .await
        .expect("inactive-subject fixture database connection");
    sql_query("UPDATE users SET is_active = FALSE WHERE id = $1")
        .bind::<SqlUuid, _>(fixture.subject_id)
        .execute(&mut connection)
        .await
        .expect("inactive-subject fixture user update");
    drop(connection);

    let request = |code: &str| PreAuthorizedTokenRequest {
        pre_authorized_code: code.to_owned(),
        tx_code: None,
        client_id: Some(fixture.wallet_client_id.clone()),
        dpop_jkt: None,
        mtls_x5t_s256: None,
    };
    let error = fixture
        .issuer
        .pre_authorized_token(request(&code))
        .await
        .expect_err("an inactive subject must reject the pre-authorized grant");
    assert_error(
        error,
        400,
        "invalid_grant",
        "Credential subject is inactive.",
    );

    let error = fixture
        .issuer
        .pre_authorized_token(request(&code))
        .await
        .expect_err("the consumed offer must not be replayable");
    assert_error(
        error,
        400,
        "invalid_grant",
        "Pre-authorized code or transaction code is invalid.",
    );
    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_pre_authorized_rejects_client_deactivated_before_persistence() {
    let Some(database_url) = std::env::var("NAZO_TEST_DATABASE_URL")
        .ok()
        .or_else(|| std::env::var("DATABASE_URL").ok())
    else {
        assert!(
            std::env::var_os("CI").is_none(),
            "CI requires NAZO_TEST_DATABASE_URL/DATABASE_URL"
        );
        return;
    };
    let wrapper_pool =
        nazo_postgres::create_pool(database_url, 2).expect("deactivating store pool should build");
    let store: Arc<dyn nazo_persistence::Openid4vciStore> = Arc::new(ClientDeactivatingStore {
        inner: Arc::new(nazo_postgres::Openid4vciRepository::new(
            wrapper_pool.clone(),
            [0x51; 32],
        )),
        pool: wrapper_pool,
    });
    let Some(fixture) = LiveEndpointFixture::new_with_overrides(
        "unit-live-client-deactivation",
        false,
        Some(store),
        None,
    )
    .await
    else {
        return;
    };
    let offer = fixture
        .issuer
        .create_offer(CreateCredentialOfferRequest {
            subject_id: fixture.subject_id,
            credential_configuration_ids: vec!["unit-live-client-deactivation".to_owned()],
            grant_types: vec![nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT.to_owned()],
            tx_code: None,
            expires_in: 300,
        })
        .await
        .expect("client-deactivation offer should persist");
    let code = pre_authorized_code(&offer);

    // The deactivating store flips the registered client to inactive inside the
    // persistence call, reproducing the window after offer consumption where
    // the earlier authentication check can no longer see the client state.
    let error = fixture
        .issuer
        .pre_authorized_token(PreAuthorizedTokenRequest {
            pre_authorized_code: code.clone(),
            tx_code: None,
            client_id: Some(fixture.wallet_client_id.clone()),
            dpop_jkt: None,
            mtls_x5t_s256: None,
        })
        .await
        .expect_err("a client deactivated before persistence must not be issued a token");
    assert_eq!(error.status, 400);
    assert_eq!(error.error, "unauthorized_client");
    assert_eq!(error.description, "Credential client is inactive.");

    // The token endpoint presents this failure as an HTTP 400
    // unauthorized_client body carrying no token material and no challenge.
    let response = nazo_http_actix::pre_authorized_token_error_response(error);
    assert_eq!(response.status(), actix_web::http::StatusCode::BAD_REQUEST);
    assert!(
        response
            .headers()
            .get(actix_web::http::header::WWW_AUTHENTICATE)
            .is_none(),
        "unauthorized_client carries no WWW-Authenticate challenge"
    );
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("pre-authorized error body should collect");
    let body: Value = serde_json::from_slice(&body).expect("pre-authorized error body is JSON");
    assert_eq!(body["error"], "unauthorized_client");
    assert_eq!(body["error_description"], "Credential client is inactive.");
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());

    let mut connection = nazo_postgres::get_conn(&fixture.pool)
        .await
        .expect("client-deactivation fixture database connection");
    let grants =
        sql_query("SELECT count(*) AS total FROM openid4vci_access_grants WHERE subject_id = $1")
            .bind::<SqlUuid, _>(fixture.subject_id)
            .get_result::<CountRow>(&mut connection)
            .await
            .expect("access grant count should query");
    assert_eq!(
        grants.total, 0,
        "no access grant may be persisted for a deactivated client"
    );
    let client =
        sql_query("SELECT is_active FROM oauth_clients WHERE tenant_id = $1 AND client_id = $2")
            .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
            .bind::<Text, _>(fixture.wallet_client_id.clone())
            .get_result::<ActiveFlagRow>(&mut connection)
            .await
            .expect("wallet client row should exist");
    assert!(
        !client.is_active,
        "the fixture deactivation must be visible"
    );
    drop(connection);

    let error = fixture
        .issuer
        .pre_authorized_token(PreAuthorizedTokenRequest {
            pre_authorized_code: code,
            tx_code: None,
            client_id: Some(fixture.wallet_client_id.clone()),
            dpop_jkt: None,
            mtls_x5t_s256: None,
        })
        .await
        .expect_err("the consumed offer must not be replayable");
    assert_error(
        error,
        400,
        "invalid_grant",
        "Pre-authorized code or transaction code is invalid.",
    );
    fixture.cleanup().await;
}
