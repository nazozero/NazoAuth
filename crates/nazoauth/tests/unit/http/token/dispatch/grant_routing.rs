use super::*;

#[actix_web::test]
async fn token_endpoint_rejects_malformed_form_requests_before_client_lookup() {
    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    let cases = [
        (
            token_request("application/json"),
            Bytes::from_static(b"{\"grant_type\":\"client_credentials\"}"),
            "invalid_request",
        ),
        (
            token_request("application/x-www-form-urlencoded"),
            Bytes::from_static(b"grant_type=\xff"),
            "invalid_request",
        ),
        (
            token_request("application/x-www-form-urlencoded"),
            Bytes::from_static(b"grant_type=client_credentials&grant_type=refresh_token"),
            "invalid_request",
        ),
        (
            token_request("application/x-www-form-urlencoded"),
            Bytes::from_static(
                b"grant_type=client_credentials&resource=https%3A%2F%2Fapi.example%2F%23fragment",
            ),
            "invalid_request",
        ),
        (
            token_request("application/x-www-form-urlencoded"),
            Bytes::from_static(b"grant_type=client_credentials&audience="),
            "invalid_request",
        ),
        (
            token_request("application/x-www-form-urlencoded"),
            Bytes::from_static(b"client_id=client-1"),
            "invalid_request",
        ),
    ];

    for (req, body, expected_error) in cases {
        assert_token_error(
            token(state.clone(), req, body).await,
            StatusCode::BAD_REQUEST,
            expected_error,
            false,
        )
        .await;
    }
}

#[actix_web::test]
async fn token_endpoint_rejects_legacy_audience_parameter_outside_token_exchange() {
    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    let req = token_request("application/x-www-form-urlencoded");
    let body = Bytes::from_static(
        b"grant_type=client_credentials&client_id=client-1&audience=https%3A%2F%2Fapi.example",
    );

    assert_token_error(
        token(state, req, body).await,
        StatusCode::BAD_REQUEST,
        "invalid_request",
        false,
    )
    .await;
}

#[actix_web::test]
async fn token_endpoint_rejects_disallowed_fapi_password_grant_before_client_auth() {
    let Some(state) = live_token_state(AuthorizationServerProfile::Fapi2Security).await else {
        return;
    };
    let req = token_request("application/x-www-form-urlencoded");
    let body = Bytes::from_static(b"grant_type=password&username=alice&password=secret");

    assert_token_error(
        token(state, req, body).await,
        StatusCode::BAD_REQUEST,
        "unsupported_grant_type",
        false,
    )
    .await;
}

#[actix_web::test]
async fn token_endpoint_returns_unsupported_grant_only_after_client_authentication() {
    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    let correct_secret = fixture_secret("unsupported-grant");
    insert_token_client(
        &state,
        "unsupported-grant-client",
        "confidential",
        "client_secret_post",
        Some(fixture_secret_hash(&state, &correct_secret)),
        vec!["urn:example:unsupported"],
        false,
        false,
        true,
    )
    .await;

    let req = token_request("application/x-www-form-urlencoded");
    let body = Bytes::from(format!(
        "grant_type=urn%3Aexample%3Aunsupported&client_id=unsupported-grant-client&client_secret={}",
        urlencoding::encode(&correct_secret)
    ));

    assert_token_error(
        token(state, req, body).await,
        StatusCode::BAD_REQUEST,
        "unsupported_grant_type",
        false,
    )
    .await;
}

#[actix_web::test]
async fn pre_authorized_token_dpop_nonce_error_returns_nonce_challenge_header() {
    let response = nazo_http_actix::pre_authorized_token_error_response(
        nazo_openid4vci::application::CredentialHttpError {
            status: 400,
            error: "use_dpop_nonce",
            description: "Credential issuer requires nonce in DPoP proof.",
            dpop_nonce: Some("issuer-nonce-1".to_owned()),
        },
    );

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .headers()
            .get(header::HeaderName::from_static("dpop-nonce")),
        Some(&header::HeaderValue::from_static("issuer-nonce-1"))
    );
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE),
        Some(&header::HeaderValue::from_static(
            r#"DPoP error="use_dpop_nonce""#
        ))
    );
    assert_eq!(oauth_error_code(response).await, "use_dpop_nonce");
}

#[actix_web::test]
async fn token_dispatch_preserves_grant_validation_and_unconfigured_issuer_error() {
    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    let client_id = format!("dispatch-grants-{}", Uuid::now_v7());
    let secret = Uuid::now_v7().to_string();
    let grants = vec![
        "authorization_code",
        "refresh_token",
        "urn:ietf:params:oauth:grant-type:device_code",
        "urn:openid:params:grant-type:ciba",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "urn:ietf:params:oauth:grant-type:token-exchange",
    ];
    insert_token_client(
        &state,
        &client_id,
        "confidential",
        "client_secret_post",
        Some(fixture_secret_hash(&state, &secret)),
        grants.clone(),
        false,
        false,
        true,
    )
    .await;
    let policy = nazo_auth::ClientSecurityPolicy {
        allow_cross_device_flows: true,
        ..Default::default()
    };
    set_token_client_security_policy(&state, &client_id, policy).await;
    for grant in grants {
        let body = Bytes::from(format!(
            "grant_type={}&client_id={}&client_secret={}",
            urlencoding::encode(grant),
            client_id,
            secret
        ));
        let response = token(
            state.clone(),
            token_request("application/x-www-form-urlencoded"),
            body,
        )
        .await;
        let expected = "invalid_request";
        assert_token_error(response, StatusCode::BAD_REQUEST, expected, false).await;
    }
    for authenticated in [false, true] {
        let mut body = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code=unused".to_owned();
        if authenticated {
            body.push_str(&format!("&client_id={client_id}&client_secret={secret}"));
        }
        assert_token_error(
            token(
                state.clone(),
                token_request("application/x-www-form-urlencoded"),
                Bytes::from(body),
            )
            .await,
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            false,
        )
        .await;
    }
    let partial = actix_web::test::TestRequest::post()
        .uri("/token")
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .insert_header(("OAuth-Client-Attestation", "incomplete-pair"))
        .to_http_request();
    assert_token_error(
        token(
            state.clone(),
            partial,
            Bytes::from_static(b"grant_type=authorization_code"),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "invalid_request",
        false,
    )
    .await;
    let inactive_id = format!("inactive-preauth-{}", Uuid::now_v7());
    insert_token_client(
        &state,
        &inactive_id,
        "confidential",
        "client_secret_post",
        Some(fixture_secret_hash(&state, &secret)),
        vec!["authorization_code"],
        false,
        false,
        false,
    )
    .await;
    assert_token_error(token(state, token_request("application/x-www-form-urlencoded"), Bytes::from(format!("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code=unused&client_id={inactive_id}&client_secret={secret}"))).await, StatusCode::UNAUTHORIZED, "invalid_client", false).await;
}

#[actix_web::test]
async fn token_exchange_issued_token_is_rejected_by_verifier_after_per_user_revocation() {
    use crate::adapters::security::tokens::{
        AccessTokenJwtInput, decode_access_claims_with, make_jwt,
    };

    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    let client_id = format!("exchange-revoke-{}", Uuid::now_v7());
    let secret = Uuid::now_v7().to_string();
    insert_token_client(
        &state,
        &client_id,
        "confidential",
        "client_secret_post",
        Some(fixture_secret_hash(&state, &secret)),
        vec!["urn:ietf:params:oauth:grant-type:token-exchange"],
        false,
        false,
        true,
    )
    .await;
    let user_id = Uuid::now_v7();
    let mut conn = get_conn(&state.diesel_db)
        .await
        .expect("database connection should be available");
    sql_query(
        r#"
        INSERT INTO users (
            id, tenant_id, realm_id, organization_id, username, email,
            password_hash, is_active, mfa_enabled, email_verified, role, admin_level
        )
        VALUES ($1, $2, $3, $4, $5, $6, 'unused-exchange-revoke-hash',
                true, false, true, 'user', 0)
        "#,
    )
    .bind::<SqlUuid, _>(user_id)
    .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
    .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
    .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
    .bind::<Text, _>(format!("exchange-revoke-{user_id}"))
    .bind::<Text, _>(format!("exchange-revoke-{user_id}@example.test"))
    .execute(&mut conn)
    .await
    .expect("exchange subject user should insert");
    drop(conn);

    let subject_token = make_jwt(
        &state.keyset,
        &state.settings.endpoint.issuer,
        AccessTokenJwtInput {
            tenant_id: DEFAULT_TENANT_ID,
            subject: &user_id.to_string(),
            user_id: Some(user_id),
            subject_type: "user",
            client_id: &client_id,
            audiences: &["resource://default".to_owned()],
            scopes: &["openid".to_owned(), "accounts".to_owned()],
            authorization_details: &json!([]),
            userinfo_claims: &[],
            userinfo_claim_requests: &[],
            ttl: 300,
            dpop_jkt: None,
            mtls_x5t_s256: None,
            actor: None,
        },
    )
    .await
    .expect("subject access token should sign");

    let (status, body) = token_json_body(
        token(
            state.clone(),
            token_request("application/x-www-form-urlencoded"),
            Bytes::from(format!(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange\
                 &subject_token={}\
                 &subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token\
                 &audience=resource%3A%2F%2Fdefault\
                 &scope=accounts\
                 &client_id={client_id}&client_secret={secret}",
                subject_token.token,
            )),
        )
        .await,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "token exchange should issue an access token: {body}"
    );
    let exchanged = body["access_token"]
        .as_str()
        .expect("token exchange must return an access token")
        .to_owned();
    let exchanged_jti =
        decode_access_claims_with(&state.keyset, &state.settings.endpoint.issuer, &exchanged)
            .expect("exchanged access token should decode")
            .jti;

    // The exchanged token never carries `openid` (token exchange strips it),
    // so the real userinfo verifier reaches the scope gate only after decode,
    // audience, tenant and revocation checks all pass. A 403
    // insufficient_scope here proves the revocation gate accepted the token.
    let userinfo_request = |token: &str| {
        actix_web::test::TestRequest::get()
            .uri("/userinfo")
            .insert_header((header::AUTHORIZATION, format!("Bearer {token}")))
            .to_http_request()
    };
    let pre_revocation = userinfo(state.clone(), userinfo_request(&exchanged), Bytes::new()).await;
    assert_eq!(
        pre_revocation.status(),
        StatusCode::FORBIDDEN,
        "before revocation the exchanged token must pass the verifier's revocation gate"
    );
    assert_eq!(oauth_error_code(pre_revocation).await, "insufficient_scope");

    // Real per-user revocation: deactivating the subject revokes every access
    // token issued for them, including token-exchange results. The operation
    // uses a cursor internally, so it needs a caller-owned transaction.
    let mut conn = get_conn(&state.diesel_db)
        .await
        .expect("database connection should be available");
    let deactivated = conn
        .transaction::<bool, diesel::result::Error, _>(async |connection| {
            nazo_postgres::disable_user_on_connection(
                connection,
                nazo_identity::TenantId::new(DEFAULT_TENANT_ID).expect("tenant id is non-nil"),
                nazo_identity::UserId::new(user_id).expect("user id is non-nil"),
            )
            .await
        })
        .await
        .expect("per-user revocation should complete");
    // Return the pooled connection before further pool use: the fixture pool
    // is intentionally small and a checked-out connection would deadlock the
    // revocation read below.
    drop(conn);
    assert!(deactivated, "the fixture user must transition to inactive");

    assert!(
        token_service(&state)
            .access_token_revoked(DEFAULT_TENANT_ID, &exchanged_jti)
            .await
            .expect("revocation state should be readable"),
        "per-user revocation must record the exchanged token's revocation fact"
    );
    let rejected = userinfo(state.clone(), userinfo_request(&exchanged), Bytes::new()).await;
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(oauth_error_code(rejected).await, "invalid_token");

    let mut conn = get_conn(&state.diesel_db)
        .await
        .expect("database connection should be available");
    for query in [
        "DELETE FROM access_token_revocations USING oauth_clients WHERE access_token_revocations.client_id = oauth_clients.id AND oauth_clients.tenant_id = $1 AND oauth_clients.client_id = $2",
        "DELETE FROM oauth_token_issuances USING oauth_clients WHERE oauth_token_issuances.client_id = oauth_clients.id AND oauth_clients.tenant_id = $1 AND oauth_clients.client_id = $2",
        "DELETE FROM oauth_clients WHERE tenant_id = $1 AND client_id = $2",
    ] {
        sql_query(query)
            .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
            .bind::<Text, _>(&client_id)
            .execute(&mut conn)
            .await
            .expect("exchange revocation client cleanup should succeed");
    }
    sql_query("DELETE FROM users WHERE id = $1")
        .bind::<SqlUuid, _>(user_id)
        .execute(&mut conn)
        .await
        .expect("exchange revocation user cleanup should succeed");
}

/// EX-01/02/04/05 + EX-07 (issued_token_type echo): a pairwise user subject
/// token carries no public UUID, so the exchange resolves its owner through
/// the issuance row (tenant + jti). Missing/inactive/cross-tenant/expired
/// resolution all fail closed with invalid_grant; a repository outage maps to
/// server_error; a public-UUID subject never touches the owner lookup.
#[actix_web::test]
async fn token_exchange_pairwise_subject_resolves_owner_through_issuance_ownership() {
    use crate::adapters::security::tokens::{
        AccessTokenJwtInput, decode_access_claims_with, make_jwt,
    };

    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    let client_id = format!("exchange-pairwise-{}", Uuid::now_v7());
    let secret = Uuid::now_v7().to_string();
    insert_token_client(
        &state,
        &client_id,
        "confidential",
        "client_secret_post",
        Some(fixture_secret_hash(&state, &secret)),
        vec!["urn:ietf:params:oauth:grant-type:token-exchange"],
        false,
        false,
        true,
    )
    .await;

    let user_id = Uuid::now_v7();
    let mut conn = get_conn(&state.diesel_db)
        .await
        .expect("database connection should be available");
    sql_query(
        r#"
        INSERT INTO users (
            id, tenant_id, realm_id, organization_id, username, email,
            password_hash, is_active, mfa_enabled, email_verified, role, admin_level
        )
        VALUES ($1, $2, $3, $4, $5, $6, 'unused-exchange-pairwise-hash',
                true, false, true, 'user', 0)
        "#,
    )
    .bind::<SqlUuid, _>(user_id)
    .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
    .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
    .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
    .bind::<Text, _>(format!("exchange-pairwise-{user_id}"))
    .bind::<Text, _>(format!("exchange-pairwise-{user_id}@example.test"))
    .execute(&mut conn)
    .await
    .expect("exchange pairwise user should insert");
    let client_row_id =
        sql_query("SELECT id FROM oauth_clients WHERE tenant_id = $1 AND client_id = $2")
            .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
            .bind::<Text, _>(&client_id)
            .get_result::<TokenClientIdRow>(&mut conn)
            .await
            .expect("test client row id should load")
            .id;
    drop(conn);

    let pairwise_subject = format!("pairwise.{}", Uuid::now_v7());
    async fn sign_pairwise_subject(
        state: &Data<TestInfrastructure>,
        client_id: &str,
        subject: &str,
    ) -> crate::adapters::security::tokens::IssuedAccessToken {
        let audiences = vec!["resource://default".to_owned()];
        let scopes = vec!["openid".to_owned(), "accounts".to_owned()];
        let authorization_details = json!([]);
        make_jwt(
            &state.keyset,
            &state.settings.endpoint.issuer,
            AccessTokenJwtInput {
                tenant_id: DEFAULT_TENANT_ID,
                subject,
                user_id: None,
                subject_type: "user",
                client_id,
                audiences: &audiences,
                scopes: &scopes,
                authorization_details: &authorization_details,
                userinfo_claims: &[],
                userinfo_claim_requests: &[],
                ttl: 300,
                dpop_jkt: None,
                mtls_x5t_s256: None,
                actor: None,
            },
        )
        .await
        .expect("pairwise subject token should sign")
    }

    let counting = crate::test_support::CountingTokenRepository::new(Arc::new(
        crate::test_support::token_issuance_repository(state.diesel_db.clone()),
    ));
    let exchange = |subject_token: &str, repository: Arc<dyn nazo_auth::TokenRepositoryPort>| {
        token_with_port_repositories(
            state.clone(),
            repository,
            Arc::new(nazo_postgres::AuthorizationFlowRepository::new(
                state.diesel_db.clone(),
                DEFAULT_TENANT_ID,
            )),
            Arc::new(
                crate::adapters::remote_client_documents::RemoteClientDocumentResolver::new(&[])
                    .expect("empty remote document policy is valid"),
            ),
            Openid4vcTokenHandles::default(),
            token_request("application/x-www-form-urlencoded"),
            Bytes::from(format!(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange\
                 &subject_token={}\
                 &subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token\
                 &audience=resource%3A%2F%2Fdefault\
                 &scope=accounts\
                 &client_id={client_id}&client_secret={secret}",
                urlencoding::encode(subject_token),
            )),
        )
    };
    let insert_issuance =
        |jti: &str, owner: Option<Uuid>, tenant: Uuid, expires: chrono::DateTime<Utc>| {
            let diesel_db = state.diesel_db.clone();
            let jti = jti.to_owned();
            async move {
                let mut conn = get_conn(&diesel_db)
                    .await
                    .expect("database connection should be available");
                sql_query(
                    r#"
                INSERT INTO oauth_token_issuances (
                    issuance_id, tenant_id, client_id, user_id,
                    access_token_jti, access_token_expires_at, retain_until
                ) VALUES ($1, $2, $3, $4, $5, $6, $6)
                "#,
                )
                .bind::<SqlUuid, _>(Uuid::now_v7())
                .bind::<SqlUuid, _>(tenant)
                .bind::<SqlUuid, _>(client_row_id)
                .bind::<diesel::sql_types::Nullable<SqlUuid>, _>(owner)
                .bind::<Text, _>(jti)
                .bind::<diesel::sql_types::Timestamptz, _>(expires)
                .execute(&mut conn)
                .await
                .expect("issuance row should insert");
            }
        };

    // Success: the pairwise subject resolves through the issuance row, the
    // issued token stays a user token with the same pairwise sub, and the
    // user-facing issued_token_type audit field is echoed.
    let resolvable = sign_pairwise_subject(&state, &client_id, &pairwise_subject).await;
    insert_issuance(
        &resolvable.jti,
        Some(user_id),
        DEFAULT_TENANT_ID,
        Utc::now() + Duration::seconds(300),
    )
    .await;
    let (status, body) =
        token_json_body(exchange(&resolvable.token, Arc::new(counting.clone())).await).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "pairwise exchange should succeed: {body}"
    );
    assert_eq!(
        body["issued_token_type"].as_str(),
        Some("urn:ietf:params:oauth:token-type:access_token"),
        "the user-facing exchange audit field must echo the issued token type"
    );
    let exchanged_claims = decode_access_claims_with(
        &state.keyset,
        &state.settings.endpoint.issuer,
        body["access_token"].as_str().expect("access token"),
    )
    .expect("exchanged token should decode");
    assert_eq!(exchanged_claims.sub, pairwise_subject);
    assert_eq!(
        exchanged_claims.user_id, None,
        "pairwise subjects must not leak the public UUID into token claims"
    );
    assert_eq!(exchanged_claims.subject_type, "user");
    let mut conn = get_conn(&state.diesel_db)
        .await
        .expect("database connection should be available");
    let persisted_owner = sql_query(
        "SELECT user_id FROM oauth_token_issuances \
         WHERE tenant_id = $1 AND access_token_jti = $2",
    )
    .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
    .bind::<Text, _>(&exchanged_claims.jti)
    .get_result::<TokenOwnerRow>(&mut conn)
    .await
    .expect("exchange issuance row should be persisted")
    .user_id;
    drop(conn);
    assert_eq!(
        persisted_owner,
        Some(user_id),
        "the persisted issuance owner must be the resolved pairwise user"
    );
    assert_eq!(
        counting.owner_lookup_count(),
        1,
        "a pairwise subject performs exactly one owner lookup"
    );

    // Missing issuance row: no resolvable user boundary.
    let orphan =
        sign_pairwise_subject(&state, &client_id, &format!("pairwise.{}", Uuid::now_v7())).await;
    let (status, body) =
        token_json_body(exchange(&orphan.token, Arc::new(counting.clone())).await).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );

    // Inactive owner: the issuance join filters is_active, so resolution fails.
    let inactive_user = Uuid::now_v7();
    let mut conn = get_conn(&state.diesel_db)
        .await
        .expect("database connection should be available");
    sql_query(
        r#"
        INSERT INTO users (
            id, tenant_id, realm_id, organization_id, username, email,
            password_hash, is_active, mfa_enabled, email_verified, role, admin_level
        )
        VALUES ($1, $2, $3, $4, $5, $6, 'unused-exchange-inactive-hash',
                false, false, true, 'user', 0)
        "#,
    )
    .bind::<SqlUuid, _>(inactive_user)
    .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
    .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
    .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
    .bind::<Text, _>(format!("exchange-inactive-{inactive_user}"))
    .bind::<Text, _>(format!("exchange-inactive-{inactive_user}@example.test"))
    .execute(&mut conn)
    .await
    .expect("inactive exchange user should insert");
    drop(conn);
    let inactive_subject =
        sign_pairwise_subject(&state, &client_id, &format!("pairwise.{}", Uuid::now_v7())).await;
    insert_issuance(
        &inactive_subject.jti,
        Some(inactive_user),
        DEFAULT_TENANT_ID,
        Utc::now() + Duration::seconds(300),
    )
    .await;
    let (status, body) =
        token_json_body(exchange(&inactive_subject.token, Arc::new(counting.clone())).await).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );

    // Cross-tenant issuance rows are invisible to this tenant's resolution.
    // The composite (client_id, tenant_id) / (user_id, tenant_id) foreign keys
    // plus the realm/organization tenant boundaries require a complete
    // fixture inside the foreign tenant.
    let foreign_tenant = Uuid::now_v7();
    let foreign_realm = Uuid::now_v7();
    let foreign_organization = Uuid::now_v7();
    let foreign_user = Uuid::now_v7();
    {
        let mut conn = get_conn(&state.diesel_db)
            .await
            .expect("database connection should be available");
        sql_query(
            "INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, 'Exchange foreign')",
        )
        .bind::<SqlUuid, _>(foreign_tenant)
        .bind::<Text, _>(format!("exchange-foreign-{foreign_tenant}"))
        .execute(&mut conn)
        .await
        .expect("foreign tenant should insert");
        sql_query(
            "INSERT INTO realms (id, tenant_id, slug, display_name) VALUES ($1, $2, $3, 'Exchange foreign realm')",
        )
        .bind::<SqlUuid, _>(foreign_realm)
        .bind::<SqlUuid, _>(foreign_tenant)
        .bind::<Text, _>(format!("exchange-foreign-{foreign_realm}"))
        .execute(&mut conn)
        .await
        .expect("foreign realm should insert");
        sql_query(
            "INSERT INTO organizations (id, tenant_id, slug, display_name) VALUES ($1, $2, $3, 'Exchange foreign organization')",
        )
        .bind::<SqlUuid, _>(foreign_organization)
        .bind::<SqlUuid, _>(foreign_tenant)
        .bind::<Text, _>(format!("exchange-foreign-{foreign_organization}"))
        .execute(&mut conn)
        .await
        .expect("foreign organization should insert");
        sql_query(
            r#"
            INSERT INTO users (
                id, tenant_id, realm_id, organization_id, username, email,
                password_hash, is_active, mfa_enabled, email_verified, role, admin_level
            )
            VALUES ($1, $2, $3, $4, $5, $6, 'unused-exchange-foreign-hash',
                    true, false, true, 'user', 0)
            "#,
        )
        .bind::<SqlUuid, _>(foreign_user)
        .bind::<SqlUuid, _>(foreign_tenant)
        .bind::<SqlUuid, _>(foreign_realm)
        .bind::<SqlUuid, _>(foreign_organization)
        .bind::<Text, _>(format!("exchange-foreign-{foreign_user}"))
        .bind::<Text, _>(format!("exchange-foreign-{foreign_user}@example.test"))
        .execute(&mut conn)
        .await
        .expect("foreign user should insert");
        sql_query(
            r#"
            INSERT INTO oauth_clients (
                tenant_id, realm_id, organization_id, client_id, client_name, client_type,
                client_secret_hash, redirect_uris, scopes, allowed_audiences,
                grant_types, token_endpoint_auth_method, require_dpop_bound_tokens,
                require_mtls_bound_tokens, tls_client_auth_san_dns, tls_client_auth_san_uri,
                tls_client_auth_san_ip, tls_client_auth_san_email,
                allow_client_assertion_audience_array,
                allow_client_assertion_endpoint_audience, require_par_request_object,
                is_active, security_policy,
                post_logout_redirect_uris, backchannel_logout_session_required
            )
            VALUES (
                $1, $2, $3, $4, 'Exchange Foreign Client', 'confidential',
                NULL, '["https://client.example/callback"]'::jsonb,
                '["openid","accounts"]'::jsonb, '["resource://default"]'::jsonb,
                '["client_credentials"]'::jsonb, 'client_secret_post',
                false, false, '[]'::jsonb, '[]'::jsonb,
                '[]'::jsonb, '[]'::jsonb,
                false, false, false, true,
                '{"version":1,"assurance":"baseline","require_signed_authorization_request":false,"require_signed_authorization_response":false,"require_signed_introspection_response":false,"session_management":false,"allow_cross_device_flows":false,"allow_confidential_oidc_without_pkce":false}'::jsonb,
                '[]'::jsonb, true
            )
            "#,
        )
        .bind::<SqlUuid, _>(foreign_tenant)
        .bind::<SqlUuid, _>(foreign_realm)
        .bind::<SqlUuid, _>(foreign_organization)
        .bind::<Text, _>(format!("exchange-foreign-{foreign_user}"))
        .execute(&mut conn)
        .await
        .expect("foreign client should insert");
    }
    let foreign_client_row_id = {
        let mut conn = get_conn(&state.diesel_db)
            .await
            .expect("database connection should be available");
        sql_query("SELECT id FROM oauth_clients WHERE tenant_id = $1 AND client_id = $2")
            .bind::<SqlUuid, _>(foreign_tenant)
            .bind::<Text, _>(format!("exchange-foreign-{foreign_user}"))
            .get_result::<TokenClientIdRow>(&mut conn)
            .await
            .expect("foreign client row id should load")
            .id
    };
    let foreign =
        sign_pairwise_subject(&state, &client_id, &format!("pairwise.{}", Uuid::now_v7())).await;
    {
        let mut conn = get_conn(&state.diesel_db)
            .await
            .expect("database connection should be available");
        sql_query(
            r#"
            INSERT INTO oauth_token_issuances (
                issuance_id, tenant_id, client_id, user_id,
                access_token_jti, access_token_expires_at, retain_until
            ) VALUES ($1, $2, $3, $4, $5, $6, $6)
            "#,
        )
        .bind::<SqlUuid, _>(Uuid::now_v7())
        .bind::<SqlUuid, _>(foreign_tenant)
        .bind::<SqlUuid, _>(foreign_client_row_id)
        .bind::<SqlUuid, _>(foreign_user)
        .bind::<Text, _>(&foreign.jti)
        .bind::<diesel::sql_types::Timestamptz, _>(Utc::now() + Duration::seconds(300))
        .execute(&mut conn)
        .await
        .expect("foreign issuance row should insert");
    }
    let (status, body) =
        token_json_body(exchange(&foreign.token, Arc::new(counting.clone())).await).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );

    // Expired issuance rows (outside the clock-skew horizon) do not resolve.
    let expired =
        sign_pairwise_subject(&state, &client_id, &format!("pairwise.{}", Uuid::now_v7())).await;
    insert_issuance(
        &expired.jti,
        Some(user_id),
        DEFAULT_TENANT_ID,
        Utc::now() - Duration::seconds(120),
    )
    .await;
    let (status, body) =
        token_json_body(exchange(&expired.token, Arc::new(counting.clone())).await).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );

    // Public-UUID subjects carry the user boundary inline and must not touch
    // the owner lookup at all.
    let public_subject = make_jwt(
        &state.keyset,
        &state.settings.endpoint.issuer,
        AccessTokenJwtInput {
            tenant_id: DEFAULT_TENANT_ID,
            subject: &user_id.to_string(),
            user_id: Some(user_id),
            subject_type: "user",
            client_id: &client_id,
            audiences: &["resource://default".to_owned()],
            scopes: &["openid".to_owned(), "accounts".to_owned()],
            authorization_details: &json!([]),
            userinfo_claims: &[],
            userinfo_claim_requests: &[],
            ttl: 300,
            dpop_jkt: None,
            mtls_x5t_s256: None,
            actor: None,
        },
    )
    .await
    .expect("public subject token should sign");
    let before = counting.owner_lookup_count();
    let (status, body) =
        token_json_body(exchange(&public_subject.token, Arc::new(counting.clone())).await).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "public exchange should succeed: {body}"
    );
    assert_eq!(
        counting.owner_lookup_count(),
        before,
        "a public-UUID subject must not perform the owner lookup"
    );

    // A repository outage on the owner lookup maps to server_error, never to
    // invalid_grant.
    let outage_subject =
        sign_pairwise_subject(&state, &client_id, &format!("pairwise.{}", Uuid::now_v7())).await;
    let failing =
        crate::test_support::CountingTokenRepository::with_failing_owner_lookup(Arc::new(
            crate::test_support::token_issuance_repository(state.diesel_db.clone()),
        ));
    let (status, body) =
        token_json_body(exchange(&outage_subject.token, Arc::new(failing)).await).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, Some("server_error"))
    );

    let mut conn = get_conn(&state.diesel_db)
        .await
        .expect("database connection should be available");
    for query in [
        "DELETE FROM access_token_revocations USING oauth_clients WHERE access_token_revocations.client_id = oauth_clients.id AND oauth_clients.tenant_id = $1 AND oauth_clients.client_id = $2",
        "DELETE FROM oauth_token_issuances USING oauth_clients WHERE oauth_token_issuances.client_id = oauth_clients.id AND oauth_clients.tenant_id = $1 AND oauth_clients.client_id = $2",
        "DELETE FROM oauth_clients WHERE tenant_id = $1 AND client_id = $2",
    ] {
        sql_query(query)
            .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
            .bind::<Text, _>(&client_id)
            .execute(&mut conn)
            .await
            .expect("pairwise exchange client cleanup should succeed");
    }
    for user in [user_id, inactive_user] {
        sql_query("DELETE FROM users WHERE id = $1")
            .bind::<SqlUuid, _>(user)
            .execute(&mut conn)
            .await
            .expect("pairwise exchange user cleanup should succeed");
    }
    for query in [
        "DELETE FROM oauth_token_issuances WHERE tenant_id = $1",
        "DELETE FROM oauth_clients WHERE tenant_id = $1",
        "DELETE FROM users WHERE tenant_id = $1",
        "DELETE FROM organizations WHERE tenant_id = $1",
        "DELETE FROM realms WHERE tenant_id = $1",
        "DELETE FROM tenants WHERE id = $1",
    ] {
        sql_query(query)
            .bind::<SqlUuid, _>(foreign_tenant)
            .execute(&mut conn)
            .await
            .expect("foreign tenant fixture cleanup should succeed");
    }
}

/// Row shape for the oauth_clients.id lookup used by the exchange tests.
#[derive(diesel::QueryableByName)]
struct TokenClientIdRow {
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
}

/// Row shape for the persisted issuance owner lookup in the pairwise exchange
/// test.
#[derive(diesel::QueryableByName)]
struct TokenOwnerRow {
    #[diesel(sql_type = diesel::sql_types::Nullable<SqlUuid>)]
    user_id: Option<Uuid>,
}
