use super::*;

async fn wait_for_issuance_commit_lock(
    observer: &mut AsyncPgConnection,
    blocking_backend_pid: i64,
    issuer: &mut tokio::task::JoinHandle<(StatusCode, String)>,
) {
    let deadline = std::time::Instant::now() + StdDuration::from_secs(5);
    while std::time::Instant::now() < deadline {
        let blocked = sql_query(
            "SELECT COUNT(*)::bigint AS count FROM pg_stat_activity WHERE $1::bigint = ANY(pg_blocking_pids(pid))",
        )
        .bind::<BigInt, _>(blocking_backend_pid)
        .get_result::<TokenRowCount>(observer)
        .await
        .expect("blocked token issuance should be observable");
        if blocked.count > 0 {
            return;
        }
        tokio::select! {
            result = &mut *issuer => panic!(
                "issuance ended before blocking on the principal row lock: {result:?}"
            ),
            () = tokio::task::yield_now() => {}
        }
    }
    panic!("timed out waiting for token issuance to block on the principal row lock");
}

async fn insert_issue_user_with_invalid_principal_metadata(
    state: &TestInfrastructure,
    user_id: Uuid,
) {
    insert_issue_user(state, user_id).await;
    let mut connection = get_conn(&state.diesel_db)
        .await
        .expect("issue test database connection should be available");
    sql_query("UPDATE users SET role = 'user', admin_level = 1 WHERE tenant_id = $1 AND id = $2")
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<SqlUuid, _>(user_id)
        .execute(&mut connection)
        .await
        .expect("issue test user metadata corruption should succeed");
}

#[actix_web::test]
async fn openid_issue_without_user_subject_fails_before_token_signing() {
    let state = issue_state_with_invalid_signing_key();
    let client = client_with_grants(&["authorization_code"]);
    let mut issue = token_issue_with_sid(Vec::new());
    issue.user_id = None;
    issue.authorization_code_hash = Some("code-hash".to_owned());

    let response = issue_token_response(&state, &client, issue).await;

    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should collect");
    let value: Value = serde_json::from_slice(&body).expect("OAuth error body should be JSON");
    assert_eq!(status, StatusCode::BAD_REQUEST, "{value}");
    assert_eq!(value.get("error"), Some(&json!("invalid_grant")));
    assert!(value.get("access_token").is_none());
    assert!(value.get("refresh_token").is_none());
    assert!(value.get("id_token").is_none());
}

#[actix_web::test]
async fn client_credentials_issue_returns_minimal_bearer_token_response_without_oidc_artifacts() {
    let Some(state) = issue_state_with_live_database() else {
        return;
    };
    let mut client = client_with_grants(&["client_credentials"]);
    client.client_id = format!("issue-client-credentials-{}", Uuid::now_v7());
    insert_issue_client(&state, &client).await;
    let mut issue = token_issue_without_openid();
    issue.user_id = None;
    issue.subject = client.client_id.clone();
    issue.scopes = vec!["accounts".to_owned(), "read".to_owned()];
    issue.include_refresh = false;
    issue.auth_time = None;
    issue.amr = Vec::new();

    let response = issue_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        HeaderValue::from_static("no-store")
    );
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should collect");
    let value: Value = serde_json::from_slice(&body).expect("token response should be JSON");
    assert_eq!(value["token_type"], "Bearer");
    assert_eq!(
        value["expires_in"],
        state.settings.protocol.access_token_ttl_seconds
    );
    assert_eq!(value["scope"], "accounts read");
    assert!(
        value["access_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );
    assert!(value.get("id_token").is_none());
    assert!(value.get("refresh_token").is_none());
}

#[actix_web::test]
async fn non_oidc_user_issuance_skips_subject_claims_and_rechecks_principal_at_commit() {
    let Some(state) = issue_state_with_live_database() else {
        return;
    };
    let mut client = client_with_grants(&["client_credentials"]);
    client.client_id = format!("issue-non-oidc-subject-{}", Uuid::now_v7());
    insert_issue_client(&state, &client).await;
    let user_id = Uuid::now_v7();
    insert_issue_user(&state, user_id).await;
    let repository = std::sync::Arc::new(crate::test_support::CountingTokenRepository::new(
        std::sync::Arc::new(crate::test_support::token_issuance_repository(
            state.diesel_db.clone(),
        )),
    ));
    let mut issue = token_issue_without_openid();
    issue.user_id = Some(user_id);
    issue.subject = format!("pairwise-subject-{user_id}");
    issue.include_refresh = false;

    let response =
        issue_token_response_with_repository(&state, &client, issue, repository.clone()).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        repository.subject_data_reads(),
        0,
        "non-OIDC issuance must not load subject claims"
    );

    {
        let mut connection = get_conn(&state.diesel_db)
            .await
            .expect("issue test database connection should be available");
        sql_query("UPDATE users SET is_active = FALSE WHERE tenant_id = $1 AND id = $2")
            .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
            .bind::<SqlUuid, _>(user_id)
            .execute(&mut connection)
            .await
            .expect("issue test user deactivation should succeed");
    }

    let mut retry = token_issue_without_openid();
    retry.user_id = Some(user_id);
    retry.subject = format!("pairwise-subject-{user_id}");
    retry.include_refresh = false;
    let response =
        issue_token_response_with_repository(&state, &client, retry, repository.clone()).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(response).await, "invalid_grant");
    assert_eq!(
        repository.subject_data_reads(),
        0,
        "the commit principal recheck must not load subject claims"
    );
}

#[actix_web::test]
async fn issuance_rechecks_principal_deactivation_before_commit() {
    let Some(state) = issue_state_with_live_database_pool_size(3) else {
        return;
    };
    let database_url =
        std::env::var("DATABASE_URL").expect("live issue fixture must provide DATABASE_URL");
    for (principal, deactivation_sql, expected_error) in [
        (
            "client",
            "UPDATE oauth_clients SET is_active = FALSE WHERE id = $1",
            "unauthorized_client",
        ),
        (
            "subject",
            "UPDATE users SET is_active = FALSE WHERE id = $1",
            "invalid_grant",
        ),
    ] {
        let mut client = client_with_grants(&["client_credentials"]);
        client.client_id = format!("issue-principal-race-{principal}-{}", Uuid::now_v7());
        let user_id = Uuid::now_v7();
        insert_issue_client(&state, &client).await;
        insert_issue_user(&state, user_id).await;

        let mut issue = token_issue_without_openid();
        issue.user_id = Some(user_id);
        issue.subject = user_id.to_string();
        issue.include_refresh = false;

        let principal_id = if principal == "client" {
            client.id
        } else {
            user_id
        };
        let mut coordinator = AsyncPgConnection::establish(&database_url)
            .await
            .expect("principal lock coordinator should connect");
        let mut observer = AsyncPgConnection::establish(&database_url)
            .await
            .expect("principal lock observer should connect");
        sql_query("BEGIN")
            .execute(&mut coordinator)
            .await
            .expect("principal lock transaction should begin");
        let locked = sql_query(
            "SELECT 1::bigint AS count FROM oauth_clients WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
        )
        .bind::<SqlUuid, _>(client.tenant_id)
        .bind::<SqlUuid, _>(client.id)
        .get_result::<TokenRowCount>(&mut coordinator)
        .await
        .expect("active client fixture should lock");
        assert_eq!(locked.count, 1);
        let blocking_backend_pid = sql_query("SELECT pg_backend_pid()::bigint AS count")
            .get_result::<TokenRowCount>(&mut coordinator)
            .await
            .expect("principal lock backend pid should load")
            .count;

        let issue_state = state.clone();
        let issue_client = client.clone();
        let mut issuer = actix_web::rt::spawn(async move {
            let response = issue_token_response(&issue_state, &issue_client, issue).await;
            (response.status(), oauth_error_code(response).await)
        });
        wait_for_issuance_commit_lock(&mut observer, blocking_backend_pid, &mut issuer).await;

        let changed = sql_query(deactivation_sql)
            .bind::<SqlUuid, _>(principal_id)
            .execute(&mut coordinator)
            .await
            .expect("principal deactivation should update its locked row");
        assert_eq!(changed, 1);
        sql_query("COMMIT")
            .execute(&mut coordinator)
            .await
            .expect("principal deactivation should commit");

        let (status, error) = issuer.await.expect("issuance task should join");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(error, expected_error);
        assert_eq!(
            token_issuance_row_count(&state, &client).await,
            0,
            "issuance must not persist after {principal} deactivation"
        );
    }
}

#[actix_web::test]
async fn openid_issue_with_active_user_emits_id_and_refresh_tokens() {
    let Some(state) = issue_state_with_live_database() else {
        return;
    };
    let mut client = client_with_grants(&["authorization_code", "refresh_token"]);
    client.client_id = format!("issue-client-{}", Uuid::now_v7());
    let user_id = Uuid::now_v7();
    insert_issue_client(&state, &client).await;
    insert_issue_user(&state, user_id).await;
    let mut issue = token_issue_with_sid(vec!["sid".to_owned()]);
    issue.user_id = Some(user_id);
    issue.subject = user_id.to_string();
    issue.scopes = vec!["openid".to_owned(), "offline_access".to_owned()];
    issue.include_refresh = true;
    issue.oidc_sid = Some("issue-session-sid".to_owned());

    let response = issue_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_body(response).await;
    let value: Value = serde_json::from_slice(&body).expect("token response should be JSON");
    assert!(
        value["access_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );
    assert!(
        value["id_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );
    assert!(
        value["refresh_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );
    assert_eq!(value["token_type"], "Bearer");
}

#[actix_web::test]
async fn id_token_subject_load_failure_does_not_issue_oidc_response() {
    let state = issue_state_with_valid_signing_key();
    let client = client_with_grants(&["authorization_code"]);
    let mut issue = token_issue_with_sid(Vec::new());
    issue.user_id = Some(Uuid::now_v7());
    issue.subject = "subject-1".to_owned();
    issue.include_refresh = false;

    let response = issue_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should collect");
    let value: Value = serde_json::from_slice(&body).expect("OAuth error body should be JSON");
    assert_eq!(
        value
            .get("error")
            .and_then(serde_json::Value::as_str)
            .expect("OAuth JSON should contain an error code"),
        "server_error"
    );
    assert!(value.get("id_token").is_none());
    assert!(value.get("refresh_token").is_none());
}

#[actix_web::test]
async fn missing_id_token_subject_fails_closed_without_returning_credentials() {
    let Some(state) = issue_state_with_live_database() else {
        return;
    };
    let mut client = client_with_grants(&["authorization_code"]);
    client.client_id = format!("missing-subject-client-{}", Uuid::now_v7());
    insert_issue_client(&state, &client).await;
    let mut issue = token_issue_with_sid(vec!["sid".to_owned()]);
    let missing_user_id = Uuid::now_v7();
    issue.user_id = Some(missing_user_id);
    issue.subject = missing_user_id.to_string();
    issue.include_refresh = false;

    let response = issue_token_response(&state, &client, issue).await;

    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should collect");
    let value: Value = serde_json::from_slice(&body).expect("OAuth error body should be JSON");
    assert_eq!(status, StatusCode::BAD_REQUEST, "{value}");
    assert_eq!(value.get("error"), Some(&json!("invalid_grant")));
    assert!(value.get("access_token").is_none());
    assert!(value.get("refresh_token").is_none());
    assert!(value.get("id_token").is_none());
}

#[actix_web::test]
async fn refresh_issue_rejects_missing_essential_id_token_claims() {
    let Some(state) = issue_state_with_live_database() else {
        return;
    };
    let mut client = client_with_grants(&["authorization_code"]);
    client.client_id = format!("issue-essential-{}", Uuid::now_v7());
    let user_id = Uuid::now_v7();
    insert_issue_client(&state, &client).await;
    insert_issue_user(&state, user_id).await;

    let mut issue = token_issue_with_sid(Vec::new());
    issue.user_id = Some(user_id);
    issue.subject = user_id.to_string();
    issue.refresh_token_scopes = Some(vec!["openid".to_owned()]);
    issue.id_token_claim_requests = vec![OidcClaimRequest {
        name: "department".to_owned(),
        essential: true,
        value: None,
        values: Vec::new(),
    }];

    let response = issue_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let value: Value = serde_json::from_slice(&response_body(response).await)
        .expect("OAuth error body should be JSON");
    assert_eq!(
        value
            .get("error")
            .and_then(serde_json::Value::as_str)
            .expect("OAuth JSON should contain an error code"),
        "invalid_grant"
    );
    assert_eq!(value["error"], "invalid_grant");
    assert!(value.get("id_token").is_none());
}

#[actix_web::test]
async fn malformed_active_subject_claims_fail_closed_before_id_token_signing() {
    let Some(state) = issue_state_with_live_database() else {
        return;
    };
    let mut client = client_with_grants(&["authorization_code"]);
    client.client_id = format!("invalid-subject-claims-{}", Uuid::now_v7());
    let user_id = Uuid::now_v7();
    insert_issue_client(&state, &client).await;
    insert_issue_user_with_invalid_principal_metadata(&state, user_id).await;
    let mut issue = token_issue_with_sid(Vec::new());
    issue.user_id = Some(user_id);
    issue.subject = user_id.to_string();
    issue.include_refresh = false;

    let response = issue_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let value: Value = serde_json::from_slice(&response_body(response).await)
        .expect("OAuth error body should be JSON");
    assert_eq!(
        value
            .get("error")
            .and_then(serde_json::Value::as_str)
            .expect("OAuth JSON should contain an error code"),
        "server_error"
    );
    assert_eq!(value["error"], "server_error");
    assert!(value.get("id_token").is_none());
}
