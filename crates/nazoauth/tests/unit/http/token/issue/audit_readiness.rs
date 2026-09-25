use super::*;
use nazo_oauth_server::ports::audit::{AuditFuture, SecurityAudit};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

/// Records which readiness gate the issuance path actually invoked. The
/// commit-owned Fresh path must use `ensure_transactional_ready`; every
/// issuance shape carrying earlier durable side effects must keep the full
/// `ensure_storage` preflight.
#[derive(Default)]
struct CountingSecurityAudit {
    storage_calls: AtomicU64,
    transactional_calls: AtomicU64,
}

impl CountingSecurityAudit {
    fn counts(&self) -> (u64, u64) {
        (
            AtomicU64::load(&self.storage_calls, AtomicOrdering::SeqCst),
            AtomicU64::load(&self.transactional_calls, AtomicOrdering::SeqCst),
        )
    }
}

impl SecurityAudit for CountingSecurityAudit {
    fn ensure_storage(&self) -> AuditFuture<'_> {
        Box::pin(async move {
            self.storage_calls.fetch_add(1, AtomicOrdering::SeqCst);
            Ok(())
        })
    }

    fn ensure_transactional_ready(&self) -> AuditFuture<'_> {
        Box::pin(async move {
            self.transactional_calls
                .fetch_add(1, AtomicOrdering::SeqCst);
            Ok(())
        })
    }

    fn record(&self, _: &str, _: serde_json::Map<String, serde_json::Value>) {}

    fn record_required<'a>(
        &'a self,
        _: &'a str,
        _: serde_json::Map<String, serde_json::Value>,
    ) -> AuditFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

async fn issue_counted(
    state: &TestInfrastructure,
    client: &ClientRow,
    mode: TokenIssuanceMode,
    issue: TokenIssue,
    modules: nazo_runtime_modules::ActiveModuleSnapshot,
    audit: &dyn SecurityAudit,
    repository: Option<Arc<dyn TokenRepositoryPort>>,
) -> HttpResponse {
    let service = ServerTokenService::from_port(
        repository.unwrap_or_else(|| {
            Arc::new(crate::test_support::token_issuance_repository(
                state.diesel_db.clone(),
            ))
        }),
        std::sync::Arc::new(nazo_valkey::TokenIssuanceStateAdapter::new(
            &state.valkey_connection(),
        )),
        state.keyset.clone(),
    );
    let config = token_issuance_config(state.settings.as_ref());
    let authorization = test_support::test_authorization_service(state);
    present_token_result(
        nazo_oauth_server::token::issue::issue_token_response(
            &TokenIssuanceContext {
                config: &config,
                modules: &modules,
                authorization: &authorization,
                security_audit: audit,
                remote_client_documents: crate::test_support::test_remote_client_documents(),
            },
            &service,
            client,
            mode,
            issue,
        )
        .await,
    )
}

async fn issue_counted_fresh(
    state: &TestInfrastructure,
    client: &ClientRow,
    issue: TokenIssue,
    audit: &dyn SecurityAudit,
) -> HttpResponse {
    issue_counted(
        state,
        client,
        TokenIssuanceMode::Fresh,
        issue,
        state.active_module_snapshot(),
        audit,
        None,
    )
    .await
}

/// The conservative eligibility predicate: commit-owned Fresh issuance
/// with no refresh bookkeeping, no authorization-code consumption and no
/// Native SSO device-secret write relies on the commit transaction for the
/// writer check, so the static per-request probe is elided.
#[actix_web::test]
async fn commit_owned_fresh_issuance_uses_transactional_readiness() {
    let Some(state) = issue_state_with_live_database() else {
        return;
    };
    let mut client = client_with_grants(&["client_credentials"]);
    client.client_id = format!("audit-ready-fresh-{}", Uuid::now_v7());
    insert_issue_client(&state, &client).await;
    let mut issue = token_issue_without_openid();
    issue.user_id = None;
    issue.subject = client.client_id.clone();
    issue.scopes = vec!["accounts".to_owned()];
    issue.include_refresh = false;
    let audit = CountingSecurityAudit::default();

    let response = issue_counted_fresh(&state, &client, issue, &audit).await;

    assert_eq!(response.status(), StatusCode::OK);
    let value: Value = serde_json::from_slice(&response_body(response).await)
        .expect("token response should be JSON");
    assert!(value.get("access_token").is_some());
    assert_eq!(
        audit.counts(),
        (0, 1),
        "commit-owned Fresh issuance must take the transactional gate once"
    );
}

/// Refresh issuance carries family/spent bookkeeping alongside the commit,
/// so it keeps the full storage preflight.
#[actix_web::test]
async fn refresh_issuance_keeps_the_full_storage_preflight() {
    let Some(state) = issue_state_with_live_database() else {
        return;
    };
    let mut client = client_with_grants(&["client_credentials", "refresh_token"]);
    client.client_id = format!("audit-ready-refresh-{}", Uuid::now_v7());
    insert_issue_client(&state, &client).await;
    let mut issue = token_issue_without_openid();
    issue.user_id = None;
    issue.subject = client.client_id.clone();
    issue.scopes = vec!["accounts".to_owned(), "offline_access".to_owned()];
    issue.include_refresh = true;
    let audit = CountingSecurityAudit::default();

    let response = issue_counted_fresh(&state, &client, issue, &audit).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        audit.counts(),
        (1, 0),
        "refresh issuance must keep ensure_storage"
    );
}

/// Authorization-code (single-use) redemption consumes grant state and is
/// not commit-owned Fresh issuance.
#[actix_web::test]
async fn single_use_issuance_keeps_the_full_storage_preflight() {
    let Some(state) = issue_state_with_live_database() else {
        return;
    };
    let mut client = client_with_grants(&["authorization_code"]);
    client.client_id = format!("audit-ready-single-{}", Uuid::now_v7());
    insert_issue_client(&state, &client).await;
    let mut issue = token_issue_without_openid();
    issue.user_id = None;
    issue.subject = client.client_id.clone();
    issue.scopes = vec!["accounts".to_owned()];
    issue.include_refresh = false;
    issue.authorization_code_hash = Some(format!("code-hash-{}", Uuid::now_v7()));
    let audit = CountingSecurityAudit::default();

    let response = issue_counted(
        &state,
        &client,
        TokenIssuanceMode::SingleUse {
            grant_key: format!("grant-{}", Uuid::now_v7()),
            grant_expires_at: Utc::now() + chrono::Duration::minutes(5),
        },
        issue,
        state.active_module_snapshot(),
        &audit,
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        audit.counts(),
        (1, 0),
        "single-use issuance must keep ensure_storage"
    );
}

/// Native SSO persists the device secret before the final commit, so the
/// path keeps the full storage preflight even though it also commits a
/// `token_issued` event transactionally.
#[actix_web::test]
async fn native_sso_issuance_keeps_the_full_storage_preflight() {
    let Some(state) = issue_state_with_live_database() else {
        return;
    };
    state
        .valkey
        .init()
        .await
        .expect("live Native SSO fixture should connect to Valkey");
    let mut client = client_with_grants(&["authorization_code", "refresh_token"]);
    client.client_id = format!("audit-ready-sso-{}", Uuid::now_v7());
    let user_id = Uuid::now_v7();
    insert_issue_client(&state, &client).await;
    insert_issue_user(&state, user_id).await;
    let mut modules = state.active_module_snapshot();
    modules
        .accepting
        .insert(nazo_runtime_modules::ModuleId::NativeSso);

    let mut issue = token_issue_with_sid(vec!["sid".to_owned()]);
    issue.user_id = Some(user_id);
    issue.subject = user_id.to_string();
    issue.scopes = vec!["openid".to_owned(), "offline_access".to_owned()];
    issue.include_refresh = true;
    issue.native_sso = Some(NativeSsoTokenBinding {
        device_secret: format!("device-secret-{}", Uuid::now_v7()),
        ds_hash: "device-hash".to_owned(),
        sid: "audit-ready-sso-sid".to_owned(),
    });
    let audit = CountingSecurityAudit::default();

    let response = issue_counted(
        &state,
        &client,
        TokenIssuanceMode::Fresh,
        issue,
        modules,
        &audit,
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        audit.counts(),
        (1, 0),
        "Native SSO persists device state before commit and must keep \
         ensure_storage"
    );
}

/// The core fail-closed proof: with the candidate path active (no
/// per-request writer probe), revoking EXECUTE on the audit append
/// function mid-run must make the commit fail — no token is returned, no
/// issuance row, no audit event, no outbox row, and the pool is left
/// without an open transaction.
#[actix_web::test]
async fn revoked_audit_append_execute_fails_the_candidate_commit() {
    let Some(database_url) = std::env::var("DATABASE_URL").ok() else {
        return;
    };
    let Some(state) = issue_state_with_live_database() else {
        return;
    };
    let mut client = client_with_grants(&["client_credentials"]);
    client.client_id = format!("audit-revoke-{}", Uuid::now_v7());
    insert_issue_client(&state, &client).await;

    let role = format!("nazotest_revoke_{}", Uuid::now_v7().simple());
    let password = Uuid::now_v7().simple().to_string();
    // The fixture pool is capped at one connection and stays available for
    // row-count verification, so privilege administration runs on its own
    // dedicated connection.
    let mut admin = AsyncPgConnection::establish(&database_url)
        .await
        .expect("admin connection should be available");
    sql_query(format!(
        "CREATE ROLE \"{role}\" LOGIN PASSWORD '{password}' NOSUPERUSER NOBYPASSRLS NOINHERIT"
    ))
    .execute(&mut admin)
    .await
    .expect("restricted role should be creatable");
    sql_query(format!("GRANT CONNECT ON DATABASE oauth TO \"{role}\""))
        .execute(&mut admin)
        .await
        .expect("connect grant should apply");
    nazo_postgres::configure_runtime_role(&database_url, &role)
        .await
        .expect("the production grant path should configure the role");

    let restricted_url = {
        let mut url = url::Url::parse(&database_url).expect("DATABASE_URL should parse");
        url.set_username(&role).expect("username should set");
        url.set_password(Some(&password))
            .expect("password should set");
        url.to_string()
    };
    let restricted_pool = create_pool(&restricted_url, 2).expect("restricted pool should build");
    let repository: Arc<dyn TokenRepositoryPort> = Arc::new(
        nazo_postgres::TokenIssuanceRepository::new(restricted_pool.clone()),
    );
    let audit = CountingSecurityAudit::default();
    let fresh_issue = |subject: String| {
        let mut issue = token_issue_without_openid();
        issue.user_id = None;
        issue.subject = subject;
        issue.scopes = vec!["accounts".to_owned()];
        issue.include_refresh = false;
        issue
    };

    // Sanity: the restricted runtime role completes the candidate path.
    let first = issue_counted(
        &state,
        &client,
        TokenIssuanceMode::Fresh,
        fresh_issue(format!("{}-first", client.client_id)),
        state.active_module_snapshot(),
        &audit,
        Some(repository.clone()),
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(
        audit.counts(),
        (0, 1),
        "candidate path used the transactional gate"
    );
    let baseline_rows = token_issuance_row_count(&state, &client).await;

    // Revoke the append capability after the successful start.
    sql_query(format!(
        "REVOKE EXECUTE ON FUNCTION \
         public.nazo_persist_security_audit_event(UUID, TEXT, TEXT, JSONB, TIMESTAMPTZ) \
         FROM \"{role}\""
    ))
    .execute(&mut admin)
    .await
    .expect("EXECUTE revoke should apply");

    let second = issue_counted(
        &state,
        &client,
        TokenIssuanceMode::Fresh,
        fresh_issue(format!("{}-second", client.client_id)),
        state.active_module_snapshot(),
        &audit,
        Some(repository.clone()),
    )
    .await;

    assert_eq!(second.status(), StatusCode::SERVICE_UNAVAILABLE);
    let value: Value = serde_json::from_slice(&response_body(second).await)
        .expect("OAuth error body should be JSON");
    assert_eq!(
        value.get("error").and_then(serde_json::Value::as_str),
        Some("server_error")
    );
    assert!(value.get("access_token").is_none());
    assert_eq!(
        token_issuance_row_count(&state, &client).await,
        baseline_rows,
        "the failed commit must not leave a second issuance row"
    );
    // No half audit row or outbox entry for the failed issuance: count the
    // committed token_issued events for this client through the admin role.
    let mut verify = get_conn(&state.diesel_db)
        .await
        .expect("verification connection should be available");
    let audit_rows = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM security_audit_events \
         WHERE event_type = 'token_issued' AND payload->>'client_id' = $1",
    )
    .bind::<Text, _>(client.client_id.clone())
    .get_result::<TokenRowCount>(&mut verify)
    .await
    .expect("audit count should load")
    .count;
    assert_eq!(
        audit_rows, 1,
        "only the pre-revoke committed event may exist"
    );
    let open_transactions = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM pg_stat_activity \
         WHERE usename = $1 AND state = 'idle in transaction'",
    )
    .bind::<Text, _>(role.clone())
    .get_result::<TokenRowCount>(&mut verify)
    .await
    .expect("open-transaction count should load")
    .count;
    assert_eq!(
        open_transactions, 0,
        "the failed commit must not return an open transaction to the pool"
    );

    // Recovery: re-grant and prove the same pool commits again.
    sql_query(format!(
        "GRANT EXECUTE ON FUNCTION \
         public.nazo_persist_security_audit_event(UUID, TEXT, TEXT, JSONB, TIMESTAMPTZ) \
         TO \"{role}\""
    ))
    .execute(&mut admin)
    .await
    .expect("EXECUTE grant should reapply");
    let third = issue_counted(
        &state,
        &client,
        TokenIssuanceMode::Fresh,
        fresh_issue(format!("{}-third", client.client_id)),
        state.active_module_snapshot(),
        &audit,
        Some(repository),
    )
    .await;
    assert_eq!(
        third.status(),
        StatusCode::OK,
        "the pool must recover once the capability is restored"
    );
    assert_eq!(audit.counts(), (0, 3));

    drop(restricted_pool);
    sql_query(format!("REVOKE ALL ON DATABASE oauth FROM \"{role}\""))
        .execute(&mut admin)
        .await
        .expect("database grant should be revoked");
    sql_query(format!("DROP OWNED BY \"{role}\""))
        .execute(&mut admin)
        .await
        .expect("owned privileges should be dropped");
    sql_query(format!("DROP ROLE \"{role}\""))
        .execute(&mut admin)
        .await
        .expect("restricted role should be dropped");
}
