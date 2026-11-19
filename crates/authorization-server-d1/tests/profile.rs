#![cfg(feature = "local-sqlite")]

mod support;

use futures_executor::block_on;
use jiff::{SignedDuration, Timestamp};
use nazo_auth::{
    AuthorizationDecisionCommit, AuthorizationDecisionCommitResult, AuthorizationDecisionKind,
};
use nazo_identity::{
    AccountProfileService, ProfilePatch, SessionId, SessionService, TenantId, UserId,
    ports::{LoginSessionCreate, RepositoryError},
    session::SessionRecord,
};
use nazo_oauth_server::{
    contracts::profile_account::{ProfileAccountError, ProfileAccountOperations, ProfileMe},
    domain::profile_account::ServerProfileAccountOperations,
    ports::{
        persistence::ServerPersistenceProvider, transient_state::ServerTransientStateProvider,
    },
};
use nazo_oauth_server_d1::D1Provider;
use serde_json::json;
use support::{CLIENT, TENANT, USER, fixture};
use uuid::Uuid;

fn profile_operations(provider: &D1Provider) -> ServerProfileAccountOperations {
    ServerProfileAccountOperations::new(
        SessionService::new(
            provider.sessions(),
            provider.session_accounts(),
            TenantId::new(TENANT).unwrap(),
        ),
        AccountProfileService::from_ports(
            provider.profiles(),
            provider.grant_summaries(),
            provider.authorized_applications(),
        ),
    )
}

#[test]
fn current_session_profile_reads_real_account_and_tenant_user_grant_count() {
    block_on(async {
        let (database, provider) = fixture().await;
        let session_id = SessionId::new("current-profile-session");
        let now = Timestamp::now();
        let record = SessionRecord::new(
            UserId::new(USER).unwrap(),
            0,
            now.as_second(),
            vec!["pwd".into()],
            false,
            Some("profile-oidc-session".into()),
        );
        assert_eq!(
            provider
                .login_sessions()
                .create(session_id.as_str(), &record, 600)
                .await
                .unwrap(),
            LoginSessionCreate::Created,
        );
        let operations = profile_operations(&provider);
        let ProfileMe::Active(initial) = operations.me(session_id.clone()).await.unwrap() else {
            panic!("fully authenticated session must have an active profile")
        };
        assert_eq!(initial.id, USER);
        assert_eq!(initial.email, "test@example.com");
        assert_eq!(initial.authorized_app_count, 0);

        assert_eq!(
            provider
                .authorization_repository(TENANT)
                .commit_decision(AuthorizationDecisionCommit {
                    tenant_id: TENANT,
                    user_id: USER,
                    client_id: "client".into(),
                    request_id: Uuid::new_v4().to_string(),
                    pushed_request_uri: None,
                    valid_until: now + SignedDuration::from_secs(60),
                    retain_until: now + SignedDuration::from_secs(600),
                    decision: AuthorizationDecisionKind::Approve,
                    event_id: Uuid::new_v4(),
                    occurred_at: now,
                    audit_fields: json!({"decision":"approve"}),
                    scopes: vec!["openid".into()],
                    resource_indicators: vec!["https://api.example".into()],
                    authorization_details: json!([]),
                })
                .await
                .unwrap(),
            AuthorizationDecisionCommitResult::Committed,
        );
        let other_tenant = Uuid::from_u128(10);
        let other_user = Uuid::from_u128(11);
        database.execute_sql(&format!(
            "INSERT INTO nazo_grants(tenant_id,user_id,client_id,scopes,resources,details,revision) VALUES('{other_tenant}','{USER}','{CLIENT}','[]','[]','[]','other-tenant'),('{TENANT}','{other_user}','{CLIENT}','[]','[]','[]','other-user')"
        )).unwrap();
        let ProfileMe::Active(current) = operations.me(session_id.clone()).await.unwrap() else {
            panic!("fully authenticated session must have an active profile")
        };
        assert_eq!(current.id, USER);
        assert_eq!(current.authorized_app_count, 1);
        assert!(
            provider
                .grant_summaries()
                .authorized_client_count(TenantId::new(other_tenant).unwrap(), USER)
                .await
                .is_err()
        );
        assert_eq!(
            provider
                .profiles()
                .update_profile(
                    TenantId::new(TENANT).unwrap(),
                    UserId::new(USER).unwrap(),
                    ProfilePatch::default()
                )
                .await,
            Err(RepositoryError::Unavailable),
        );

        database.execute_sql("DROP TABLE nazo_grants").unwrap();
        assert_eq!(
            operations.me(session_id).await,
            Err(ProfileAccountError::OverviewUnavailable)
        );
    });
}
