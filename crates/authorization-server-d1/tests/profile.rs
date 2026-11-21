#![cfg(feature = "local-sqlite")]

mod support;

use futures_executor::block_on;
use jiff::{SignedDuration, Timestamp};
use nazo_auth::{
    AuthorizationDecisionCommit, AuthorizationDecisionCommitResult, AuthorizationDecisionKind,
};
use nazo_identity::{
    AccountProfileService, AvatarContentType, AvatarObject, ProfilePatch, SessionId,
    SessionService, TenantId, UserId,
    ports::{AvatarRepositoryPort, LoginSessionCreate, RepositoryError},
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
fn r2_avatar_cas_only_selects_ready_versions_and_fences_retirement() {
    block_on(async {
        let (_database, provider) = fixture().await;
        let tenant = TenantId::new(TENANT).unwrap();
        let user = UserId::new(USER).unwrap();
        let candidate = AvatarObject {
            bytes: vec![1, 2, 3],
            content_type: AvatarContentType::Png,
            version: Uuid::new_v4().to_string(),
        };
        let url = format!("/auth/me/avatar?v={}", candidate.version);
        provider.prepare_r2_avatar(user, &candidate).await.unwrap();
        assert!(
            provider
                .compare_and_set_avatar(tenant, user, None, 0, Some(url.clone()))
                .await
                .unwrap()
                .is_none()
        );
        provider
            .publish_r2_avatar(user, &candidate.version)
            .await
            .unwrap();
        assert!(
            provider
                .compare_and_set_avatar(tenant, user, None, 0, Some(url.clone()))
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            !provider
                .retire_r2_avatar(user, &candidate.version)
                .await
                .unwrap()
        );

        assert!(
            provider
                .compare_and_set_avatar(tenant, user, Some(&url), 1, None)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            provider
                .retire_r2_avatar(user, &candidate.version)
                .await
                .unwrap()
        );
        assert!(
            provider
                .compare_and_set_avatar(tenant, user, None, 2, Some(url))
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            provider.stale_r2_avatars().await.unwrap(),
            [(user, candidate.version.clone())]
        );
        provider
            .forget_retired_r2_avatar(user, &candidate.version)
            .await
            .unwrap();
        assert!(provider.stale_r2_avatars().await.unwrap().is_empty());
    });
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
                    ProfilePatch {
                        display_name: Some("Updated name".into()),
                        ..Default::default()
                    },
                )
                .await
                .unwrap()
                .profile
                .display_name
                .as_deref(),
            Some("Updated name")
        );

        database.execute_sql("DROP TABLE nazo_grants").unwrap();
        assert_eq!(
            operations.me(session_id).await,
            Err(ProfileAccountError::OverviewUnavailable)
        );
    });
}

#[test]
fn profile_updates_preserve_identity_and_only_keep_verification_for_the_same_phone() {
    block_on(async {
        let (database, provider) = fixture().await;
        database
            .execute_sql(&format!(
                "UPDATE nazo_users SET claims=json_set(claims,'$.phone_number','+8613800000000',
                '$.phone_number_verified',json('true'),'$.picture','https://images.example/avatar',
                '$.email_verified',json('true')),epoch=7,avatar_revision=3
             WHERE tenant_id='{TENANT}' AND id='{USER}'"
            ))
            .unwrap();
        let profiles = provider.profiles();
        let update = ProfilePatch {
            display_name: Some("New display".into()),
            given_name: Some("Given".into()),
            phone_number: Some("+8613800000000".into()),
            address_locality: Some("Shenzhen".into()),
            ..Default::default()
        };
        let before = Timestamp::now().as_second();
        let updated = profiles
            .update_profile(
                TenantId::new(TENANT).unwrap(),
                UserId::new(USER).unwrap(),
                update,
            )
            .await
            .unwrap();
        assert_eq!(updated.account.email, "test@example.com");
        assert_eq!(updated.account.username, "test");
        assert!(updated.account.email_verified);
        assert_eq!(updated.principal.authorization_epoch, 7);
        assert_eq!(updated.profile.avatar_revision, 3);
        assert_eq!(
            updated.profile.avatar_url.as_deref(),
            Some("https://images.example/avatar")
        );
        assert_eq!(updated.profile.display_name.as_deref(), Some("New display"));
        assert_eq!(
            updated.profile.address.locality.as_deref(),
            Some("Shenzhen")
        );
        assert!(updated.profile.phone_number_verified);
        assert!(updated.updated_at.as_second() >= before);

        let changed = profiles
            .update_profile(
                TenantId::new(TENANT).unwrap(),
                UserId::new(USER).unwrap(),
                ProfilePatch {
                    phone_number: Some("+8613900000000".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(!changed.profile.phone_number_verified);
        assert!(changed.profile.display_name.is_none());
        assert_eq!(changed.profile.address, Default::default());
        assert_eq!(changed.profile.avatar_revision, 3);
        assert_eq!(changed.principal.authorization_epoch, 7);
    });
}

#[test]
fn profile_mutation_rejects_other_tenants_missing_users_and_inactive_accounts() {
    block_on(async {
        let (database, provider) = fixture().await;
        let profiles = provider.profiles();
        assert!(
            profiles
                .update_profile(
                    TenantId::new(Uuid::from_u128(999)).unwrap(),
                    UserId::new(USER).unwrap(),
                    ProfilePatch::default(),
                )
                .await
                .is_err()
        );
        assert_eq!(
            profiles
                .update_profile(
                    TenantId::new(TENANT).unwrap(),
                    UserId::new(Uuid::from_u128(999)).unwrap(),
                    ProfilePatch::default(),
                )
                .await,
            Err(RepositoryError::NotFound)
        );
        database
            .execute_sql(&format!(
                "UPDATE nazo_users SET active=0 WHERE tenant_id='{TENANT}' AND id='{USER}'"
            ))
            .unwrap();
        assert_eq!(
            profiles
                .update_profile(
                    TenantId::new(TENANT).unwrap(),
                    UserId::new(USER).unwrap(),
                    ProfilePatch::default(),
                )
                .await,
            Err(RepositoryError::NotFound)
        );
    });
}
