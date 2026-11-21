#![cfg(feature = "local-sqlite")]
mod support;

use futures_executor::block_on;
use jiff::{SignedDuration, Timestamp};
use nazo_auth::{
    AuthorizationDecisionCommit, AuthorizationDecisionCommitResult, AuthorizationDecisionKind,
    BackchannelLogoutOutboxPort, IdempotentBackchannelLogoutDelivery,
};
use nazo_identity::{
    AvatarContentType, AvatarObject, TenantId, UserId,
    ports::{AuthorizedApplicationRepositoryPort, AvatarRepositoryPort, AvatarStoragePort},
};
use nazo_oauth_server::ports::persistence::ServerPersistenceProvider;
use nazo_oauth_server_d1::D1Provider;
use nazo_persistence::BackchannelLogoutDeliveryStore;
use serde_json::json;
use support::{CLIENT, TENANT, USER, fixture};
use uuid::Uuid;

async fn grant(provider: &D1Provider, now: Timestamp) {
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
                audit_fields: json!({}),
                scopes: vec!["openid".into()],
                resource_indicators: vec!["https://api.example".into()],
                authorization_details: json!([]),
            })
            .await
            .unwrap(),
        AuthorizationDecisionCommitResult::Committed
    );
}
fn avatar(bytes: Vec<u8>) -> AvatarObject {
    AvatarObject {
        bytes,
        content_type: AvatarContentType::Png,
        version: Uuid::new_v4().to_string(),
    }
}
fn user() -> UserId {
    UserId::new(USER).unwrap()
}
fn tenant() -> TenantId {
    TenantId::new(TENANT).unwrap()
}

#[test]
fn grant_history_counts_atomic_approvals_and_restarts_after_revoke() {
    block_on(async {
        let (db, p) = fixture().await;
        grant(&p, Timestamp::now()).await;
        grant(&p, Timestamp::now()).await;
        let apps = p.applications_for_user(tenant(), USER).await.unwrap();
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].authorization_count, Some(2));
        assert_eq!(apps[0].last_scopes, json!(["openid"]));
        db.execute_sql(&format!("UPDATE nazo_users SET principal=json_set(principal,'$.role',json('{{\"Admin\":{{\"level\":2}}}}')) WHERE tenant_id='{TENANT}' AND id='{USER}'")).unwrap();
        let result = p
            .admin_grants()
            .revoke_by_client_id(TENANT, USER, "client", USER)
            .await
            .unwrap();
        assert_eq!(result.removed_grants, 1);
        assert_eq!(result.revoked_refresh_tokens, 0);
        assert!(
            p.applications_for_user(tenant(), USER)
                .await
                .unwrap()
                .is_empty()
        );
        grant(&p, Timestamp::now()).await;
        assert_eq!(
            p.applications_for_user(tenant(), USER).await.unwrap()[0].authorization_count,
            Some(1)
        );
        let page = p.admin_grants().page(TENANT, 10, 0).await.unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.grants.len(), 1);
    });
}

#[test]
fn legacy_grant_without_completion_history_remains_visible_without_invented_statistics() {
    block_on(async {
        let (db, p) = fixture().await;
        db.execute_sql(&format!(
            "INSERT INTO nazo_grants(tenant_id,user_id,client_id,scopes,resources,details,revision)
            VALUES('{TENANT}','{USER}','{CLIENT}','[\"openid\"]','[]','[]','legacy-device-grant');"
        ))
        .unwrap();
        // Missing history on an unmarked new write remains corruption.
        assert!(p.applications_for_user(tenant(), USER).await.is_err());
        db.execute_sql(include_str!("../migrations/0012_grant_history.sql"))
            .unwrap();
        let apps = p.applications_for_user(tenant(), USER).await.unwrap();
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].last_authorized_at, None);
        assert_eq!(apps[0].authorization_count, None);
        let now = Timestamp::now();
        grant(&p, now).await;
        let apps = p.applications_for_user(tenant(), USER).await.unwrap();
        assert_eq!(
            apps[0].last_authorized_at.unwrap().as_microsecond(),
            now.as_microsecond()
        );
        // A new known approval cannot reconstruct the lost earlier count.
        assert_eq!(apps[0].authorization_count, None);
        assert_eq!(
            p.admin_grants().page(TENANT, 10, 0).await.unwrap().grants[0].authorization_count,
            None
        );
    });
}

#[test]
fn grant_revoke_rechecks_active_admin_and_required_audit_rolls_back() {
    block_on(async {
        let (db, p) = fixture().await;
        grant(&p, Timestamp::now()).await;
        assert!(
            p.admin_grants()
                .revoke_by_client_id(TENANT, USER, "client", USER)
                .await
                .is_err()
        );
        assert_eq!(
            p.applications_for_user(tenant(), USER).await.unwrap().len(),
            1
        );
        db.execute_sql(&format!("UPDATE nazo_users SET principal=json_set(principal,'$.role',json('{{\"Admin\":{{\"level\":2}}}}')) WHERE tenant_id='{TENANT}' AND id='{USER}';
        CREATE TRIGGER reject_revoke BEFORE INSERT ON nazo_audit WHEN NEW.event_type='admin_grant_revoked' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END;")).unwrap();
        assert!(
            p.admin_grants()
                .revoke_by_client_id(TENANT, USER, "client", USER)
                .await
                .is_err()
        );
        assert_eq!(
            p.applications_for_user(tenant(), USER).await.unwrap().len(),
            1
        );
        assert!(
            p.applications_for_user(TenantId::new(Uuid::new_v4()).unwrap(), USER)
                .await
                .is_err()
        );
    });
}

#[test]
fn ignored_grant_revocation_or_required_audit_never_commits_success() {
    block_on(async {
        for trigger in [
            "CREATE TRIGGER ignore_revoke BEFORE DELETE ON nazo_grants BEGIN SELECT RAISE(IGNORE); END;",
            "CREATE TRIGGER ignore_revoke BEFORE INSERT ON nazo_audit WHEN NEW.event_type='admin_grant_revoked' BEGIN SELECT RAISE(IGNORE); END;",
        ] {
            let (db, p) = fixture().await;
            grant(&p, Timestamp::now()).await;
            db.execute_sql(&format!("UPDATE nazo_users SET principal=json_set(principal,'$.role',json('{{\"Admin\":{{\"level\":2}}}}')) WHERE tenant_id='{TENANT}' AND id='{USER}';{trigger}")).unwrap();
            assert!(
                p.admin_grants()
                    .revoke_by_client_id(TENANT, USER, "client", USER)
                    .await
                    .is_err()
            );
            assert_eq!(
                p.applications_for_user(tenant(), USER).await.unwrap().len(),
                1
            );
            db.execute_sql("SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM nazo_audit WHERE event_type='admin_grant_revoked') THEN 1 ELSE json_extract('revocation audit survived rollback','$') END").unwrap();
        }
    });
}

#[test]
fn avatar_chunk_roundtrip_cas_conflict_and_owner_cleanup() {
    block_on(async {
        let (_, p) = fixture().await;
        let first = avatar(vec![73; 150_000]);
        let first_url = format!("/auth/me/avatar?v={}", first.version);
        let mutation = p.begin_replace(user(), None, first.clone()).await.unwrap();
        let account = p
            .compare_and_set_avatar(tenant(), user(), None, 0, Some(first_url.clone()))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(account.profile.avatar_revision, 1);
        p.commit(&mutation).await.unwrap();
        assert_eq!(p.read(user(), &first.version).await.unwrap(), first);
        // An uncertain/repeated cleanup cannot delete the account's selected object.
        p.rollback(&mutation).await.unwrap();
        assert!(p.read(user(), &first.version).await.is_ok());
        assert!(
            p.compare_and_set_avatar(tenant(), user(), None, 0, Some(first_url.clone()))
                .await
                .unwrap()
                .is_some()
        );
        let stale = avatar(vec![2; 3]);
        let stale_url = format!("/auth/me/avatar?v={}", stale.version);
        let stale_mutation = p.begin_replace(user(), None, stale.clone()).await.unwrap();
        assert!(
            p.compare_and_set_avatar(tenant(), user(), None, 0, Some(stale_url))
                .await
                .unwrap()
                .is_none()
        );
        p.rollback(&stale_mutation).await.unwrap();
        assert!(p.read(user(), &stale.version).await.is_err());
        let delete = p.begin_delete(user(), Some(&first.version)).await.unwrap();
        assert!(
            p.compare_and_set_avatar(tenant(), user(), Some(&first_url), 1, None)
                .await
                .unwrap()
                .is_some()
        );
        p.commit(&delete).await.unwrap();
        assert!(p.read(user(), &first.version).await.is_err());
    });
}

#[test]
fn avatar_missing_candidate_inactive_account_and_foreign_tenant_never_publish() {
    block_on(async {
        let (db, p) = fixture().await;
        let image = avatar(vec![1]);
        let url = format!("/auth/me/avatar?v={}", image.version);
        assert!(
            p.compare_and_set_avatar(tenant(), user(), None, 0, Some(url.clone()))
                .await
                .unwrap()
                .is_none()
        );
        p.begin_replace(user(), None, image.clone()).await.unwrap();
        assert!(
            p.compare_and_set_avatar(
                TenantId::new(Uuid::new_v4()).unwrap(),
                user(),
                None,
                0,
                Some(url.clone())
            )
            .await
            .is_err()
        );
        db.execute_sql(&format!(
            "UPDATE nazo_users SET active=0 WHERE tenant_id='{TENANT}' AND id='{USER}'"
        ))
        .unwrap();
        assert!(
            p.compare_and_set_avatar(tenant(), user(), None, 0, Some(url))
                .await
                .unwrap()
                .is_none()
        );
        let duplicate = p.begin_replace(user(), None, image).await;
        assert!(duplicate.is_err());
        assert!(
            p.read(UserId::new(Uuid::new_v4()).unwrap(), "../../etc/passwd")
                .await
                .is_err()
        );
    });
}

fn notification() -> IdempotentBackchannelLogoutDelivery {
    IdempotentBackchannelLogoutDelivery {
        operation_key: Uuid::new_v4().to_string(),
        tenant_id: TENANT,
        client_id: CLIENT,
        client_public_id: "client".into(),
        logout_uri: "https://rp.example/logout".into(),
        logout_token: "signed-logout-token-fixture".into(),
        expires_at: Timestamp::now() + SignedDuration::from_secs(300),
    }
}
#[test]
fn logout_outbox_deduplicates_and_fences_reclaimed_delivery() {
    block_on(async {
        let (db, p) = fixture().await;
        let delivery = notification();
        p.enqueue_idempotent_batch(&[delivery.clone(), delivery.clone()])
            .await
            .unwrap();
        let initial = p.claim_due(20, 10).await.unwrap();
        assert_eq!(initial.len(), 1);
        assert!(p.claim_due(20, 10).await.unwrap().is_empty());
        db.execute_sql(&format!(
            "UPDATE nazo_logout_outbox SET lease_until=0 WHERE tenant_id='{TENANT}'"
        ))
        .unwrap();
        let next = p.claim_due(20, 10).await.unwrap();
        assert_eq!(next[0].attempts, initial[0].attempts + 1);
        p.complete(initial[0].id, initial[0].attempts)
            .await
            .unwrap();
        p.fail(
            next[0].id,
            next[0].attempts,
            // SQLite's clock has millisecond precision. Make this retry
            // unambiguously due instead of racing a sub-millisecond timestamp.
            Some(Timestamp::now() - SignedDuration::from_secs(1)),
            "temporary",
        )
        .await
        .unwrap();
        let retry = p.claim_due(20, 10).await.unwrap();
        assert_eq!(retry.len(), 1);
        p.complete(retry[0].id, retry[0].attempts).await.unwrap();
        assert!(p.claim_due(20, 10).await.unwrap().is_empty());
        p.enqueue_idempotent_batch(&[delivery]).await.unwrap();
        assert!(p.claim_due(20, 10).await.unwrap().is_empty());
    });
}

#[test]
fn logout_expiry_and_tenant_mismatch_fail_closed() {
    block_on(async {
        let (_, p) = fixture().await;
        let mut expired = notification();
        expired.expires_at = Timestamp::now() - SignedDuration::from_secs(1);
        p.enqueue_idempotent_batch(&[expired]).await.unwrap();
        assert!(p.claim_due(20, 10).await.unwrap().is_empty());
        let mut foreign = notification();
        foreign.tenant_id = Uuid::new_v4();
        assert!(p.enqueue_idempotent_batch(&[foreign]).await.is_err());
    });
}
