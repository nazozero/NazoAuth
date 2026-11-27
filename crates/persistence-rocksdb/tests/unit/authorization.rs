use super::*;
use crate::db::{put, read};
use nazo_identity::{OrganizationId, RealmId, TenantContext, UserId, UserRole};
use std::path::PathBuf;

struct Fixture {
    db: Option<RocksDb>,
    path: PathBuf,
    tenant: Uuid,
    client: Uuid,
    user: Uuid,
}
impl Fixture {
    fn new() -> Self {
        let tenant = Uuid::new_v4();
        let client = Uuid::new_v4();
        let user = Uuid::new_v4();
        let path =
            std::env::temp_dir().join(format!("nazo-rocksdb-authorization-{}", Uuid::new_v4()));
        let db = RocksDb::open(&path).unwrap().for_tenant(tenant);
        let context = TenantContext {
            tenant_id: TenantId::new(tenant).unwrap(),
            realm_id: RealmId::new(Uuid::new_v4()).unwrap(),
            organization_id: OrganizationId::new(Uuid::new_v4()).unwrap(),
        };
        let tx = db.transaction();
        put(&tx, &key(CLIENT_PUBLIC_ID, tenant, b"client"), &client).unwrap();
        put(
            &tx,
            &key(CLIENT_PRINCIPAL, tenant, client.as_bytes()),
            &ClientPrincipal {
                id: client,
                public_id: "client".into(),
                client_type: "confidential".into(),
                active: true,
                epoch: 0,
                tenant: context,
            },
        )
        .unwrap();
        put(
            &tx,
            &key(USER_PRINCIPAL, tenant, user.as_bytes()),
            &Principal {
                authorization_epoch: 0,
                user_id: UserId::new(user).unwrap(),
                tenant: context,
                role: UserRole::User,
                active: true,
            },
        )
        .unwrap();
        tx.commit().unwrap();
        Self {
            db: Some(db),
            path,
            tenant,
            client,
            user,
        }
    }
    fn db(&self) -> &RocksDb {
        self.db.as_ref().unwrap()
    }
    fn decision(
        &self,
        request: &str,
        decision: AuthorizationDecisionKind,
    ) -> AuthorizationDecisionCommit {
        let now = Timestamp::now();
        AuthorizationDecisionCommit {
            tenant_id: self.tenant,
            user_id: self.user,
            user_epoch: 0,
            client_id: "client".into(),
            request_id: request.into(),
            pushed_request_uri: None,
            valid_until: now + jiff::SignedDuration::from_secs(30),
            retain_until: now + jiff::SignedDuration::from_secs(300),
            decision,
            event_id: Uuid::now_v7(),
            occurred_at: now,
            audit_fields: if decision == AuthorizationDecisionKind::Deny {
                json!({})
            } else {
                json!({"code_id":"code-identity","code_hash":"a".repeat(64),"code_payload_digest":"b".repeat(64)})
            },
            scopes: vec!["openid".into()],
            resource_indicators: vec!["https://api.example.test".into()],
            authorization_details: json!([]),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        drop(self.db.take());
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[tokio::test]
async fn prompt_none_rechecks_grant_and_does_not_consume_on_rejection() {
    let fixture = Fixture::new();
    let prompt = fixture.decision("request", AuthorizationDecisionKind::PromptNone);
    assert_eq!(
        fixture.db().commit_decision(prompt.clone()).await.unwrap(),
        AuthorizationDecisionCommitResult::GrantUnavailable
    );
    let mut approval = fixture.decision("request", AuthorizationDecisionKind::Approve);
    let event_id = approval.event_id;
    approval.audit_fields["raw_secret"] = json!("must-not-export");
    assert_eq!(
        fixture.db().commit_decision(approval).await.unwrap(),
        AuthorizationDecisionCommitResult::Committed
    );
    let grant = fixture
        .db()
        .grant(fixture.user, fixture.client)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(grant.scopes, json!(["openid"]));
    assert_eq!(
        fixture.db().commit_decision(prompt).await.unwrap(),
        AuthorizationDecisionCommitResult::Conflict
    );
    let event: Value = read(
        &fixture.db().db,
        &key(crate::audit::EVENTS, Uuid::nil(), event_id.as_bytes()),
    )
    .unwrap()
    .unwrap();
    assert!(event["payload"].get("raw_secret").is_none());
    let mut fresh = fixture.decision("fresh", AuthorizationDecisionKind::PromptNone);
    fresh.scopes.push("email".into());
    assert_eq!(
        fixture.db().commit_decision(fresh).await.unwrap(),
        AuthorizationDecisionCommitResult::GrantUnavailable
    );
    assert_eq!(
        fixture
            .db()
            .commit_decision(fixture.decision("fresh", AuthorizationDecisionKind::PromptNone))
            .await
            .unwrap(),
        AuthorizationDecisionCommitResult::Committed
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_par_has_one_accepting_decision() {
    let fixture = Fixture::new();
    let mut left = fixture.decision("left", AuthorizationDecisionKind::Approve);
    let mut right = fixture.decision("right", AuthorizationDecisionKind::Approve);
    left.pushed_request_uri = Some("urn:ietf:params:oauth:request_uri:one".into());
    right.pushed_request_uri = left.pushed_request_uri.clone();
    let (a, b) = tokio::join!(
        fixture.db().commit_decision(left),
        fixture.db().commit_decision(right)
    );
    let outcomes = [a.unwrap(), b.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| **o == AuthorizationDecisionCommitResult::Committed)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| **o == AuthorizationDecisionCommitResult::Conflict)
            .count(),
        1
    );
    let grant: GrantRecord = read(
        &fixture.db().db,
        &grants::grant_key(fixture.tenant, fixture.user, fixture.client),
    )
    .unwrap()
    .unwrap();
    assert_eq!(grant.authorization_count, 1);
}

#[tokio::test]
async fn deadline_is_checked_after_waiting_for_authority_locks() {
    let fixture = Fixture::new();
    let tx = fixture.db().transaction();
    let _ = read_tx::<Principal>(
        &tx,
        &key(USER_PRINCIPAL, fixture.tenant, fixture.user.as_bytes()),
        true,
    )
    .unwrap();
    let mut input = fixture.decision("expires-during-wait", AuthorizationDecisionKind::Approve);
    input.valid_until = Timestamp::now() + jiff::SignedDuration::from_millis(40);
    let db = fixture.db().clone();
    let task = tokio::spawn(async move { db.commit_decision(input).await });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    drop(tx);
    assert_eq!(
        task.await.unwrap().unwrap(),
        AuthorizationDecisionCommitResult::Expired
    );
    assert!(
        fixture
            .db()
            .grant(fixture.user, fixture.client)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        fixture
            .db()
            .commit_decision(
                fixture.decision("expires-during-wait", AuthorizationDecisionKind::Approve)
            )
            .await
            .unwrap(),
        AuthorizationDecisionCommitResult::Committed
    );
}

#[tokio::test]
async fn device_approval_replay_cannot_restore_a_revoked_grant() {
    let fixture = Fixture::new();
    let scopes = vec!["openid".into()];
    let details = json!([]);
    let expiry = Timestamp::now() + jiff::SignedDuration::from_secs(120);
    let write = || DeviceGrantWrite {
        device_code_hash: "device-code-digest",
        expires_at: expiry,
        tenant_id: fixture.tenant,
        user_id: fixture.user,
        client_id: fixture.client,
        scopes: &scopes,
        resource_indicators: &[],
        authorization_details: &details,
    };
    fixture.db().upsert_grant(write()).await.unwrap();
    let tx = fixture.db().transaction();
    grants::delete_scope_tx(&tx, fixture.tenant, fixture.user, fixture.client).unwrap();
    tx.commit().unwrap();
    fixture.db().upsert_grant(write()).await.unwrap();
    assert!(
        fixture
            .db()
            .grant(fixture.user, fixture.client)
            .await
            .unwrap()
            .is_none()
    );
    let mut expired = write();
    expired.expires_at = Timestamp::now() - jiff::SignedDuration::from_secs(1);
    assert_eq!(
        fixture.db().upsert_grant(expired).await.unwrap_err(),
        DeviceGrantPortError::Conflict
    );
}
