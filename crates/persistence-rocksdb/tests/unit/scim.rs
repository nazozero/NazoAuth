use super::*;
use crate::db::read;
use jiff::{SignedDuration, Timestamp};
use nazo_auth::{
    CommitTokenIssuance, CommitTokenIssuanceResult, NewRefreshToken, RefreshContract,
    RefreshTokenAuthenticationContext, RefreshTokenCommit, TokenIssuanceMode,
    TokenIssuedAuditFields, TokenPrincipalState, TokenRepositoryPort,
};
use nazo_identity::{TenantDirectoryBinding, ports::PasswordHashInput};

use crate::support::clients;
use crate::support::database;

async fn initialize(db: &RocksDb) -> TenantContext {
    let context = TenantContext::default_system();
    db.initialize_tenant_directory(TenantDirectoryBinding {
        tenant: context,
        runtime_revision: 1,
        issuer: "https://scim.example.test".into(),
        external_host: "scim.example.test".into(),
    })
    .await
    .unwrap();
    context
}

fn new_user(tenant: TenantContext, name: &str) -> NewScimUser {
    NewScimUser {
        tenant,
        input: NormalizedScimUser {
            user_name: name.into(),
            email: format!("{name}@example.test"),
            active: true,
            display_name: Some(name.into()),
            given_name: None,
            family_name: None,
        },
        password_hash: PasswordHashInput::new("fixture-hash").unwrap(),
        mutation: MutationContext::enabled(),
    }
}

fn count(db: &RocksDb, table: u8, tenant: Uuid) -> usize {
    let prefix = key(table, tenant, &[]);
    let mut iterator = db.db.raw_iterator();
    iterator.seek(&prefix);
    let mut count = 0;
    while iterator.key().is_some_and(|key| key.starts_with(&prefix)) {
        count += 1;
        iterator.next();
    }
    iterator.status().unwrap();
    count
}

async fn issue_family(db: &RocksDb, tenant: TenantContext, user: UserId) -> (Uuid, Uuid) {
    let client = clients::client(tenant, "scim-client");
    let family = Uuid::now_v7();
    let now = Timestamp::now();
    let tx = db.transaction();
    crate::clients::insert_client_tx(&tx, &client, None, None, 0).unwrap();
    crate::grants::write_grant_tx(
        &tx,
        client.tenant_id,
        user.as_uuid(),
        client.id,
        &["openid".into()],
        &[],
        &json!([]),
        true,
        now,
    )
    .unwrap();
    tx.commit().unwrap();
    let subject = user.as_uuid().to_string();
    let input = CommitTokenIssuance {
        authorization_id: Some(family),
        principal_state: TokenPrincipalState {
            client_epoch: 0,
            user_epoch: Some(0),
            subject_bound: false,
        },
        subject: subject.clone(),
        issuance_id: Uuid::now_v7(),
        tenant_id: client.tenant_id,
        client_id: client.id,
        user_id: Some(user.as_uuid()),
        mode: TokenIssuanceMode::Fresh,
        access_token_jti: Uuid::new_v4().to_string(),
        access_token_expires_at: now.as_second() + 300,
        refresh_token: Some(RefreshTokenCommit::IssueNew {
            token: NewRefreshToken {
                raw_token: Uuid::new_v4().to_string(),
                member_id: Uuid::now_v7(),
                tenant_id: client.tenant_id,
                family_id: family,
                rotated_from_id: None,
                lost_response_retry: None,
                client_id: client.id,
                user_id: Some(user.as_uuid()),
                audiences: vec!["resource://default".into()],
                issued_at: now,
                expires_at: now + SignedDuration::from_secs(900),
                id_token_sid: None,
                dpop_jkt: None,
                mtls_x5t_s256: None,
                client_attestation_jkt: None,
            },
            contract: RefreshContract {
                subject,
                scopes: vec!["openid".into()],
                audiences: vec!["resource://default".into()],
                authorization_details: json!([]),
                authentication_context: RefreshTokenAuthenticationContext {
                    version: RefreshTokenAuthenticationContext::CURRENT_VERSION,
                    issuer: "https://scim.example.test".into(),
                    audience: client.client_id.clone(),
                    auth_time: now.as_second() - 1,
                    amr: vec!["pwd".into()],
                    oidc_sid: None,
                    acr: None,
                    userinfo_claim_requests: Default::default(),
                    id_token_claim_requests: Default::default(),
                },
            },
        }),
        native_sso_source: None,
        audit_fields: TokenIssuedAuditFields {
            client_id: client.client_id.clone(),
            subject_hash: "subject-digest".into(),
            scope: "openid".into(),
            audience: vec!["resource://default".into()],
        },
    };
    assert_eq!(
        db.commit_token_issuance(input).await.unwrap(),
        CommitTokenIssuanceResult::Committed
    );
    (client.id, family)
}

#[tokio::test]
async fn scim_deactivation_and_required_event_evidence_commit_or_roll_back_together() {
    let database = database::Database::new();
    let db = database.store();
    let tenant = initialize(db).await;
    let repo = ScimRepository {
        store: db.clone(),
        retention_seconds: 600,
    };
    let user = repo
        .create(new_user(tenant, "alice"))
        .await
        .unwrap()
        .principal
        .user_id;
    let (client, family) = issue_family(db, tenant, user).await;
    let baseline_audit = count(db, crate::audit::EVENTS, Uuid::nil());
    let baseline_events = count(db, EVENT, tenant.tenant_id.as_uuid());
    // This rejects the event's retention deadline after authority/grant/audit
    // writes have been staged, proving that the accepting transaction rolls back.
    let broken = ScimRepository {
        store: db.clone(),
        retention_seconds: u64::MAX,
    };
    assert!(
        broken
            .patch(
                tenant,
                user,
                ScimPatch {
                    active: Some(false),
                    ..Default::default()
                },
                MutationContext::enabled()
            )
            .await
            .is_err()
    );
    let account = repo.get(tenant, user).await.unwrap().unwrap();
    assert!(account.principal.active);
    assert_eq!(account.principal.authorization_epoch, 0);
    assert!(
        db.refresh_family_active(tenant.tenant_id.as_uuid(), family, user.as_uuid())
            .await
            .unwrap()
    );
    assert!(
        read::<crate::grants::GrantRecord>(
            &db.db,
            &crate::grants::grant_key(tenant.tenant_id.as_uuid(), user.as_uuid(), client)
        )
        .unwrap()
        .is_some()
    );
    assert_eq!(count(db, crate::audit::EVENTS, Uuid::nil()), baseline_audit);
    assert_eq!(
        count(db, EVENT, tenant.tenant_id.as_uuid()),
        baseline_events
    );
    let disabled = repo
        .patch(
            tenant,
            user,
            ScimPatch {
                active: Some(false),
                ..Default::default()
            },
            MutationContext::enabled(),
        )
        .await
        .unwrap();
    assert!(!disabled.principal.active);
    assert_eq!(disabled.principal.authorization_epoch, 1);
    assert!(
        !db.refresh_family_active(tenant.tenant_id.as_uuid(), family, user.as_uuid())
            .await
            .unwrap()
    );
    assert!(
        read::<crate::grants::GrantRecord>(
            &db.db,
            &crate::grants::grant_key(tenant.tenant_id.as_uuid(), user.as_uuid(), client)
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(
        count(db, crate::audit::EVENTS, Uuid::nil()),
        baseline_audit + 1
    );
    assert_eq!(
        count(db, EVENT, tenant.tenant_id.as_uuid()),
        baseline_events + 1
    );
    assert!(
        repo.delete(tenant, user, MutationContext::enabled())
            .await
            .unwrap()
    );
    assert!(repo.get(tenant, user).await.unwrap().is_none());
    assert!(
        repo.patch(
            tenant,
            user,
            ScimPatch {
                active: Some(true),
                ..Default::default()
            },
            MutationContext::enabled()
        )
        .await
        .is_err()
    );
    let page = repo
        .list(ScimListQuery {
            tenant_id: tenant.tenant_id,
            email: None,
            after: None,
            limit: 10,
            offset: 0,
        })
        .await
        .unwrap();
    assert_eq!(page.total, 0);
}

#[tokio::test]
async fn scim_event_acknowledgements_are_receiver_scoped_and_bind_the_audience() {
    let database = database::Database::new();
    let db = database.store();
    let tenant = initialize(db).await;
    let mut receivers = Vec::new();
    for byte in ['a', 'b'] {
        let credential = ScimTokenCredential {
            id: Uuid::new_v4(),
            tenant_id: tenant.tenant_id.as_uuid(),
            scopes: vec!["scim:events".into()],
            event_audience: Some("receiver".into()),
        };
        db.provision_scim_credential(&credential, &byte.to_string().repeat(64), None)
            .await
            .unwrap();
        receivers.push(EventReceiver {
            token_id: credential.id,
            tenant_id: credential.tenant_id,
            audience: "receiver".into(),
        });
    }
    let repo = ScimRepository {
        store: db.clone(),
        retention_seconds: 600,
    };
    let input = new_user(tenant, "bob");
    let transaction = input.mutation.transaction_id().unwrap();
    repo.create(input).await.unwrap();
    let request = ValidatedPollRequest {
        max_events: 10,
        return_immediately: true,
        ack: vec![],
        set_errors: Default::default(),
    };
    let first = db
        .apply_dispositions_and_poll(&receivers[0], &request)
        .await
        .unwrap();
    assert_eq!(first.events.len(), 1);
    assert_eq!(first.events[0].transaction_id, transaction);
    let mut ack = request.clone();
    ack.ack.push(first.events[0].id);
    assert!(
        db.apply_dispositions_and_poll(&receivers[0], &ack)
            .await
            .unwrap()
            .events
            .is_empty()
    );
    assert_eq!(
        db.apply_dispositions_and_poll(&receivers[1], &request)
            .await
            .unwrap()
            .events
            .len(),
        1
    );
    let mut wrong = receivers[1].clone();
    wrong.audience = "other".into();
    assert!(
        db.apply_dispositions_and_poll(&wrong, &ack)
            .await
            .unwrap()
            .events
            .is_empty()
    );
    assert_eq!(
        db.apply_dispositions_and_poll(&receivers[1], &request)
            .await
            .unwrap()
            .events
            .len(),
        1
    );
}
