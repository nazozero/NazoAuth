#![cfg(feature = "local-sqlite")]
mod support;

use futures_executor::block_on;
use jiff::{SignedDuration, Timestamp};
use nazo_auth::PreparedClientRegistration;
use nazo_identity::{
    AccessRequestStatus, NewAccessRequest, OidcFederationState, SocialFederationState,
    TenantContext, TenantId, UserId,
    ports::{
        AccessRequestRepositoryPort, DeliveryConsume, DeliveryPublish, DeliveryRecord,
        DeliveryStage, DeliveryStageResult, DeliveryStorePort, FederationLinkRepositoryPort,
        FederationLogin, FederationLoginRepositoryPort, FederationStatePort, NewFederatedIdentity,
        NewUser, PasswordHashInput, RegistrationAccountRepositoryPort, RepositoryError,
    },
};
use nazo_oauth_server_d1::{D1Provider, Database};
use nazo_persistence::AdminAccessRequestStore;
use serde_json::{Value, json};
use std::sync::{Arc, Barrier};
use support::{TENANT, USER};
use uuid::Uuid;

const KEY: [u8; 32] = [61; 32];
fn tenant() -> TenantId {
    TenantId::new(TENANT).unwrap()
}
fn user() -> UserId {
    UserId::new(USER).unwrap()
}
fn context() -> TenantContext {
    TenantContext {
        tenant_id: tenant(),
        realm_id: nazo_identity::RealmId::new(TENANT).unwrap(),
        organization_id: nazo_identity::OrganizationId::new(TENANT).unwrap(),
    }
}
async fn fixture() -> (Database, D1Provider) {
    let (db, provider) = support::fixture().await;
    (db, provider.with_data_encryption_key(KEY))
}
fn assert_sql(db: &Database, predicate: &str) {
    db.execute_sql(&format!("CREATE TEMP TABLE assertion(ok INTEGER CHECK(ok=1));INSERT INTO assertion SELECT CASE WHEN ({predicate}) THEN 1 ELSE 0 END;DROP TABLE assertion;")).unwrap();
}
async fn assert_statement(db: &Database, sql: &'static str, params: Vec<Value>) {
    db.execute_sql("CREATE TEMP TABLE assertion(ok INTEGER CHECK(ok=1))")
        .unwrap();
    db.execute_statement(sql, params).await.unwrap();
    db.execute_sql("DROP TABLE assertion").unwrap();
}
fn admin(db: &Database) {
    db.execute_sql(&format!("UPDATE nazo_users SET principal=json_set(principal,'$.role',json('{{\"Admin\":{{\"level\":2}}}}')) WHERE id='{USER}'")).unwrap();
}
async fn applicant(provider: &D1Provider) -> UserId {
    RegistrationAccountRepositoryPort::create_user(
        provider,
        NewUser {
            tenant: context(),
            username: "applicant".into(),
            email: "applicant@example.com".into(),
            password_hash: PasswordHashInput::new("$argon2id$applicant").unwrap(),
            email_verified: true,
        },
    )
    .await
    .unwrap()
    .principal
    .user_id
}
fn identity(subject: &str, email: &str) -> NewFederatedIdentity {
    NewFederatedIdentity {
        login: FederationLogin {
            tenant: context(),
            provider_type: "oidc".into(),
            provider_id: "upstream".into(),
            subject: subject.into(),
            email: Some(email.into()),
            claims: json!({"scope":"verified","private":"provider-private"}),
        },
        email: email.into(),
        display_name: Some("Federated identity".into()),
        password_hash: PasswordHashInput::new("$argon2id$federated").unwrap(),
    }
}
fn oidc() -> OidcFederationState {
    OidcFederationState {
        browser_binding_hash: Some("browser-binding".into()),
        provider_id: Some("upstream".into()),
        nonce: "nonce".into(),
        pkce_verifier: "verifier".into(),
        created_at: Timestamp::now().as_second(),
    }
}

#[test]
fn concurrent_federation_creation_has_one_account_link_and_required_event() {
    let (db, provider) = block_on(fixture());
    let provider = Arc::new(provider);
    let gate = Arc::new(Barrier::new(8));
    let tasks = (0..8)
        .map(|_| {
            let provider = provider.clone();
            let gate = gate.clone();
            std::thread::spawn(move || {
                gate.wait();
                block_on(provider.create_federated(identity("subject", "federated@example.com")))
            })
        })
        .collect::<Vec<_>>();
    let results = tasks
        .into_iter()
        .map(|task| task.join().unwrap().unwrap())
        .collect::<Vec<_>>();
    let owner = results[0].principal.user_id;
    assert!(
        results
            .iter()
            .all(|account| account.principal.user_id == owner)
    );
    assert_sql(
        &db,
        "(SELECT count(*) FROM nazo_users)=2 AND (SELECT count(*) FROM nazo_federation_links)=1 AND (SELECT count(*) FROM nazo_audit WHERE event_type='external_identity_linked')=1 AND NOT EXISTS(SELECT 1 FROM nazo_audit WHERE instr(payload,'provider-private')>0)",
    );
    let links = block_on(provider.list_summaries(tenant(), owner)).unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].subject, "subject");
    assert!(
        block_on(provider.list_summaries(tenant(), user()))
            .unwrap()
            .is_empty()
    );
    assert!(
        block_on(provider.list_summaries(TenantId::new(Uuid::new_v4()).unwrap(), owner)).is_err()
    );
}

#[test]
fn social_federation_migration_preserves_existing_links() {
    let db = Database::in_memory().unwrap();
    db.execute_sql(include_str!("../migrations/0001.sql"))
        .unwrap();
    db.execute_sql(include_str!("../migrations/0010_federation_access.sql"))
        .unwrap();
    db.execute_sql(&format!(
        "INSERT INTO nazo_users (tenant_id,id,email,principal,claims,password_hash,epoch,active,created_at,updated_at)
         VALUES ('{TENANT}','{USER}','test@example.com','{{}}','{{}}','unused',0,1,0,0);
         INSERT INTO nazo_federation_links VALUES
           ('{TENANT}','legacy','{USER}','social','upstream','subject','test@example.com','{{}}',1,2,3);",
    ))
    .unwrap();
    db.execute_sql(include_str!("../migrations/0017_social_federation.sql"))
        .unwrap();
    assert_sql(
        &db,
        "(SELECT count(*) FROM nazo_federation_links)=1
         AND EXISTS(SELECT 1 FROM nazo_federation_links WHERE id='legacy' AND provider_type='oauth2_social'
            AND provider_id='upstream' AND subject='subject' AND last_login_at=3)
         AND NOT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
    );
}

#[test]
fn social_federation_round_trips_the_shared_provider_type() {
    block_on(async {
        let (_, provider) = fixture().await;
        let mut identity = identity("social-subject", "social@example.com");
        identity.login.provider_type = "oauth2_social".into();
        let login = identity.login.clone();
        let account = provider.create_federated(identity).await.unwrap();
        let user = account.principal.user_id;

        let restored = provider.resolve_existing(&login).await.unwrap().unwrap();
        assert_eq!(restored.principal.user_id, user);
        let links = provider.list_summaries(tenant(), user).await.unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].provider_type, "oauth2_social");
    });
}

#[test]
fn federation_never_links_an_email_collision_and_refreshes_only_provider_metadata() {
    block_on(async {
        let (db, provider) = fixture().await;
        assert!(matches!(
            provider
                .create_federated(identity("attacker", "test@example.com"))
                .await,
            Err(RepositoryError::Conflict)
        ));
        assert_sql(
            &db,
            "NOT EXISTS(SELECT 1 FROM nazo_federation_links) AND NOT EXISTS(SELECT 1 FROM nazo_audit)",
        );
        let account = provider
            .create_federated(identity("owner", "old@example.com"))
            .await
            .unwrap();
        let mut login = identity("owner", "new@example.com").login;
        login.claims = json!({"new":"claims"});
        let resolved = provider.resolve_existing(&login).await.unwrap().unwrap();
        assert_eq!(resolved.principal.user_id, account.principal.user_id);
        assert_eq!(resolved.account.email, "old@example.com");
        let links = provider
            .list_summaries(tenant(), account.principal.user_id)
            .await
            .unwrap();
        assert_eq!(links[0].email, "new@example.com");
        login.email = None;
        provider.resolve_existing(&login).await.unwrap();
        assert_eq!(
            provider
                .list_summaries(tenant(), account.principal.user_id)
                .await
                .unwrap()[0]
                .email,
            "new@example.com"
        );
        db.execute_statement(
            "UPDATE nazo_users SET active=0 WHERE id=?1",
            vec![json!(account.principal.user_id.as_uuid())],
        )
        .await
        .unwrap();
        assert!(
            !provider
                .resolve_existing(&login)
                .await
                .unwrap()
                .unwrap()
                .principal
                .active
        );
        assert_sql(
            &db,
            "(SELECT count(*) FROM nazo_audit WHERE event_type='external_identity_linked')=1",
        );
    });
}

#[test]
fn suppressed_federation_creation_and_unlink_effects_roll_back() {
    block_on(async {
        for table in ["nazo_users", "nazo_federation_links", "nazo_audit"] {
            let (db, provider) = fixture().await;
            db.execute_sql(&format!(
                "CREATE TRIGGER suppress BEFORE INSERT ON {table} BEGIN SELECT RAISE(IGNORE);END;"
            ))
            .unwrap();
            assert!(
                provider
                    .create_federated(identity("owner", "new@example.com"))
                    .await
                    .is_err()
            );
            assert_sql(
                &db,
                "(SELECT count(*) FROM nazo_users)=1 AND NOT EXISTS(SELECT 1 FROM nazo_federation_links) AND NOT EXISTS(SELECT 1 FROM nazo_audit)",
            );
        }
        for sql in [
            "CREATE TRIGGER suppress BEFORE INSERT ON nazo_audit BEGIN SELECT RAISE(IGNORE);END;",
            "CREATE TRIGGER suppress BEFORE DELETE ON nazo_federation_links BEGIN SELECT RAISE(IGNORE);END;",
        ] {
            let (db, provider) = fixture().await;
            let account = provider
                .create_federated(identity("owner", "new@example.com"))
                .await
                .unwrap();
            let link = provider
                .list_summaries(tenant(), account.principal.user_id)
                .await
                .unwrap()
                .remove(0);
            db.execute_sql(sql).unwrap();
            assert!(
                provider
                    .delete(tenant(), account.principal.user_id, link.id)
                    .await
                    .is_err()
            );
            assert_sql(
                &db,
                "(SELECT count(*) FROM nazo_federation_links)=1 AND NOT EXISTS(SELECT 1 FROM nazo_audit WHERE event_type='external_identity_unlinked')",
            );
            db.execute_sql("DROP TRIGGER suppress").unwrap();
            assert!(
                provider
                    .delete(tenant(), user(), link.id)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                provider
                    .delete(tenant(), account.principal.user_id, link.id)
                    .await
                    .unwrap(),
                Some(link)
            );
            assert!(
                provider
                    .delete(tenant(), account.principal.user_id, Uuid::new_v4())
                    .await
                    .unwrap()
                    .is_none()
            );
            assert_sql(
                &db,
                "NOT EXISTS(SELECT 1 FROM nazo_federation_links) AND (SELECT count(*) FROM nazo_audit WHERE event_type='external_identity_unlinked')=1",
            );
        }
    });
}

#[test]
fn federation_state_storage_rejects_ignored_inserts_and_replacements() {
    block_on(async {
        for operation in ["INSERT", "UPDATE"] {
            let (db, provider) = fixture().await;
            if operation == "UPDATE" {
                provider.store_oidc("state", &oidc(), 60).await.unwrap();
            }
            db.execute_sql(&format!(
                "CREATE TRIGGER ignore_state BEFORE {operation} ON nazo_state
                 WHEN NEW.kind='federation_oidc' BEGIN SELECT RAISE(IGNORE); END;"
            ))
            .unwrap();
            let mut next = oidc();
            next.nonce = "replacement".into();
            assert!(provider.store_oidc("state", &next, 60).await.is_err());
            let stored = provider
                .take_oidc("state", "browser-binding")
                .await
                .unwrap();
            assert_eq!(
                stored.map(|value| value.nonce),
                (operation == "UPDATE").then(|| "nonce".into())
            );
        }
    });
}

#[test]
fn federation_state_preserves_unbound_values_and_consumes_exact_browser_once() {
    block_on(async {
        let (db, provider) = fixture().await;
        provider.store_oidc("state", &oidc(), 60).await.unwrap();
        assert!(
            provider
                .take_oidc("state", "wrong")
                .await
                .unwrap()
                .is_none()
        );
        assert_sql(
            &db,
            "(SELECT count(*) FROM nazo_state WHERE kind='federation_oidc')=1",
        );
        assert_eq!(
            provider
                .take_oidc("state", "browser-binding")
                .await
                .unwrap()
                .unwrap()
                .nonce,
            "nonce"
        );
        assert!(
            provider
                .take_oidc("state", "browser-binding")
                .await
                .unwrap()
                .is_none()
        );
        for raw in [
            "not json",
            "{}",
            "{\"browser_binding_hash\":null}",
            "{\"browser_binding_hash\":7}",
        ] {
            provider.store_oidc("corrupt", &oidc(), 60).await.unwrap();
            let raw = raw.replace('\'', "''");
            db.execute_sql(&format!(
                "UPDATE nazo_state SET value='{raw}' WHERE kind='federation_oidc'"
            ))
            .unwrap();
            assert!(
                provider
                    .take_oidc("corrupt", "browser-binding")
                    .await
                    .unwrap()
                    .is_none()
            );
            assert_sql(
                &db,
                "(SELECT count(*) FROM nazo_state WHERE kind='federation_oidc')=1",
            );
        }
        db.execute_sql("UPDATE nazo_state SET value='{\"browser_binding_hash\":\"browser-binding\"}' WHERE kind='federation_oidc'").unwrap();
        assert!(
            provider
                .take_oidc("corrupt", "browser-binding")
                .await
                .is_err()
        );
        assert_sql(
            &db,
            "NOT EXISTS(SELECT 1 FROM nazo_state WHERE kind='federation_oidc')",
        );
        provider.store_oidc("same-key", &oidc(), 60).await.unwrap();
        let social = SocialFederationState {
            browser_binding_hash: Some("browser-binding".into()),
            provider_id: "social".into(),
            pkce_verifier: "social-verifier".into(),
            created_at: 0,
        };
        provider
            .store_social("same-key", &social, 60)
            .await
            .unwrap();
        assert_eq!(
            provider
                .take_social("same-key", "browser-binding")
                .await
                .unwrap()
                .unwrap()
                .provider_id,
            "social"
        );
        assert!(
            provider
                .take_oidc("same-key", "browser-binding")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            provider
                .reserve_saml_replay("assertion-signature", 60)
                .await
                .unwrap()
        );
        assert!(
            !provider
                .reserve_saml_replay("assertion-signature", 60)
                .await
                .unwrap()
        );
        db.execute_sql("UPDATE nazo_state SET expires_at=0 WHERE kind='federation_saml_replay'")
            .unwrap();
        assert!(
            provider
                .reserve_saml_replay("assertion-signature", 60)
                .await
                .unwrap()
        );
    });
}

fn candidate(owner: UserId, secret: &str, seconds: i64) -> DeliveryStage {
    let expires_at = Timestamp::now() + SignedDuration::from_secs(seconds);
    DeliveryStage {
        attempt_id: Uuid::new_v4(),
        expires_at,
        secret_binding: Some(format!("binding-{secret}")),
        value: json!({"delivery_state":"staged","user_id":owner,"client_id":"approved-client","client_secret":secret,"request_id":Uuid::new_v4(),"expires_at":expires_at}),
    }
}
async fn stage(provider: &D1Provider, token: &str, value: DeliveryStage) -> DeliveryRecord {
    match provider.stage(user(), token, value).await.unwrap() {
        DeliveryStageResult::Created(record) => record,
        _ => panic!("fresh stage was not created"),
    }
}

#[test]
fn delivery_encrypts_payload_and_preserves_exact_deadline_through_publication() {
    block_on(async {
        let (db, provider) = fixture().await;
        let staged = stage(
            &provider,
            "private-token",
            candidate(user(), "plain-secret-never-stored", 60),
        )
        .await;
        assert_sql(
            &db,
            "NOT EXISTS(SELECT 1 FROM nazo_client_deliveries WHERE instr(ciphertext,'plain-secret-never-stored')>0 OR instr(token_hash,'private-token')>0)",
        );
        assert!(matches!(
            provider
                .stage(
                    user(),
                    "private-token",
                    candidate(user(), "replacement", 120)
                )
                .await
                .unwrap(),
            DeliveryStageResult::Existing
        ));
        let client = Uuid::new_v4();
        assert_eq!(
            provider
                .publish(user(), "private-token", &staged, client)
                .await
                .unwrap(),
            DeliveryPublish::Published
        );
        let stored = provider
            .load(user(), "private-token")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.expires_at, staged.expires_at);
        assert_eq!(stored.attempt_id, staged.attempt_id);
        assert_eq!(stored.value["client_secret"], staged.value["client_secret"]);
        assert_eq!(stored.value["approved_client_id"], json!(client));
        assert!(
            !provider
                .retire(user(), "private-token", &staged)
                .await
                .unwrap()
        );
        assert!(
            !provider
                .retire(user(), "private-token", &stored)
                .await
                .unwrap()
        );
        let many = provider
            .load_many(&[
                (user(), "missing"),
                (user(), "private-token"),
                (UserId::new(Uuid::new_v4()).unwrap(), "private-token"),
            ])
            .await
            .unwrap();
        assert!(many[0].is_none() && many[2].is_none());
        assert_eq!(
            many[1].as_ref().unwrap().opaque_version,
            stored.opaque_version
        );
        assert!(
            D1Provider::new(db.clone(), tenant())
                .with_data_encryption_key([99; 32])
                .load(user(), "private-token")
                .await
                .is_err()
        );
        let foreign = D1Provider::new(db.clone(), TenantId::new(Uuid::new_v4()).unwrap())
            .with_data_encryption_key(KEY);
        assert!(
            foreign
                .load(user(), "private-token")
                .await
                .unwrap()
                .is_none()
        );
        assert_sql(
            &db,
            &format!(
                "(SELECT expires_at FROM nazo_client_deliveries)={}",
                staged.expires_at.as_microsecond()
            ),
        );
    });
}

#[test]
fn concurrent_delivery_staging_and_consumption_each_have_one_winner() {
    let (db, provider) = block_on(fixture());
    let provider = Arc::new(provider);
    let gate = Arc::new(Barrier::new(8));
    let tasks = (0..8)
        .map(|index| {
            let provider = provider.clone();
            let gate = gate.clone();
            std::thread::spawn(move || {
                gate.wait();
                block_on(provider.stage(
                    user(),
                    "race-token",
                    candidate(user(), &format!("secret-{index}"), 60),
                ))
                .unwrap()
            })
        })
        .collect::<Vec<_>>();
    let mut winners = tasks
        .into_iter()
        .filter_map(|task| match task.join().unwrap() {
            DeliveryStageResult::Created(record) => Some(record),
            DeliveryStageResult::Existing => None,
            DeliveryStageResult::Expired => panic!("fresh delivery expired"),
        })
        .collect::<Vec<_>>();
    assert_eq!(winners.len(), 1);
    let staged = winners.remove(0);
    assert_eq!(
        block_on(provider.publish(user(), "race-token", &staged, Uuid::new_v4())).unwrap(),
        DeliveryPublish::Published
    );
    let committed = Arc::new(
        block_on(provider.load(user(), "race-token"))
            .unwrap()
            .unwrap(),
    );
    let gate = Arc::new(Barrier::new(8));
    let tasks = (0..8)
        .map(|_| {
            let provider = provider.clone();
            let gate = gate.clone();
            let committed = committed.clone();
            std::thread::spawn(move || {
                gate.wait();
                block_on(provider.consume(user(), "race-token", &committed)).unwrap()
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(
        tasks
            .into_iter()
            .map(|task| task.join().unwrap())
            .filter(|outcome| *outcome == DeliveryConsume::Consumed)
            .count(),
        1
    );
    assert_eq!(
        block_on(provider.publish(user(), "race-token", &staged, Uuid::new_v4())).unwrap(),
        DeliveryPublish::MissingOrChanged
    );
    assert_sql(&db, "NOT EXISTS(SELECT 1 FROM nazo_client_deliveries)");
}

#[test]
fn delivery_cas_cannot_restore_expired_retired_or_changed_material() {
    block_on(async {
        let (db, provider) = fixture().await;
        let old = stage(&provider, "token", candidate(user(), "old", 60)).await;
        let mut tampered = old.clone();
        tampered.value["client_secret"] = json!("attacker");
        assert_eq!(
            provider
                .publish(user(), "token", &tampered, Uuid::new_v4())
                .await
                .unwrap(),
            DeliveryPublish::MissingOrChanged
        );
        assert!(!provider.retire(user(), "token", &tampered).await.unwrap());
        assert!(provider.retire(user(), "token", &old).await.unwrap());
        assert_eq!(
            provider
                .publish(user(), "token", &old, Uuid::new_v4())
                .await
                .unwrap(),
            DeliveryPublish::MissingOrChanged
        );
        let fresh = stage(&provider, "token", candidate(user(), "fresh", 60)).await;
        assert_ne!(fresh.attempt_id, old.attempt_id);
        assert!(!provider.retire(user(), "token", &old).await.unwrap());
        db.execute_sql("UPDATE nazo_client_deliveries SET expires_at=0")
            .unwrap();
        assert!(provider.load(user(), "token").await.unwrap().is_none());
        assert_eq!(
            provider
                .publish(user(), "token", &fresh, Uuid::new_v4())
                .await
                .unwrap(),
            DeliveryPublish::MissingOrChanged
        );
        assert!(!provider.retire(user(), "token", &fresh).await.unwrap());
        assert!(matches!(
            provider
                .stage(user(), "expired", candidate(user(), "expired", -1))
                .await
                .unwrap(),
            DeliveryStageResult::Expired
        ));
        let unconfigured = D1Provider::new(db.clone(), tenant());
        assert!(
            unconfigured
                .stage(user(), "without-key", candidate(user(), "missing-key", 60))
                .await
                .is_err()
        );
        assert_sql(&db, "(SELECT count(*) FROM nazo_client_deliveries)=1");
    });
}

fn prepared(name: &str) -> PreparedClientRegistration {
    let mut registration = support::client().registration;
    registration.client_id = name.into();
    registration.client_type = "confidential".into();
    registration.token_endpoint_auth_method = "client_secret_basic".into();
    PreparedClientRegistration {
        tenant: context(),
        registration,
        require_mtls_bound_tokens: false,
        issued_secret: Some("new-client-secret".into()).into(),
        client_secret_hash: Some("secret-binding".into()),
        registration_access_token_blake3: Some("a".repeat(64)),
    }
}
async fn request(provider: &D1Provider, owner: UserId, name: &str) -> nazo_identity::AccessRequest {
    AccessRequestRepositoryPort::create(
        provider,
        NewAccessRequest {
            tenant_id: tenant(),
            user_id: owner,
            site_name: name.into(),
            site_url: "https://client.example".into(),
            request_description: "Request scoped access".into(),
        },
    )
    .await
    .unwrap()
}

#[test]
fn access_approval_returns_actual_view_and_binds_delivery_to_current_secret() {
    block_on(async {
        let (db, provider) = fixture().await;
        admin(&db);
        let owner = applicant(&provider).await;
        let pending = request(&provider, owner, "Application").await;
        assert!(pending.requester_email.is_none());
        let prepared = prepared("approved");
        let result = provider
            .approve_with_required_audit(
                context(),
                pending.id,
                user(),
                &prepared,
                "source-hash".into(),
            )
            .await
            .unwrap();
        assert_eq!(result.request.status, AccessRequestStatus::Approved);
        assert_eq!(result.request.approved_client_id, Some(result.client.id));
        assert_eq!(
            result.request.requester_email.as_deref(),
            Some("applicant@example.com")
        );
        assert!(result.request.resolved_at.is_some());
        assert_eq!(
            AdminAccessRequestStore::by_id(&provider, tenant(), pending.id)
                .await
                .unwrap()
                .unwrap(),
            result.request
        );
        let matches = |binding| {
            AccessRequestRepositoryPort::approved_delivery_with_required_audit_matches(
                &provider,
                tenant(),
                owner,
                pending.id,
                result.client.id,
                "approved",
                binding,
            )
        };
        assert!(matches(Some("secret-binding")).await.unwrap());
        assert!(!matches(None).await.unwrap());
        assert!(!matches(Some("wrong")).await.unwrap());
        assert!(
            !AccessRequestRepositoryPort::approved_delivery_with_required_audit_matches(
                &provider,
                tenant(),
                user(),
                pending.id,
                result.client.id,
                "approved",
                Some("secret-binding")
            )
            .await
            .unwrap()
        );
        assert_statement(
            &db,
            "INSERT INTO assertion SELECT CASE WHEN (SELECT count(*) FROM nazo_audit WHERE event_type='client_created' AND category='client_lifecycle' AND json_extract(payload,'$.request_id')=?1 AND json_extract(payload,'$.request_user_id')=?2 AND json_extract(payload,'$.approved_client_id')=?3)=1 AND (SELECT count(*) FROM nazo_client_registrations WHERE client_id=?3)=1 THEN 1 ELSE 0 END",
            vec![json!(pending.id),json!(owner.as_uuid()),json!(result.client.id)],
        ).await;
        db.execute_sql(
            "UPDATE nazo_clients SET secret_digest='rotated' WHERE client_id='approved'",
        )
        .unwrap();
        assert!(!matches(Some("secret-binding")).await.unwrap());
        db.execute_sql("UPDATE nazo_clients SET secret_digest='secret-binding',active=0 WHERE client_id='approved'").unwrap();
        assert!(!matches(Some("secret-binding")).await.unwrap());
        assert!(matches!(
            provider
                .approve_with_required_audit(
                    context(),
                    pending.id,
                    user(),
                    &prepared,
                    String::new()
                )
                .await,
            Err(RepositoryError::AlreadyProcessed)
        ));
    });
}

#[test]
fn concurrent_access_approvals_create_only_the_winning_client_and_audit() {
    let (db, provider) = block_on(fixture());
    admin(&db);
    let owner = block_on(applicant(&provider));
    let pending = block_on(request(&provider, owner, "Race"));
    let provider = Arc::new(provider);
    let gate = Arc::new(Barrier::new(8));
    let tasks = (0..8)
        .map(|index| {
            let provider = provider.clone();
            let gate = gate.clone();
            std::thread::spawn(move || {
                let client = prepared(&format!("winner-{index}"));
                gate.wait();
                block_on(provider.approve_with_required_audit(
                    context(),
                    pending.id,
                    user(),
                    &client,
                    "source".into(),
                ))
            })
        })
        .collect::<Vec<_>>();
    let results = tasks
        .into_iter()
        .map(|task| task.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert!(
        results
            .iter()
            .filter_map(|r| r.as_ref().err())
            .all(|e| matches!(e, RepositoryError::AlreadyProcessed))
    );
    assert_sql(
        &db,
        "(SELECT count(*) FROM nazo_clients WHERE client_id LIKE 'winner-%')=1 AND (SELECT count(*) FROM nazo_audit WHERE event_type='client_created')=1 AND (SELECT count(*) FROM nazo_client_registrations)=1",
    );
}

#[test]
fn missing_approval_effect_or_required_audit_rolls_back_everything() {
    block_on(async {
        for sql in [
            "CREATE TRIGGER suppress BEFORE INSERT ON nazo_audit BEGIN SELECT RAISE(IGNORE);END;",
            "CREATE TRIGGER suppress BEFORE INSERT ON nazo_clients BEGIN SELECT RAISE(IGNORE);END;",
            "CREATE TRIGGER suppress BEFORE INSERT ON nazo_client_registrations BEGIN SELECT RAISE(IGNORE);END;",
            "CREATE TRIGGER suppress BEFORE UPDATE ON nazo_access_requests BEGIN SELECT RAISE(IGNORE);END;",
            "CREATE TRIGGER suppress AFTER UPDATE ON nazo_access_requests BEGIN UPDATE nazo_access_requests SET site_name='corrupt view' WHERE id=NEW.id;END;",
        ] {
            let (db, provider) = fixture().await;
            admin(&db);
            let owner = applicant(&provider).await;
            let pending = request(&provider, owner, "Original").await;
            db.execute_sql(sql).unwrap();
            assert!(
                provider
                    .approve_with_required_audit(
                        context(),
                        pending.id,
                        user(),
                        &prepared("atomic"),
                        "source".into()
                    )
                    .await
                    .is_err()
            );
            assert_sql(
                &db,
                "NOT EXISTS(SELECT 1 FROM nazo_clients WHERE client_id='atomic') AND NOT EXISTS(SELECT 1 FROM nazo_client_registrations) AND NOT EXISTS(SELECT 1 FROM nazo_audit WHERE event_type='client_created') AND (SELECT status=0 AND site_name='Original' AND required_approval_event_id IS NULL FROM nazo_access_requests)",
            );
        }
    });
}

#[test]
fn access_authority_requires_current_active_admin_and_matching_tenant_context() {
    block_on(async {
        let (db, provider) = fixture().await;
        let owner = applicant(&provider).await;
        let pending = request(&provider, owner, "Authority").await;
        assert!(matches!(
            provider
                .approve_with_required_audit(
                    context(),
                    pending.id,
                    user(),
                    &prepared("not-admin"),
                    String::new()
                )
                .await,
            Err(RepositoryError::Consistency(_))
        ));
        admin(&db);
        db.execute_statement(
            "UPDATE nazo_users SET active=0 WHERE id=?1",
            vec![json!(owner.as_uuid())],
        )
        .await
        .unwrap();
        assert!(matches!(
            provider
                .approve_with_required_audit(
                    context(),
                    pending.id,
                    user(),
                    &prepared("inactive"),
                    String::new()
                )
                .await,
            Err(RepositoryError::Consistency(_))
        ));
        let rejected = provider
            .reject_with_required_audit(context(), pending.id, user(), "inactive applicant".into())
            .await
            .unwrap();
        assert_eq!(rejected.status, AccessRequestStatus::Rejected);
        let next = request(&provider, owner, "Wrong realm").await;
        db.execute_statement("UPDATE nazo_users SET active=1,principal=json_set(principal,'$.tenant.realm_id',?1) WHERE id=?2",vec![json!(Uuid::new_v4()),json!(owner.as_uuid())]).await.unwrap();
        assert!(
            provider
                .approve_with_required_audit(
                    context(),
                    next.id,
                    user(),
                    &prepared("wrong-realm"),
                    String::new()
                )
                .await
                .is_err()
        );
        assert!(
            provider
                .reject_with_required_audit(context(), next.id, user(), String::new())
                .await
                .is_err()
        );
        assert_sql(
            &db,
            "(SELECT count(*) FROM nazo_clients)=1 AND NOT EXISTS(SELECT 1 FROM nazo_audit WHERE event_type='client_created')",
        );
    });
}

#[test]
fn access_rejection_is_atomic_and_admin_pages_search_literals() {
    block_on(async {
        let (db, provider) = fixture().await;
        admin(&db);
        let owner = applicant(&provider).await;
        let first = request(&provider, owner, "100%_literal").await;
        for sql in [
            "CREATE TRIGGER suppress BEFORE INSERT ON nazo_audit BEGIN SELECT RAISE(IGNORE);END;",
            "CREATE TRIGGER suppress BEFORE UPDATE ON nazo_access_requests BEGIN SELECT RAISE(IGNORE);END;",
        ] {
            db.execute_sql(sql).unwrap();
            assert!(
                provider
                    .reject_with_required_audit(context(), first.id, user(), "note".into())
                    .await
                    .is_err()
            );
            assert_sql(
                &db,
                "NOT EXISTS(SELECT 1 FROM nazo_audit WHERE event_type='admin_access_request_rejected') AND (SELECT count(*) FROM nazo_access_requests WHERE status=0)=1",
            );
            db.execute_sql("DROP TRIGGER suppress").unwrap();
        }
        let rejected = provider
            .reject_with_required_audit(context(), first.id, user(), "Policy decision".into())
            .await
            .unwrap();
        assert_eq!(rejected.admin_note.as_deref(), Some("Policy decision"));
        assert!(matches!(
            provider
                .reject_with_required_audit(context(), first.id, user(), "Again".into())
                .await,
            Err(RepositoryError::Conflict)
        ));
        request(&provider, owner, "Other").await;
        let page = AdminAccessRequestStore::page(
            &provider,
            tenant(),
            10,
            0,
            Some("%_"),
            Some(AccessRequestStatus::Rejected),
        )
        .await
        .unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.items, vec![rejected]);
        let page = AdminAccessRequestStore::page(
            &provider,
            tenant(),
            1,
            1,
            Some("APPLICANT@EXAMPLE.COM"),
            None,
        )
        .await
        .unwrap();
        assert_eq!(page.total, 2);
        assert_eq!(page.items.len(), 1);
        assert_eq!(
            provider.list_for_user(tenant(), owner).await.unwrap().len(),
            2
        );
        assert!(
            provider
                .list_for_user(tenant(), user())
                .await
                .unwrap()
                .is_empty()
        );
    });
}
