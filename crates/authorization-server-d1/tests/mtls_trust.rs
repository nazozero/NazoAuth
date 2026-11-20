#![cfg(feature = "local-sqlite")]

mod support;

use futures_executor::block_on;
use jiff::{SignedDuration, Timestamp};
use nazo_identity::{
    MtlsTrustAnchorStatus, NewMtlsTrustAnchorRequest, OrganizationId, RealmId, TenantContext,
    TenantId, UserId,
    ports::{
        MtlsTrustAnchorStore, NewUser, PasswordHashInput, RegistrationAccountRepositoryPort,
        RepositoryError,
    },
};
use nazo_oauth_server::ports::persistence::ServerPersistenceProvider;
use nazo_oauth_server_d1::{D1Provider, Database};
use serde_json::json;
use std::sync::{Arc, Barrier};
use support::{CLIENT, TENANT, USER};
use uuid::Uuid;

fn tenant() -> TenantId {
    TenantId::new(TENANT).unwrap()
}
fn user() -> UserId {
    UserId::new(USER).unwrap()
}
fn assert_sql(database: &Database, predicate: &str) {
    database.execute_sql(&format!("CREATE TEMP TABLE trust_assertion(ok INTEGER CHECK(ok=1));INSERT INTO trust_assertion SELECT CASE WHEN ({predicate}) THEN 1 ELSE 0 END;DROP TABLE trust_assertion")).unwrap();
}

struct Fixture {
    database: Database,
    provider: D1Provider,
    admin: UserId,
}
impl Fixture {
    async fn new() -> Self {
        let (database, provider) = support::fixture().await;
        let admin = provider
            .create_user(NewUser {
                tenant: TenantContext {
                    tenant_id: tenant(),
                    realm_id: RealmId::new(TENANT).unwrap(),
                    organization_id: OrganizationId::new(TENANT).unwrap(),
                },
                username: "reviewer".into(),
                email: "reviewer@example.test".into(),
                password_hash: PasswordHashInput::new("fixture").unwrap(),
                email_verified: true,
            })
            .await
            .unwrap()
            .user_id();
        database.execute_statement("UPDATE nazo_users SET principal=json_set(principal,'$.role',json('{\"Admin\":{\"level\":1}}')) WHERE id=?1",vec![json!(admin.as_uuid())]).await.unwrap();
        database
            .execute_statement(
                "UPDATE nazo_clients SET require_mtls_bound_tokens=1 WHERE id=?1",
                vec![json!(CLIENT)],
            )
            .await
            .unwrap();
        let fixture = Self {
            database,
            provider,
            admin,
        };
        fixture.ownership(CLIENT);
        fixture
    }
    fn ownership(&self, client: Uuid) {
        self.database.execute_sql(&format!("INSERT INTO nazo_access_requests(tenant_id,id,user_id,site_name,site_url,request_description,status,approved_client_id,created_at,resolved_at) VALUES('{TENANT}','{}','{USER}','owned','https://client.example','fixture',1,'{client}',0,0)",Uuid::new_v4())).unwrap();
    }
    fn request(&self, digit: usize) -> NewMtlsTrustAnchorRequest {
        NewMtlsTrustAnchorRequest {
            tenant_id: tenant(),
            user_id: user(),
            client_id: "client".into(),
            certificate_pem: format!(
                "-----BEGIN CERTIFICATE-----\nFIXTURE-{digit}\n-----END CERTIFICATE-----\n"
            ),
            certificate_sha256: format!("{digit:064x}"),
            subject_dn: format!("CN=Fixture {digit}"),
            not_before: Timestamp::now() - SignedDuration::from_secs(60),
            not_after: Timestamp::now() + SignedDuration::from_hours(1),
        }
    }
    fn block_audit(&self, event: &str) {
        self.database.execute_sql(&format!("CREATE TRIGGER reject_trust_audit BEFORE INSERT ON nazo_audit WHEN NEW.event_type='{event}' BEGIN SELECT RAISE(ABORT,'fixture audit failure'); END")).unwrap();
    }
    fn unblock_audit(&self) {
        self.database
            .execute_sql("DROP TRIGGER reject_trust_audit")
            .unwrap();
    }
}

#[test]
fn shared_validated_certificate_has_owned_two_person_revocable_trust() {
    block_on(async {
        let fixture = Fixture::new().await;
        let certificate = nazo_key_management::validate_mtls_trust_anchor(include_str!(
            "../../crypto/tests/fixtures/certificates/root.pem"
        ))
        .unwrap();
        let mut input = fixture.request(1);
        input.certificate_pem = certificate.certificate_pem;
        input.certificate_sha256 = certificate.certificate_sha256;
        input.subject_dn = certificate.subject_dn;
        input.not_before = certificate.not_before;
        input.not_after = certificate.not_after;
        let expected_expiry = input.not_after;
        let request = fixture
            .provider
            .mtls_trust_anchors()
            .create_for_owned_client(input)
            .await
            .unwrap();
        assert_eq!(request.not_after, expected_expiry);
        assert_eq!(request.requester_email.as_deref(), Some("test@example.com"));
        assert_eq!(request.status, MtlsTrustAnchorStatus::Pending.code());
        fixture.database.execute_sql(&format!("UPDATE nazo_users SET principal=json_set(principal,'$.role',json('{{\"Admin\":{{\"level\":1}}}}')) WHERE id='{USER}'")).unwrap();
        assert_eq!(
            fixture
                .provider
                .approve(tenant(), request.id, user(), None)
                .await,
            Err(RepositoryError::Conflict)
        );
        let approved = fixture
            .provider
            .approve(
                tenant(),
                request.id,
                fixture.admin,
                Some("approved CA".into()),
            )
            .await
            .unwrap();
        assert_eq!(approved.status, MtlsTrustAnchorStatus::Approved.code());
        assert!(approved.resolved_at.is_some());
        assert_eq!(
            fixture
                .provider
                .active_bundle(tenant(), Some(CLIENT))
                .await
                .unwrap(),
            request.certificate_pem
        );
        assert_eq!(
            fixture
                .provider
                .authorization_repository(TENANT)
                .mtls_trust_anchor_bundle(CLIENT)
                .await
                .unwrap(),
            request.certificate_pem
        );
        assert_eq!(
            fixture
                .provider
                .approve(tenant(), request.id, fixture.admin, None)
                .await,
            Err(RepositoryError::Conflict)
        );
        assert_eq!(
            fixture
                .provider
                .list_for_user(tenant(), user())
                .await
                .unwrap(),
            vec![approved.clone()]
        );
        let page = fixture
            .provider
            .page(tenant(), Some(MtlsTrustAnchorStatus::Approved), 1, 0)
            .await
            .unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.items, vec![approved.clone()]);
        assert_eq!(
            fixture.provider.by_id(tenant(), request.id).await.unwrap(),
            Some(approved)
        );
        let other = TenantId::new(Uuid::new_v4()).unwrap();
        assert!(fixture.provider.by_id(other, request.id).await.is_err());
        assert!(fixture.provider.active_bundle(other, None).await.is_err());
        fixture
            .database
            .execute_sql(&format!(
                "UPDATE nazo_clients SET active=0 WHERE id='{CLIENT}'"
            ))
            .unwrap();
        assert!(
            fixture
                .provider
                .active_bundle(tenant(), None)
                .await
                .unwrap()
                .is_empty()
        );
        fixture
            .database
            .execute_sql(&format!(
                "UPDATE nazo_clients SET active=1 WHERE id='{CLIENT}'"
            ))
            .unwrap();
        let revoked = fixture
            .provider
            .revoke(tenant(), request.id, fixture.admin, "retired CA".into())
            .await
            .unwrap();
        assert_eq!(revoked.status, MtlsTrustAnchorStatus::Revoked.code());
        assert!(revoked.revoked_at.is_some());
        assert!(
            fixture
                .provider
                .active_bundle(tenant(), None)
                .await
                .unwrap()
                .is_empty()
        );
        assert_sql(
            &fixture.database,
            "(SELECT count(*) FROM nazo_mtls_trust_events)=3 AND (SELECT count(*) FROM nazo_audit WHERE event_type LIKE 'mtls_trust_anchor_%')=3",
        );
    });
}

#[test]
fn request_requires_current_ownership_client_profile_user_and_validity() {
    block_on(async {
        let fixture = Fixture::new().await;
        let mut request = fixture.request(1);
        request.user_id = fixture.admin;
        assert_eq!(
            fixture.provider.create_for_owned_client(request).await,
            Err(RepositoryError::NotFound)
        );
        fixture
            .database
            .execute_sql("UPDATE nazo_clients SET require_mtls_bound_tokens=0")
            .unwrap();
        assert_eq!(
            fixture
                .provider
                .create_for_owned_client(fixture.request(1))
                .await,
            Err(RepositoryError::NotFound)
        );
        fixture.database.execute_sql("UPDATE nazo_clients SET registration=json_set(registration,'$.token_endpoint_auth_method','tls_client_auth')").unwrap();
        assert_eq!(
            fixture
                .provider
                .create_for_owned_client(fixture.request(1))
                .await,
            Err(RepositoryError::NotFound)
        );
        fixture.database.execute_sql(&format!("UPDATE nazo_clients SET registration=json_set(registration,'$.tls_client_auth_cert_sha256','{}')", "a".repeat(64))).unwrap();
        let accepted = fixture
            .provider
            .create_for_owned_client(fixture.request(1))
            .await
            .unwrap();
        fixture
            .database
            .execute_sql(&format!("UPDATE nazo_users SET active=0 WHERE id='{USER}'"))
            .unwrap();
        assert_eq!(
            fixture
                .provider
                .create_for_owned_client(fixture.request(2))
                .await,
            Err(RepositoryError::NotFound)
        );
        fixture
            .database
            .execute_sql(&format!("UPDATE nazo_users SET active=1 WHERE id='{USER}'"))
            .unwrap();
        let mut expired = fixture.request(2);
        expired.not_after = Timestamp::now() - SignedDuration::from_secs(1);
        assert_eq!(
            fixture.provider.create_for_owned_client(expired).await,
            Err(RepositoryError::NotFound)
        );
        let mut future = fixture.request(2);
        future.not_before = Timestamp::now() + SignedDuration::from_secs(60);
        assert_eq!(
            fixture.provider.create_for_owned_client(future).await,
            Err(RepositoryError::NotFound)
        );
        assert_eq!(
            fixture
                .provider
                .create_for_owned_client(fixture.request(1))
                .await,
            Err(RepositoryError::Conflict)
        );
        fixture
            .database
            .execute_statement(
                "UPDATE nazo_users SET active=0 WHERE id=?1",
                vec![json!(fixture.admin.as_uuid())],
            )
            .await
            .unwrap();
        assert_eq!(
            fixture
                .provider
                .approve(tenant(), accepted.id, fixture.admin, None)
                .await,
            Err(RepositoryError::Conflict)
        );
        fixture
            .database
            .execute_statement(
                "UPDATE nazo_users SET active=1 WHERE id=?1",
                vec![json!(fixture.admin.as_uuid())],
            )
            .await
            .unwrap();
        fixture
            .database
            .execute_sql("UPDATE nazo_mtls_trust_requests SET not_before=-2,not_after=-1")
            .unwrap();
        assert_eq!(
            fixture
                .provider
                .approve(tenant(), accepted.id, fixture.admin, None)
                .await,
            Err(RepositoryError::Conflict)
        );
        // Rejection remains possible after the requested certificate expires.
        assert_eq!(
            fixture
                .provider
                .reject(tenant(), accepted.id, fixture.admin, Some("expired".into()))
                .await
                .unwrap()
                .status,
            MtlsTrustAnchorStatus::Rejected.code()
        );
    });
}

#[test]
fn required_audit_failure_rolls_back_requests_source_events_and_all_decisions() {
    block_on(async {
        let fixture = Fixture::new().await;
        fixture.block_audit("mtls_trust_anchor_requested");
        assert!(
            fixture
                .provider
                .create_for_owned_client(fixture.request(1))
                .await
                .is_err()
        );
        assert_sql(
            &fixture.database,
            "(SELECT count(*) FROM nazo_mtls_trust_requests)=0 AND (SELECT count(*) FROM nazo_mtls_trust_events)=0",
        );
        fixture.unblock_audit();
        let request = fixture
            .provider
            .create_for_owned_client(fixture.request(1))
            .await
            .unwrap();
        fixture.block_audit("mtls_trust_anchor_approved");
        assert!(
            fixture
                .provider
                .approve(tenant(), request.id, fixture.admin, None)
                .await
                .is_err()
        );
        assert_eq!(
            fixture
                .provider
                .by_id(tenant(), request.id)
                .await
                .unwrap()
                .unwrap()
                .status,
            0
        );
        assert_sql(
            &fixture.database,
            "(SELECT count(*) FROM nazo_mtls_trust_events)=1",
        );
        fixture.unblock_audit();
        fixture
            .provider
            .approve(tenant(), request.id, fixture.admin, None)
            .await
            .unwrap();
        fixture.block_audit("mtls_trust_anchor_revoked");
        assert!(
            fixture
                .provider
                .revoke(tenant(), request.id, fixture.admin, "reason".into())
                .await
                .is_err()
        );
        assert_eq!(
            fixture
                .provider
                .by_id(tenant(), request.id)
                .await
                .unwrap()
                .unwrap()
                .status,
            1
        );
        assert_sql(
            &fixture.database,
            "(SELECT count(*) FROM nazo_mtls_trust_events)=2",
        );
        fixture.unblock_audit();
        fixture
            .provider
            .revoke(tenant(), request.id, fixture.admin, "reason".into())
            .await
            .unwrap();
        assert!(
            fixture
                .database
                .execute_sql("DELETE FROM nazo_mtls_trust_events")
                .is_err()
        );
        assert!(
            fixture
                .database
                .execute_sql("UPDATE nazo_mtls_trust_events SET note='rewritten'")
                .is_err()
        );
    });
}

#[test]
fn ignored_required_source_or_audit_record_rolls_back_every_trust_action() {
    block_on(async {
        for table in ["nazo_mtls_trust_events", "nazo_audit"] {
            for action in 0..=3 {
                let fixture = Fixture::new().await;
                let request = if action == 0 {
                    None
                } else {
                    Some(
                        fixture
                            .provider
                            .create_for_owned_client(fixture.request(1))
                            .await
                            .unwrap(),
                    )
                };
                if action == 3 {
                    fixture
                        .provider
                        .approve(tenant(), request.as_ref().unwrap().id, fixture.admin, None)
                        .await
                        .unwrap();
                }
                let before = fixture
                    .provider
                    .list_for_user(tenant(), user())
                    .await
                    .unwrap();
                fixture
                    .database
                    .execute_sql(&format!(
                        "CREATE TRIGGER ignore_trust_record BEFORE INSERT ON {table} BEGIN SELECT RAISE(IGNORE); END"
                    ))
                    .unwrap();
                let outcome = match action {
                    0 => {
                        fixture
                            .provider
                            .create_for_owned_client(fixture.request(1))
                            .await
                    }
                    1 => {
                        fixture
                            .provider
                            .approve(
                                tenant(),
                                request.as_ref().unwrap().id,
                                fixture.admin,
                                Some("reviewed".into()),
                            )
                            .await
                    }
                    2 => {
                        fixture
                            .provider
                            .reject(
                                tenant(),
                                request.as_ref().unwrap().id,
                                fixture.admin,
                                Some("rejected".into()),
                            )
                            .await
                    }
                    3 => {
                        fixture
                            .provider
                            .revoke(
                                tenant(),
                                request.as_ref().unwrap().id,
                                fixture.admin,
                                "retired".into(),
                            )
                            .await
                    }
                    _ => unreachable!(),
                };
                assert!(outcome.is_err(), "{table}, action {action}");
                assert_eq!(
                    fixture
                        .provider
                        .list_for_user(tenant(), user())
                        .await
                        .unwrap(),
                    before,
                    "{table}, action {action} must preserve the whole prior view"
                );
                let records = match action {
                    0 => 0,
                    3 => 2,
                    _ => 1,
                };
                assert_sql(
                    &fixture.database,
                    &format!(
                        "(SELECT count(*) FROM nazo_mtls_trust_events)={records} AND (SELECT count(*) FROM nazo_audit WHERE event_type LIKE 'mtls_trust_anchor_%')={records}"
                    ),
                );
                fixture
                    .database
                    .execute_sql("DROP TRIGGER ignore_trust_record")
                    .unwrap();
                // The failed request/decision did not consume the next action.
                let retry = if action == 0 {
                    fixture
                        .provider
                        .create_for_owned_client(fixture.request(1))
                        .await
                } else if action == 3 {
                    fixture
                        .provider
                        .revoke(
                            tenant(),
                            request.as_ref().unwrap().id,
                            fixture.admin,
                            "retired".into(),
                        )
                        .await
                } else {
                    fixture
                        .provider
                        .approve(tenant(), request.as_ref().unwrap().id, fixture.admin, None)
                        .await
                };
                assert!(retry.is_ok(), "{table}, action {action}");
            }
        }
    });
}

#[test]
fn ignored_or_rewritten_trust_state_does_not_commit_records_or_partial_effects() {
    block_on(async {
        for creating in [true, false] {
            for ignore in [true, false] {
                let fixture = Fixture::new().await;
                let request = if creating {
                    None
                } else {
                    Some(
                        fixture
                            .provider
                            .create_for_owned_client(fixture.request(1))
                            .await
                            .unwrap(),
                    )
                };
                let before = fixture
                    .provider
                    .list_for_user(tenant(), user())
                    .await
                    .unwrap();
                let when = if ignore { "BEFORE" } else { "AFTER" };
                let operation = if creating {
                    "INSERT"
                } else {
                    "UPDATE OF status"
                };
                let effect = if ignore {
                    "SELECT RAISE(IGNORE)"
                } else if creating {
                    "UPDATE nazo_mtls_trust_requests SET subject_dn='unexpected subject' WHERE tenant_id=NEW.tenant_id AND id=NEW.id"
                } else {
                    "UPDATE nazo_mtls_trust_requests SET version='unexpected version' WHERE tenant_id=NEW.tenant_id AND id=NEW.id"
                };
                fixture
                    .database
                    .execute_sql(&format!(
                        "CREATE TRIGGER alter_trust_state {when} {operation} ON nazo_mtls_trust_requests BEGIN {effect}; END"
                    ))
                    .unwrap();
                let outcome = if creating {
                    fixture
                        .provider
                        .create_for_owned_client(fixture.request(1))
                        .await
                } else {
                    fixture
                        .provider
                        .approve(tenant(), request.unwrap().id, fixture.admin, None)
                        .await
                };
                assert!(outcome.is_err(), "create={creating}, ignore={ignore}");
                assert_eq!(
                    fixture
                        .provider
                        .list_for_user(tenant(), user())
                        .await
                        .unwrap(),
                    before
                );
                let records = usize::from(!creating);
                assert_sql(
                    &fixture.database,
                    &format!(
                        "(SELECT count(*) FROM nazo_mtls_trust_events)={records} AND (SELECT count(*) FROM nazo_audit WHERE event_type LIKE 'mtls_trust_anchor_%')={records}"
                    ),
                );
            }
        }
    });
}

#[test]
fn required_audit_must_preserve_the_exact_event_payload() {
    block_on(async {
        let fixture = Fixture::new().await;
        fixture.database.execute_sql("CREATE TRIGGER replace_trust_audit BEFORE INSERT ON nazo_audit WHEN NEW.event_type='mtls_trust_anchor_requested' BEGIN INSERT INTO nazo_audit(tenant_id,event_id,event_type,category,occurred_at,payload) VALUES(NEW.tenant_id,NEW.event_id,NEW.event_type,NEW.category,NEW.occurred_at,'{}'); SELECT RAISE(IGNORE); END").unwrap();
        assert!(
            fixture
                .provider
                .create_for_owned_client(fixture.request(1))
                .await
                .is_err()
        );
        assert_sql(
            &fixture.database,
            "(SELECT count(*) FROM nazo_mtls_trust_requests)=0 AND (SELECT count(*) FROM nazo_mtls_trust_events)=0 AND (SELECT count(*) FROM nazo_audit WHERE event_type LIKE 'mtls_trust_anchor_%')=0",
        );
    });
}

#[test]
fn concurrent_pending_requests_and_review_enforce_atomic_limits_and_one_ack() {
    let fixture = block_on(Fixture::new());
    let barrier = Arc::new(Barrier::new(8));
    let outcomes = std::thread::scope(|scope| {
        (1..=8)
            .map(|index| {
                let provider = fixture.provider.clone();
                let request = fixture.request(index);
                let barrier = barrier.clone();
                scope.spawn(move || {
                    barrier.wait();
                    block_on(provider.create_for_owned_client(request))
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 4);
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| **result == Err(RepositoryError::Conflict))
            .count(),
        4
    );
    let id = outcomes.into_iter().find_map(Result::ok).unwrap().id;
    let barrier = Arc::new(Barrier::new(6));
    let outcomes = std::thread::scope(|scope| {
        (0..6)
            .map(|_| {
                let provider = fixture.provider.clone();
                let barrier = barrier.clone();
                let admin = fixture.admin;
                scope.spawn(move || {
                    barrier.wait();
                    block_on(provider.approve(tenant(), id, admin, None))
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| **result == Err(RepositoryError::Conflict))
            .count(),
        5
    );
    assert_sql(
        &fixture.database,
        "(SELECT count(*) FROM nazo_audit WHERE event_type='mtls_trust_anchor_approved')=1 AND (SELECT count(*) FROM nazo_mtls_trust_events WHERE action=1)=1",
    );
}

#[test]
fn approval_enforces_the_active_client_limit_and_does_not_trust_expired_anchors() {
    block_on(async {
        let fixture = Fixture::new().await;
        for index in 1..=8 {
            let request = fixture
                .provider
                .create_for_owned_client(fixture.request(index))
                .await
                .unwrap();
            fixture
                .provider
                .approve(tenant(), request.id, fixture.admin, None)
                .await
                .unwrap();
        }
        let request = fixture
            .provider
            .create_for_owned_client(fixture.request(9))
            .await
            .unwrap();
        assert_eq!(
            fixture
                .provider
                .approve(tenant(), request.id, fixture.admin, None)
                .await,
            Err(RepositoryError::Conflict)
        );
        assert_eq!(
            fixture
                .provider
                .by_id(tenant(), request.id)
                .await
                .unwrap()
                .unwrap()
                .status,
            0
        );
        fixture
            .database
            .execute_sql(
                "UPDATE nazo_mtls_trust_requests SET not_before=-2,not_after=-1 WHERE status=1",
            )
            .unwrap();
        assert!(
            fixture
                .provider
                .active_bundle(tenant(), None)
                .await
                .unwrap()
                .is_empty()
        );
        fixture
            .provider
            .approve(tenant(), request.id, fixture.admin, None)
            .await
            .unwrap();
        assert_eq!(
            fixture
                .provider
                .active_bundle(tenant(), None)
                .await
                .unwrap(),
            request.certificate_pem
        );
    });
}

#[test]
fn pending_user_limit_applies_across_owned_clients_and_invalid_metadata_is_rejected() {
    block_on(async {
        let fixture = Fixture::new().await;
        for client_index in 0..5 {
            let mut client = support::client();
            client.id = Uuid::new_v4();
            client.registration.client_id = format!("owned-{client_index}");
            client.require_mtls_bound_tokens = true;
            fixture
                .provider
                .provision_client(&client, None, 0)
                .await
                .unwrap();
            fixture.ownership(client.id);
            for request_index in 0..4 {
                let mut request = fixture.request(client_index * 4 + request_index + 1);
                request.client_id = client.registration.client_id.clone();
                let result = fixture.provider.create_for_owned_client(request).await;
                if client_index < 4 {
                    assert!(result.is_ok());
                } else {
                    assert_eq!(result, Err(RepositoryError::Conflict));
                }
            }
        }
        let mut malformed = fixture.request(100);
        malformed.certificate_sha256 = "not-a-fingerprint".into();
        assert_eq!(
            fixture.provider.create_for_owned_client(malformed).await,
            Err(RepositoryError::Conflict)
        );
        let mut malformed = fixture.request(101);
        malformed.subject_dn = "".into();
        assert_eq!(
            fixture.provider.create_for_owned_client(malformed).await,
            Err(RepositoryError::Conflict)
        );
        assert_sql(
            &fixture.database,
            "(SELECT count(*) FROM nazo_mtls_trust_requests WHERE status=0)=16",
        );
    });
}

#[test]
fn tenant_limit_counts_distinct_current_certificates_and_preserves_long_lived_validity() {
    block_on(async {
        let fixture = Fixture::new().await;
        let far_expiry = Timestamp::from_microsecond(67_090_227_200_000_001).unwrap();
        let mut first_client = None;
        for index in 0..17 {
            let mut client = support::client();
            client.id = Uuid::new_v4();
            client.registration.client_id = format!("tenant-limit-{index}");
            client.require_mtls_bound_tokens = true;
            fixture
                .provider
                .provision_client(&client, None, 0)
                .await
                .unwrap();
            fixture.ownership(client.id);
            if first_client.is_none() {
                first_client = Some(client.id);
            }
            if index < 16 {
                for certificate in 1..=8 {
                    let mut input = fixture.request(index * 8 + certificate);
                    input.client_id = client.registration.client_id.clone();
                    input.not_after = far_expiry;
                    let request = fixture
                        .provider
                        .create_for_owned_client(input)
                        .await
                        .unwrap();
                    assert_eq!(request.not_after, far_expiry);
                    fixture
                        .provider
                        .approve(tenant(), request.id, fixture.admin, None)
                        .await
                        .unwrap();
                }
            } else {
                let mut input = fixture.request(129);
                input.client_id = client.registration.client_id.clone();
                let request = fixture
                    .provider
                    .create_for_owned_client(input)
                    .await
                    .unwrap();
                assert_eq!(
                    fixture
                        .provider
                        .approve(tenant(), request.id, fixture.admin, None)
                        .await,
                    Err(RepositoryError::Conflict)
                );
                let mut duplicate = fixture.request(1);
                duplicate.client_id = client.registration.client_id;
                let duplicate = fixture
                    .provider
                    .create_for_owned_client(duplicate)
                    .await
                    .unwrap();
                fixture
                    .provider
                    .approve(tenant(), duplicate.id, fixture.admin, None)
                    .await
                    .unwrap();
                fixture
                    .database
                    .execute_sql(&format!(
                        "UPDATE nazo_clients SET active=0 WHERE id='{}'",
                        first_client.unwrap()
                    ))
                    .unwrap();
                fixture
                    .provider
                    .approve(tenant(), request.id, fixture.admin, None)
                    .await
                    .unwrap();
            }
        }
    });
}
