#![cfg(feature = "local-sqlite")]

mod support;

use futures_executor::block_on;
use jiff::{SignedDuration, Timestamp};
use nazo_identity::{
    OrganizationId, RealmId, TenantContext, TenantId, UserId,
    ports::{NewScimUser, PasswordHashInput, RepositoryError, ScimCredentialPort, ScimListQuery},
    scim::{NormalizedScimUser, ScimPatch, ScimTokenCredential},
};
use nazo_oauth_server::ports::persistence::ServerPersistenceProvider;
use nazo_oauth_server_d1::{D1Provider, Database};
use nazo_scim_events::{
    CREATE_NOTICE_EVENT, DEACTIVATE_EVENT, DELETE_EVENT, EventReceiver, EventStorePort,
    MutationContext, PATCH_NOTICE_EVENT, PUT_NOTICE_EVENT, SetError, ValidatedPollRequest,
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Barrier},
};
use support::{CLIENT, TENANT, USER};
use uuid::Uuid;

async fn fixture() -> (Database, D1Provider) {
    let (database, provider) = support::fixture().await;
    database
        .execute_sql(include_str!("../migrations/0005_ciba_scim.sql"))
        .unwrap();
    (database, provider)
}
fn tenant() -> TenantContext {
    TenantContext {
        tenant_id: TenantId::new(TENANT).unwrap(),
        realm_id: RealmId::new(TENANT).unwrap(),
        organization_id: OrganizationId::new(TENANT).unwrap(),
    }
}
fn input(name: &str) -> NormalizedScimUser {
    NormalizedScimUser {
        user_name: name.into(),
        email: format!("{name}@example.com"),
        active: true,
        display_name: Some("Provisioned name".into()),
        given_name: Some("Given".into()),
        family_name: Some("Family".into()),
    }
}
fn create(name: &str, mutation: MutationContext) -> NewScimUser {
    NewScimUser {
        tenant: tenant(),
        input: input(name),
        password_hash: PasswordHashInput::new("$argon2id$offline-bootstrap").unwrap(),
        mutation,
    }
}
fn poll(max: u16) -> ValidatedPollRequest {
    ValidatedPollRequest {
        max_events: max,
        return_immediately: true,
        ack: Vec::new(),
        set_errors: BTreeMap::new(),
    }
}
async fn receiver(provider: &D1Provider) -> EventReceiver {
    let id = Uuid::new_v4();
    let digest = blake3::hash(id.as_bytes()).to_hex().to_string();
    provider
        .provision_scim_credential(
            &ScimTokenCredential {
                id,
                tenant_id: TENANT,
                scopes: vec!["scim:*".into()],
                event_audience: Some("https://receiver.example".into()),
            },
            &digest,
            None,
        )
        .await
        .unwrap();
    EventReceiver {
        token_id: id,
        tenant_id: TENANT,
        audience: "https://receiver.example".into(),
    }
}

#[test]
fn provisioning_requires_the_scim_credential_to_be_written() {
    block_on(async {
        let (database, provider) = fixture().await;
        database
            .execute_sql(
                "CREATE TRIGGER ignore_credential BEFORE INSERT ON nazo_scim_tokens
             BEGIN SELECT RAISE(IGNORE); END;",
            )
            .unwrap();
        let credential = ScimTokenCredential {
            id: Uuid::new_v4(),
            tenant_id: TENANT,
            scopes: vec!["scim:read".into()],
            event_audience: None,
        };
        let digest = blake3::hash(credential.id.as_bytes()).to_hex().to_string();
        assert!(
            provider
                .provision_scim_credential(&credential, &digest, None)
                .await
                .is_err()
        );
        assert!(provider.active_credential(&digest).await.unwrap().is_none());
    });
}

fn assert_sql(database: &Database, predicate: &str) {
    database.execute_sql(&format!("CREATE TEMP TABLE assertion(ok INTEGER CHECK(ok=1)); INSERT INTO assertion SELECT CASE WHEN ({predicate}) THEN 1 ELSE 0 END; DROP TABLE assertion;")).unwrap();
}
fn family(database: &Database) -> Uuid {
    let family = Uuid::new_v4();
    let now = Timestamp::now().as_microsecond();
    database.execute_sql(&format!(
        "INSERT INTO nazo_refresh_families(tenant_id,id,client_id,user_id,contract,contract_hash,member,member_id,token_hash,created_at,expires_at)
         VALUES('{TENANT}','{family}','{CLIENT}','{USER}','{{}}','contract','{{}}','member','token',{now},{});
         INSERT INTO nazo_grants(tenant_id,user_id,client_id,scopes,resources,details,revision)
         VALUES('{TENANT}','{USER}','{CLIENT}','[]','[]','[]','grant');",now+3_600_000_000)).unwrap();
    family
}

#[test]
fn crud_preserves_identity_and_profiles_and_publishes_shared_event_shapes() {
    block_on(async {
        let (database, provider) = fixture().await;
        let repository = provider.scim_repository(604_800);
        let receiver = receiver(&provider).await;
        let mutation = MutationContext::enabled();
        let created = repository
            .create(create("created", mutation))
            .await
            .unwrap();
        assert_eq!(created.account.username, "created");
        assert!(created.account.email_verified);
        assert_eq!(created.principal.tenant, tenant());
        assert_eq!(created.principal.authorization_epoch, 0);
        let page = provider
            .apply_dispositions_and_poll(&receiver, &poll(20))
            .await
            .unwrap();
        assert_eq!(page.events.len(), 1);
        assert_eq!(
            page.events[0].transaction_id,
            mutation.transaction_id().unwrap()
        );
        assert!(page.events[0].events.contains_key(CREATE_NOTICE_EVENT));
        assert_eq!(page.events[0].occurred_at, created.created_at);
        let patched = repository
            .patch(
                tenant(),
                created.user_id(),
                ScimPatch {
                    email: Some("renamed@example.com".into()),
                    display_name: Some("Patched".into()),
                    ..Default::default()
                },
                MutationContext::enabled(),
            )
            .await
            .unwrap();
        assert_eq!(patched.account.email, "renamed@example.com");
        assert_eq!(patched.account.username, "created");
        assert_eq!(patched.profile.given_name.as_deref(), Some("Given"));
        let mut replacement = input("replaced");
        replacement.display_name = None;
        replacement.given_name = None;
        replacement.family_name = None;
        let replaced = repository
            .replace(
                tenant(),
                created.user_id(),
                replacement,
                MutationContext::enabled(),
            )
            .await
            .unwrap();
        assert_eq!(replaced.id(), created.id());
        assert_eq!(replaced.created_at, created.created_at);
        assert!(replaced.profile.display_name.is_none() && replaced.profile.given_name.is_none());
        assert!(
            repository
                .delete(tenant(), created.user_id(), MutationContext::enabled())
                .await
                .unwrap()
        );
        assert!(
            !repository
                .delete(tenant(), created.user_id(), MutationContext::enabled())
                .await
                .unwrap()
        );
        assert!(
            repository
                .get(tenant(), created.user_id())
                .await
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            repository
                .patch(
                    tenant(),
                    created.user_id(),
                    ScimPatch {
                        active: Some(true),
                        ..Default::default()
                    },
                    MutationContext::enabled()
                )
                .await,
            Err(RepositoryError::NotFound)
        ));
        let events = provider
            .apply_dispositions_and_poll(&receiver, &poll(20))
            .await
            .unwrap()
            .events;
        assert_eq!(events.len(), 4);
        for kind in [
            CREATE_NOTICE_EVENT,
            PATCH_NOTICE_EVENT,
            PUT_NOTICE_EVENT,
            DELETE_EVENT,
        ] {
            assert_eq!(
                events
                    .iter()
                    .filter(|event| event.events.contains_key(kind))
                    .count(),
                1
            );
        }
        assert_sql(
            &database,
            "(SELECT count(*) FROM nazo_audit WHERE event_type LIKE 'scim_user_%')=4 AND (SELECT count(*) FROM nazo_state WHERE kind='scim_mutation')=0",
        );
    });
}

#[test]
fn concurrent_identity_creation_has_one_winner_with_one_required_audit_and_event() {
    let (database, provider) = block_on(fixture());
    let repository = provider.scim_repository(3600);
    let barrier = Arc::new(Barrier::new(12));
    let results = std::thread::scope(|scope| {
        let joins = (0..12)
            .map(|_| {
                let repository = repository.clone();
                let barrier = barrier.clone();
                scope.spawn(move || {
                    barrier.wait();
                    block_on(repository.create(create("unique", MutationContext::enabled())))
                })
            })
            .collect::<Vec<_>>();
        joins
            .into_iter()
            .map(|join| join.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|value| value.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|value| matches!(value, Err(RepositoryError::Conflict)))
            .count(),
        11
    );
    assert_sql(
        &database,
        "(SELECT count(*) FROM nazo_users)=2 AND (SELECT count(*) FROM nazo_audit WHERE event_type='scim_user_created')=1 AND (SELECT count(*) FROM nazo_scim_events)=1 AND (SELECT count(*) FROM nazo_state WHERE kind='scim_mutation')=0",
    );
    let mut duplicate = create("other", MutationContext::enabled());
    duplicate.input.user_name = "unique".into();
    assert!(matches!(
        block_on(repository.create(duplicate)),
        Err(RepositoryError::Conflict)
    ));
    let mut duplicate = create("third", MutationContext::enabled());
    duplicate.input.email = "UNIQUE@example.com".into();
    assert!(matches!(
        block_on(repository.create(duplicate)),
        Err(RepositoryError::Conflict)
    ));
}

#[test]
fn scim_creation_requires_account_audit_and_event_effects() {
    block_on(async {
        for table in ["nazo_users", "nazo_audit", "nazo_scim_events"] {
            let (database, provider) = fixture().await;
            database.execute_sql(&format!("CREATE TRIGGER suppress BEFORE INSERT ON {table} BEGIN SELECT RAISE(IGNORE); END;")).unwrap();
            assert!(
                provider
                    .scim_repository(600)
                    .create(create("ignored", MutationContext::enabled()))
                    .await
                    .is_err(),
                "{table}"
            );
            assert_sql(
                &database,
                "NOT EXISTS(SELECT 1 FROM nazo_users WHERE email='ignored@example.com') AND NOT EXISTS(SELECT 1 FROM nazo_audit) AND NOT EXISTS(SELECT 1 FROM nazo_scim_events) AND NOT EXISTS(SELECT 1 FROM nazo_state WHERE kind='scim_mutation')",
            );
        }
    });
}

#[test]
fn scim_deletion_rolls_back_each_ignored_effect() {
    block_on(async {
        for trigger in [
            "CREATE TRIGGER suppress BEFORE UPDATE ON nazo_users BEGIN SELECT RAISE(IGNORE); END;",
            "CREATE TRIGGER suppress BEFORE INSERT ON nazo_audit WHEN NEW.event_type='scim_user_deleted' BEGIN SELECT RAISE(IGNORE); END;",
            "CREATE TRIGGER suppress BEFORE INSERT ON nazo_audit WHEN NEW.event_type='refresh_family_security_revoked' BEGIN SELECT RAISE(IGNORE); END;",
            "CREATE TRIGGER suppress BEFORE INSERT ON nazo_deleted_users BEGIN SELECT RAISE(IGNORE); END;",
            "CREATE TRIGGER suppress BEFORE UPDATE ON nazo_refresh_families BEGIN SELECT RAISE(IGNORE); END;",
            "CREATE TRIGGER suppress BEFORE DELETE ON nazo_grants BEGIN SELECT RAISE(IGNORE); END;",
            "CREATE TRIGGER suppress BEFORE INSERT ON nazo_scim_events BEGIN SELECT RAISE(IGNORE); END;",
            "CREATE TRIGGER suppress BEFORE DELETE ON nazo_state WHEN OLD.kind='scim_mutation' BEGIN SELECT RAISE(IGNORE); END;",
        ] {
            let (database, provider) = fixture().await;
            family(&database);
            database.execute_sql(trigger).unwrap();
            assert!(
                provider
                    .scim_repository(600)
                    .delete(
                        tenant(),
                        UserId::new(USER).unwrap(),
                        MutationContext::enabled()
                    )
                    .await
                    .is_err(),
                "{trigger}"
            );
            assert_sql(
                &database,
                &format!(
                    "EXISTS(SELECT 1 FROM nazo_users WHERE id='{USER}' AND active=1 AND epoch=0) AND NOT EXISTS(SELECT 1 FROM nazo_deleted_users) AND EXISTS(SELECT 1 FROM nazo_refresh_families WHERE revoked_at IS NULL) AND EXISTS(SELECT 1 FROM nazo_grants) AND NOT EXISTS(SELECT 1 FROM nazo_audit) AND NOT EXISTS(SELECT 1 FROM nazo_scim_events) AND NOT EXISTS(SELECT 1 FROM nazo_state WHERE kind='scim_mutation')"
                ),
            );
        }
    });
}

#[test]
fn polling_rejects_ignored_eligible_receipts() {
    block_on(async {
        let (database, provider) = fixture().await;
        let receiver = receiver(&provider).await;
        provider
            .scim_repository(600)
            .create(create("event", MutationContext::enabled()))
            .await
            .unwrap();
        let page = provider
            .apply_dispositions_and_poll(&receiver, &poll(20))
            .await
            .unwrap();
        let event = page.events[0].id;
        let mut acknowledge = poll(20);
        acknowledge.ack.push(event);
        database.execute_sql("CREATE TRIGGER suppress BEFORE INSERT ON nazo_scim_event_receipts BEGIN SELECT RAISE(IGNORE); END;").unwrap();
        assert!(
            provider
                .apply_dispositions_and_poll(&receiver, &acknowledge)
                .await
                .is_err()
        );
        assert_sql(
            &database,
            "NOT EXISTS(SELECT 1 FROM nazo_scim_event_receipts)",
        );
        assert_eq!(
            provider
                .apply_dispositions_and_poll(&receiver, &poll(20))
                .await
                .unwrap()
                .events[0]
                .id,
            event
        );
    });
}

#[test]
fn concurrent_deactivation_emits_one_transition_and_retires_sessions_and_grants() {
    let (database, provider) = block_on(fixture());
    let receiver = block_on(receiver(&provider));
    let family = family(&database);
    let repository = provider.scim_repository(3600);
    let barrier = Arc::new(Barrier::new(8));
    std::thread::scope(|scope| {
        let joins = (0..8)
            .map(|_| {
                let repository = repository.clone();
                let barrier = barrier.clone();
                scope.spawn(move || {
                    barrier.wait();
                    block_on(repository.patch(
                        tenant(),
                        UserId::new(USER).unwrap(),
                        ScimPatch {
                            active: Some(false),
                            ..Default::default()
                        },
                        MutationContext::enabled(),
                    ))
                    .unwrap()
                })
            })
            .collect::<Vec<_>>();
        for join in joins {
            assert!(!join.join().unwrap().principal.active);
        }
    });
    let account = block_on(repository.get(tenant(), UserId::new(USER).unwrap()))
        .unwrap()
        .unwrap();
    assert_eq!(account.principal.authorization_epoch, 1);
    let events = block_on(provider.apply_dispositions_and_poll(&receiver, &poll(20)))
        .unwrap()
        .events;
    assert_eq!(events.len(), 8);
    assert_eq!(
        events
            .iter()
            .filter(|event| event.events.contains_key(DEACTIVATE_EVENT))
            .count(),
        1
    );
    assert_sql(
        &database,
        &format!(
            "(SELECT revoked_at IS NOT NULL FROM nazo_refresh_families WHERE id='{family}') AND (SELECT count(*) FROM nazo_grants)=0 AND (SELECT count(*) FROM nazo_audit WHERE event_type='refresh_family_security_revoked')=1"
        ),
    );
    let reactivated = block_on(repository.patch(
        tenant(),
        UserId::new(USER).unwrap(),
        ScimPatch {
            active: Some(true),
            ..Default::default()
        },
        MutationContext::enabled(),
    ))
    .unwrap();
    assert!(reactivated.principal.active);
    assert_eq!(reactivated.principal.authorization_epoch, 1);
    assert_sql(
        &database,
        &format!(
            "(SELECT revoked_at IS NOT NULL FROM nazo_refresh_families WHERE id='{family}') AND (SELECT count(*) FROM nazo_grants)=0"
        ),
    );
}

#[test]
fn event_or_audit_failure_rolls_back_identity_deletion_revocation_and_all_evidence() {
    block_on(async {
        let (database, provider) = fixture().await;
        let repository = provider.scim_repository(3600);
        let family = family(&database);
        database.execute_sql("CREATE TRIGGER fail_scim_event BEFORE INSERT ON nazo_scim_events BEGIN SELECT RAISE(ABORT,'event unavailable'); END;").unwrap();
        assert!(
            repository
                .create(create("rollback", MutationContext::enabled()))
                .await
                .is_err()
        );
        assert!(
            repository
                .patch(
                    tenant(),
                    UserId::new(USER).unwrap(),
                    ScimPatch {
                        active: Some(false),
                        ..Default::default()
                    },
                    MutationContext::enabled()
                )
                .await
                .is_err()
        );
        assert!(
            repository
                .delete(
                    tenant(),
                    UserId::new(USER).unwrap(),
                    MutationContext::enabled()
                )
                .await
                .is_err()
        );
        assert_sql(
            &database,
            &format!(
                "(SELECT count(*) FROM nazo_users)=1 AND (SELECT active FROM nazo_users WHERE id='{USER}')=1 AND (SELECT epoch FROM nazo_users WHERE id='{USER}')=0 AND (SELECT revoked_at IS NULL FROM nazo_refresh_families WHERE id='{family}') AND (SELECT count(*) FROM nazo_grants)=1 AND (SELECT count(*) FROM nazo_audit)=0 AND (SELECT count(*) FROM nazo_deleted_users)=0 AND (SELECT count(*) FROM nazo_state WHERE kind='scim_mutation')=0"
            ),
        );
        database.execute_sql("DROP TRIGGER fail_scim_event; CREATE TRIGGER fail_scim_audit BEFORE INSERT ON nazo_audit BEGIN SELECT RAISE(ABORT,'audit unavailable'); END;").unwrap();
        assert!(
            repository
                .patch(
                    tenant(),
                    UserId::new(USER).unwrap(),
                    ScimPatch {
                        user_name: Some("must-not-commit".into()),
                        ..Default::default()
                    },
                    MutationContext::disabled()
                )
                .await
                .is_err()
        );
        assert_eq!(
            repository
                .get(tenant(), UserId::new(USER).unwrap())
                .await
                .unwrap()
                .unwrap()
                .account
                .username,
            "test"
        );
        assert_sql(
            &database,
            "(SELECT count(*) FROM nazo_scim_events)=0 AND (SELECT count(*) FROM nazo_audit)=0",
        );
    });
}

#[test]
fn listing_counts_cursor_ties_filters_and_soft_deletion_remain_tenant_bound() {
    block_on(async {
        let (database, provider) = fixture().await;
        let repository = provider.scim_repository(3600);
        let a = repository
            .create(create("alpha", MutationContext::disabled()))
            .await
            .unwrap();
        let b = repository
            .create(create("bravo", MutationContext::disabled()))
            .await
            .unwrap();
        database
            .execute_sql(&format!(
                "UPDATE nazo_users SET created_at=1000000 WHERE tenant_id='{TENANT}';"
            ))
            .unwrap();
        let query = ScimListQuery {
            tenant_id: tenant().tenant_id,
            email: None,
            after: None,
            limit: 1,
            offset: 0,
        };
        let first = repository.list(query.clone()).await.unwrap();
        assert_eq!(first.total, 3);
        assert_eq!(first.users.len(), 1);
        let second = repository
            .list(ScimListQuery {
                after: Some((first.users[0].created_at, first.users[0].id())),
                limit: 10,
                ..query.clone()
            })
            .await
            .unwrap();
        assert_eq!(second.total, 3);
        assert_eq!(second.users.len(), 2);
        assert!(
            second
                .users
                .iter()
                .all(|user| user.id() > first.users[0].id())
        );
        let filtered = repository
            .list(ScimListQuery {
                email: Some(a.account.email.clone()),
                limit: 0,
                ..query.clone()
            })
            .await
            .unwrap();
        assert_eq!(filtered.total, 1);
        assert!(filtered.users.is_empty());
        repository
            .delete(tenant(), b.user_id(), MutationContext::disabled())
            .await
            .unwrap();
        assert_eq!(
            repository
                .list(ScimListQuery {
                    limit: 10,
                    ..query.clone()
                })
                .await
                .unwrap()
                .total,
            2
        );
        assert!(
            repository
                .list(ScimListQuery {
                    tenant_id: TenantId::new(Uuid::new_v4()).unwrap(),
                    ..query
                })
                .await
                .is_err()
        );
        assert_sql(&database, "(SELECT count(*) FROM nazo_scim_events)=0");
    });
}

#[test]
fn polling_receipts_are_receiver_scoped_idempotent_and_atomic_with_the_page() {
    block_on(async {
        let (database, provider) = fixture().await;
        let repository = provider.scim_repository(3600);
        let a = receiver(&provider).await;
        let b = receiver(&provider).await;
        for name in ["one", "two", "three"] {
            repository
                .create(create(name, MutationContext::enabled()))
                .await
                .unwrap();
        }
        let page = provider
            .apply_dispositions_and_poll(&a, &poll(1))
            .await
            .unwrap();
        assert!(page.more_available);
        let first = page.events[0].id;
        let initial = provider
            .apply_dispositions_and_poll(&a, &poll(20))
            .await
            .unwrap();
        let second = initial.events[1].id;
        database.execute_sql(&format!("CREATE TRIGGER fail_receipt BEFORE INSERT ON nazo_scim_event_receipts WHEN NEW.event_id='{second}' BEGIN SELECT RAISE(ABORT,'receipt unavailable'); END;")).unwrap();
        let ack = ValidatedPollRequest {
            ack: vec![first, second],
            ..poll(20)
        };
        assert!(
            provider
                .apply_dispositions_and_poll(&a, &ack)
                .await
                .is_err()
        );
        assert_eq!(
            provider
                .apply_dispositions_and_poll(&a, &poll(20))
                .await
                .unwrap()
                .events
                .len(),
            3
        );
        database.execute_sql("DROP TRIGGER fail_receipt;").unwrap();
        let page = provider
            .apply_dispositions_and_poll(&a, &ack)
            .await
            .unwrap();
        assert_eq!(page.events.len(), 1);
        assert!(!page.more_available);
        assert_eq!(
            provider
                .apply_dispositions_and_poll(&b, &poll(20))
                .await
                .unwrap()
                .events
                .len(),
            3
        );
        let errors = ValidatedPollRequest {
            set_errors: BTreeMap::from([
                (
                    first,
                    SetError {
                        err: "failed".into(),
                        description: "Already acknowledged".into(),
                    },
                ),
                (
                    page.events[0].id,
                    SetError {
                        err: "failed".into(),
                        description: "Consumer cannot process".into(),
                    },
                ),
            ]),
            ..poll(20)
        };
        assert!(
            provider
                .apply_dispositions_and_poll(&a, &errors)
                .await
                .unwrap()
                .events
                .is_empty()
        );
        assert_sql(
            &database,
            &format!(
                "(SELECT disposition='acknowledged' FROM nazo_scim_event_receipts WHERE token_id='{}' AND event_id='{first}') AND (SELECT count(*) FROM nazo_scim_event_receipts)=3",
                a.token_id
            ),
        );
        assert!(
            provider
                .apply_dispositions_and_poll(
                    &EventReceiver {
                        tenant_id: Uuid::new_v4(),
                        ..a
                    },
                    &poll(20)
                )
                .await
                .is_err()
        );
    });
}

#[test]
fn receiver_start_time_retention_and_credential_revocation_bound_event_visibility() {
    block_on(async {
        let (database, provider) = fixture().await;
        let repository = provider.scim_repository(3600);
        let receiver = receiver(&provider).await;
        repository
            .create(create("before", MutationContext::enabled()))
            .await
            .unwrap();
        repository
            .create(create("after", MutationContext::enabled()))
            .await
            .unwrap();
        database.execute_sql("UPDATE nazo_scim_events SET occurred_at=1 WHERE subject_uri=(SELECT '/Users/'||id FROM nazo_users WHERE email='before@example.com');").unwrap();
        let page = provider
            .apply_dispositions_and_poll(&receiver, &poll(20))
            .await
            .unwrap();
        assert_eq!(page.events.len(), 1);
        database
            .execute_sql(&format!(
                "UPDATE nazo_scim_events SET expires_at=1 WHERE id='{}';",
                page.events[0].id
            ))
            .unwrap();
        let ack = ValidatedPollRequest {
            ack: vec![page.events[0].id],
            ..poll(20)
        };
        assert!(
            provider
                .apply_dispositions_and_poll(&receiver, &ack)
                .await
                .unwrap()
                .events
                .is_empty()
        );
        assert_sql(
            &database,
            "(SELECT count(*) FROM nazo_scim_event_receipts)=0",
        );
        let hash = blake3::hash(receiver.token_id.as_bytes())
            .to_hex()
            .to_string();
        assert!(provider.active_credential(&hash).await.unwrap().is_some());
        database
            .execute_sql(&format!(
                "UPDATE nazo_scim_tokens SET revoked_at=1 WHERE id='{}';",
                receiver.token_id
            ))
            .unwrap();
        assert!(provider.active_credential(&hash).await.unwrap().is_none());
        assert!(
            provider
                .apply_dispositions_and_poll(&receiver, &poll(20))
                .await
                .unwrap()
                .events
                .is_empty()
        );
        let expired = ScimTokenCredential {
            id: Uuid::new_v4(),
            tenant_id: TENANT,
            scopes: vec!["scim:read".into()],
            event_audience: None,
        };
        let digest = blake3::hash(b"expired").to_hex().to_string();
        provider
            .provision_scim_credential(
                &expired,
                &digest,
                Some(Timestamp::now() - SignedDuration::from_secs(10)),
            )
            .await
            .unwrap();
        assert!(provider.active_credential(&digest).await.unwrap().is_none());
        let other = D1Provider::new(database, TenantId::new(Uuid::new_v4()).unwrap());
        assert!(other.active_credential(&hash).await.unwrap().is_none());
    });
}
