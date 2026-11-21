#![cfg(feature = "local-sqlite")]
mod support;

use futures_executor::block_on;
use nazo_auth::{AdminClientPortError, AdminClientRepositoryPort, OAuthClient};
use nazo_oauth_server_d1::{D1Provider, Database};
use std::sync::{Arc, Barrier};
use support::{TENANT, USER};
use uuid::Uuid;

async fn fixture() -> (Database, D1Provider) {
    let (database, provider) = support::fixture().await;
    database.execute_sql(&format!("UPDATE nazo_users SET principal=json_set(principal,'$.role',json('{{\"Admin\":{{\"level\":3}}}}')) WHERE id='{USER}'")).unwrap();
    (database, provider)
}
fn client(name: &str) -> OAuthClient {
    let mut client = support::client();
    client.id = Uuid::new_v4();
    client.registration.client_id = name.into();
    client.registration.client_type = "confidential".into();
    client.registration.token_endpoint_auth_method = "client_secret_basic".into();
    client
}
fn assert_sql(database: &Database, predicate: &str) {
    database.execute_sql(&format!("CREATE TEMP TABLE assertion(ok INTEGER CHECK(ok=1));INSERT INTO assertion SELECT CASE WHEN ({predicate}) THEN 1 ELSE 0 END;DROP TABLE assertion;")).unwrap();
}
fn family(database: &Database, client: &OAuthClient) {
    let now = jiff::Timestamp::now().as_microsecond();
    let family = Uuid::new_v4();
    database.execute_sql(&format!("INSERT INTO nazo_refresh_families(tenant_id,id,client_id,user_id,contract,contract_hash,member,member_id,token_hash,created_at,expires_at) VALUES('{TENANT}','{family}','{}','{USER}','{{}}','contract','{{}}','member','token',{now},{});INSERT INTO nazo_grants(tenant_id,user_id,client_id,scopes,resources,details,revision) VALUES('{TENANT}','{USER}','{}','[]','[]','[]','grant');",client.id,now+3_600_000_000,client.id)).unwrap();
}

#[test]
fn creation_rechecks_the_persisted_actor_context_and_rolls_back_secret_on_audit_failure() {
    block_on(async {
        let (database, provider) = fixture().await;
        let created = client("created");
        database.execute_sql("CREATE TRIGGER fail_client_insert BEFORE INSERT ON nazo_clients WHEN NEW.client_id='created' BEGIN SELECT RAISE(ABORT,'late insert failed');END;").unwrap();
        assert!(
            provider
                .insert_with_required_audit(&created, Some("secret"), None, USER, "source")
                .await
                .is_err()
        );
        assert_sql(
            &database,
            "NOT EXISTS(SELECT 1 FROM nazo_clients WHERE client_id='created') AND NOT EXISTS(SELECT 1 FROM nazo_audit)",
        );
        database
            .execute_sql("DROP TRIGGER fail_client_insert")
            .unwrap();
        assert_eq!(
            provider
                .insert_with_required_audit(&created, Some("secret"), None, USER, "source")
                .await
                .unwrap(),
            created
        );
        assert_eq!(
            provider
                .insert_with_required_audit(&created, Some("other"), None, USER, "source")
                .await,
            Err(AdminClientPortError::Conflict)
        );
        assert_sql(
            &database,
            &format!(
                "(SELECT count(*) FROM nazo_audit WHERE event_type='client_created' AND json_extract(payload,'$.admin_user_id')='{USER}' AND json_extract(payload,'$.client_pk')='{}')=1 AND (SELECT secret_digest FROM nazo_clients WHERE id='{}')='secret'",
                created.id, created.id
            ),
        );
        let mut foreign = client("context");
        foreign.organization_id = Uuid::new_v4();
        assert!(
            provider
                .insert_with_required_audit(&foreign, None, None, USER, "source")
                .await
                .is_err()
        );
        database
            .execute_sql(&format!("UPDATE nazo_users SET active=0 WHERE id='{USER}'"))
            .unwrap();
        assert!(
            provider
                .insert_with_required_audit(&client("inactive"), None, None, USER, "source")
                .await
                .is_err()
        );
    });
}

#[test]
fn creation_requires_both_the_client_and_registration_credential() {
    block_on(async {
        for table in ["nazo_clients", "nazo_client_registrations"] {
            let (database, provider) = fixture().await;
            database.execute_sql(&format!("CREATE TRIGGER suppress BEFORE INSERT ON {table} BEGIN SELECT RAISE(IGNORE); END;")).unwrap();
            let created = client("ignored");
            assert!(
                provider
                    .insert_with_required_audit(
                        &created,
                        Some("secret"),
                        Some("registration-hash"),
                        USER,
                        "source"
                    )
                    .await
                    .is_err(),
                "{table}"
            );
            assert_sql(
                &database,
                "NOT EXISTS(SELECT 1 FROM nazo_clients WHERE client_id='ignored') AND NOT EXISTS(SELECT 1 FROM nazo_client_registrations) AND NOT EXISTS(SELECT 1 FROM nazo_audit)",
            );
        }
    });
}

#[test]
fn client_deactivation_rolls_back_when_a_required_effect_is_ignored() {
    block_on(async {
        for (table, operation) in [
            ("nazo_clients", "UPDATE"),
            ("nazo_refresh_families", "UPDATE"),
            ("nazo_grants", "DELETE"),
        ] {
            let (database, provider) = fixture().await;
            let expected = client("deactivation");
            provider
                .insert_with_required_audit(&expected, Some("secret"), None, USER, "source")
                .await
                .unwrap();
            family(&database, &expected);
            let mut changed = expected.clone();
            changed.is_active = false;
            database.execute_sql(&format!("CREATE TRIGGER suppress BEFORE {operation} ON {table} BEGIN SELECT RAISE(IGNORE); END;")).unwrap();
            assert!(
                provider
                    .update_with_required_audit(&expected, &changed, USER, "source")
                    .await
                    .is_err(),
                "{table}"
            );
            assert_eq!(
                provider
                    .by_client_id(TENANT, "deactivation")
                    .await
                    .unwrap()
                    .unwrap(),
                expected
            );
            assert_sql(
                &database,
                "NOT EXISTS(SELECT 1 FROM nazo_audit WHERE event_type='client_updated') AND EXISTS(SELECT 1 FROM nazo_refresh_families WHERE revoked_at IS NULL) AND EXISTS(SELECT 1 FROM nazo_grants)",
            );
        }
    });
}

#[test]
fn authentication_downgrade_requires_each_family_revocation_audit() {
    block_on(async {
        let (database, provider) = fixture().await;
        let expected = client("downgrade-ignored");
        provider
            .insert_with_required_audit(&expected, Some("secret"), None, USER, "source")
            .await
            .unwrap();
        family(&database, &expected);
        let mut changed = expected.clone();
        changed.registration.client_type = "public".into();
        changed.registration.token_endpoint_auth_method = "none".into();
        database.execute_sql("CREATE TRIGGER suppress BEFORE INSERT ON nazo_audit WHEN NEW.event_type='refresh_family_security_revoked' BEGIN SELECT RAISE(IGNORE); END;").unwrap();
        assert!(
            provider
                .update_with_required_audit(&expected, &changed, USER, "source")
                .await
                .is_err()
        );
        assert_eq!(
            provider
                .by_client_id(TENANT, "downgrade-ignored")
                .await
                .unwrap()
                .unwrap(),
            expected
        );
        assert_sql(
            &database,
            "NOT EXISTS(SELECT 1 FROM nazo_audit WHERE event_type='client_updated') AND EXISTS(SELECT 1 FROM nazo_refresh_families WHERE revoked_at IS NULL)",
        );
    });
}

#[test]
fn metadata_cas_has_one_winner_and_never_mutates_the_authority_identity() {
    let (database, provider) = block_on(fixture());
    let expected = client("race");
    block_on(provider.insert_with_required_audit(&expected, Some("secret"), None, USER, "create"))
        .unwrap();
    let provider = Arc::new(provider);
    let barrier = Arc::new(Barrier::new(12));
    let tasks = (0..12)
        .map(|index| {
            let provider = provider.clone();
            let barrier = barrier.clone();
            let expected = expected.clone();
            std::thread::spawn(move || {
                let mut changed = expected.clone();
                changed.registration.client_name = format!("winner{index}");
                barrier.wait();
                block_on(provider.update_with_required_audit(&expected, &changed, USER, "update"))
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
            .filter_map(|result| result.as_ref().err())
            .all(|error| *error == AdminClientPortError::Conflict)
    );
    let current = provider.by_client_id(TENANT, "race");
    let current = block_on(current).unwrap().unwrap();
    let mut wrong = current.clone();
    wrong.id = Uuid::new_v4();
    assert_eq!(
        block_on(provider.update_with_required_audit(&current, &wrong, USER, "wrong")),
        Err(AdminClientPortError::CorruptData)
    );
    assert_sql(
        &database,
        "(SELECT count(*) FROM nazo_audit WHERE event_type='client_updated')=1 AND (SELECT secret_digest FROM nazo_clients WHERE client_id='race')='secret'",
    );
}

#[test]
fn confidential_downgrade_revokes_families_with_canonical_evidence_in_the_same_transaction() {
    block_on(async {
        let (database, provider) = fixture().await;
        let expected = client("downgrade");
        provider
            .insert_with_required_audit(&expected, Some("secret"), None, USER, "source")
            .await
            .unwrap();
        family(&database, &expected);
        let mut changed = expected.clone();
        changed.registration.client_type = "public".into();
        changed.registration.token_endpoint_auth_method = "none".into();
        database.execute_sql("CREATE TRIGGER fail_client_write BEFORE UPDATE ON nazo_clients BEGIN SELECT RAISE(ABORT,'late mutation failed');END;").unwrap();
        assert!(
            provider
                .update_with_required_audit(&expected, &changed, USER, "source")
                .await
                .is_err()
        );
        assert_sql(
            &database,
            "(SELECT count(*) FROM nazo_refresh_families WHERE revoked_at IS NULL)=1 AND NOT EXISTS(SELECT 1 FROM nazo_audit WHERE event_type IN('client_updated','refresh_family_security_revoked')) AND (SELECT secret_digest FROM nazo_clients WHERE client_id='downgrade')='secret'",
        );
        database
            .execute_sql("DROP TRIGGER fail_client_write")
            .unwrap();
        provider
            .update_with_required_audit(&expected, &changed, USER, "source")
            .await
            .unwrap();
        assert_sql(
            &database,
            "NOT EXISTS(SELECT 1 FROM nazo_refresh_families WHERE revoked_at IS NULL) AND (SELECT secret_digest IS NULL FROM nazo_clients WHERE client_id='downgrade') AND (SELECT count(*) FROM nazo_audit WHERE event_type='refresh_family_security_revoked' AND json_extract(payload,'$.reason')='client_authentication_class_downgrade')=1",
        );
    });
}

#[test]
fn deactivation_revokes_all_authority_and_reactivation_cannot_restore_old_families() {
    block_on(async {
        let (database, provider) = fixture().await;
        let expected = client("disable");
        provider
            .insert_with_required_audit(&expected, Some("secret"), None, USER, "source")
            .await
            .unwrap();
        family(&database, &expected);
        let mut changed = expected.clone();
        changed.is_active = false;
        provider
            .update_with_required_audit(&expected, &changed, USER, "source")
            .await
            .unwrap();
        assert_sql(
            &database,
            "(SELECT epoch=1 AND active=0 FROM nazo_clients WHERE client_id='disable') AND NOT EXISTS(SELECT 1 FROM nazo_grants) AND NOT EXISTS(SELECT 1 FROM nazo_refresh_families WHERE revoked_at IS NULL)",
        );
        provider
            .update_with_required_audit(&changed, &expected, USER, "source")
            .await
            .unwrap();
        assert_sql(
            &database,
            "(SELECT epoch=1 AND active=1 FROM nazo_clients WHERE client_id='disable') AND NOT EXISTS(SELECT 1 FROM nazo_refresh_families WHERE revoked_at IS NULL)",
        );
        database.execute_sql(&format!("UPDATE nazo_users SET principal=json_set(principal,'$.role','User') WHERE id='{USER}'")).unwrap();
        assert!(
            provider
                .update_with_required_audit(&expected, &changed, USER, "source")
                .await
                .is_err()
        );
    });
}

#[test]
fn static_and_administrative_mtls_flags_roundtrip_and_participate_in_metadata_cas() {
    block_on(async {
        let (_, provider) = fixture().await;
        let mut configured = client("static-mtls");
        configured.require_mtls_bound_tokens = true;
        configured.registration.token_endpoint_auth_method = "tls_client_auth".into();
        configured.registration.tls_client_auth_subject_dn = Some("CN=fixture".into());
        provider
            .provision_client(&configured, None, 0)
            .await
            .unwrap();
        assert_eq!(
            provider
                .by_client_id(TENANT, "static-mtls")
                .await
                .unwrap()
                .unwrap(),
            configured
        );
        let mut inserted = client("admin-mtls");
        inserted.require_mtls_bound_tokens = true;
        provider
            .insert_with_required_audit(&inserted, Some("secret"), None, USER, "source")
            .await
            .unwrap();
        assert_eq!(
            provider
                .by_client_id(TENANT, "admin-mtls")
                .await
                .unwrap()
                .unwrap(),
            inserted
        );
        let mut changed = inserted.clone();
        changed.require_mtls_bound_tokens = false;
        provider
            .update_with_required_audit(&inserted, &changed, USER, "source")
            .await
            .unwrap();
        assert_eq!(
            provider
                .by_client_id(TENANT, "admin-mtls")
                .await
                .unwrap()
                .unwrap(),
            changed
        );
        assert_eq!(
            provider
                .update_with_required_audit(&inserted, &inserted, USER, "stale")
                .await,
            Err(AdminClientPortError::Conflict)
        );
    });
}
