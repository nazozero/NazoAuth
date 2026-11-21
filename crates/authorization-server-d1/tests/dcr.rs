#![cfg(feature = "local-sqlite")]
mod support;

use futures_executor::block_on;
use nazo_auth::{
    AdminClientRepositoryPort, DynamicRegistrationClientStore,
    DynamicRegistrationDependencyError as Error, OAuthClient, PreparedClientRegistration,
    TokenRepositoryPort,
};
use nazo_identity::{OrganizationId, RealmId, TenantContext, TenantId};
use nazo_oauth_server_d1::{D1Provider, Database};
use std::sync::{Arc, Barrier};
use support::{TENANT, USER, fixture};
use uuid::Uuid;

fn hash(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex().to_string()
}

fn prepared(name: &str, confidential: bool) -> PreparedClientRegistration {
    let mut client = support::client();
    client.registration.client_id = name.into();
    if confidential {
        client.registration.client_type = "confidential".into();
        client.registration.token_endpoint_auth_method = "client_secret_basic".into();
    }
    PreparedClientRegistration {
        tenant: TenantContext {
            tenant_id: TenantId::new(TENANT).unwrap(),
            realm_id: RealmId::new(TENANT).unwrap(),
            organization_id: OrganizationId::new(TENANT).unwrap(),
        },
        registration: client.registration,
        require_mtls_bound_tokens: false,
        issued_secret: None.into(),
        client_secret_hash: confidential.then(|| "client-secret-v1:salt:digest".into()),
        registration_access_token_blake3: Some(hash("initial")),
    }
}
async fn insert(provider: &D1Provider, name: &str, confidential: bool) -> OAuthClient {
    DynamicRegistrationClientStore::insert(provider, prepared(name, confidential), &hash("source"))
        .await
        .unwrap()
}

fn family(database: &Database, client: &OAuthClient) -> Uuid {
    let family = Uuid::new_v4();
    let now = jiff::Timestamp::now().as_microsecond();
    database.execute_sql(&format!(
        "INSERT INTO nazo_refresh_families(tenant_id,id,client_id,user_id,contract,contract_hash,member,member_id,token_hash,created_at,expires_at)
         VALUES('{TENANT}','{family}','{}','{USER}','{{}}','contract','{{}}','member','token',{now},{});
         INSERT INTO nazo_grants(tenant_id,user_id,client_id,scopes,resources,details,revision)
         VALUES('{TENANT}','{USER}','{}','[\"openid\"]','[]','[]','grant');",
        client.id, now + 3_600_000_000, client.id,
    )).unwrap();
    family
}

#[test]
fn registration_token_is_client_and_tenant_bound_and_static_clients_are_unmanaged() {
    block_on(async {
        let (_, provider) = fixture().await;
        let client = insert(&provider, "dynamic", true).await;
        let snapshot = provider
            .by_registration_access_token(TENANT, "dynamic", &hash("initial"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.client.id, client.id);
        assert!(snapshot.has_client_secret);
        assert_eq!(snapshot.secret_salt.as_deref(), Some("salt"));
        assert!(
            DynamicRegistrationClientStore::client_secret_digest_matches(
                &provider,
                TENANT,
                client.id,
                "client-secret-v1:salt:digest"
            )
            .await
            .unwrap()
        );
        for (public_id, token) in [("dynamic", hash("wrong")), ("client", hash("initial"))] {
            assert!(
                provider
                    .by_registration_access_token(TENANT, public_id, &token)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        assert!(
            provider
                .by_registration_access_token(Uuid::new_v4(), "dynamic", &hash("initial"))
                .await
                .is_err()
        );
    });
}

#[test]
fn registration_creation_rejects_ignored_credentials_or_required_audit() {
    block_on(async {
        for table in ["nazo_client_registrations", "nazo_audit"] {
            let (database, provider) = fixture().await;
            database.execute_sql(&format!("CREATE TRIGGER suppress BEFORE INSERT ON {table} BEGIN SELECT RAISE(IGNORE); END;")).unwrap();
            assert!(
                DynamicRegistrationClientStore::insert(
                    &provider,
                    prepared("ignored", true),
                    &hash("source")
                )
                .await
                .is_err(),
                "{table}"
            );
            assert!(
                provider
                    .by_client_id(TENANT, "ignored")
                    .await
                    .unwrap()
                    .is_none()
            );
            database.execute_sql("CREATE TEMP TABLE assertion(ok INTEGER CHECK(ok=1)); INSERT INTO assertion SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM nazo_client_registrations) AND NOT EXISTS(SELECT 1 FROM nazo_audit) THEN 1 ELSE 0 END;").unwrap();
        }
    });
}

#[test]
fn management_rotation_and_deletion_reject_ignored_effects() {
    block_on(async {
        for table in ["nazo_clients", "nazo_client_registrations"] {
            let (database, provider) = fixture().await;
            let original = insert(&provider, "rotation", true).await;
            database.execute_sql(&format!("CREATE TRIGGER suppress BEFORE UPDATE ON {table} BEGIN SELECT RAISE(IGNORE); END;")).unwrap();
            assert!(
                provider
                    .rotate_credentials(
                        TENANT,
                        original.id,
                        Some("client-secret-v1:new:digest"),
                        &hash("initial"),
                        &hash("next")
                    )
                    .await
                    .is_err(),
                "{table}"
            );
            assert_eq!(
                provider
                    .by_registration_access_token(TENANT, "rotation", &hash("initial"))
                    .await
                    .unwrap()
                    .unwrap()
                    .client,
                original
            );
        }
        for (table, operation) in [
            ("nazo_clients", "UPDATE"),
            ("nazo_client_registrations", "DELETE"),
            ("nazo_refresh_families", "UPDATE"),
            ("nazo_grants", "DELETE"),
        ] {
            let (database, provider) = fixture().await;
            let original = insert(&provider, "deletion", true).await;
            family(&database, &original);
            database.execute_sql(&format!("CREATE TRIGGER suppress BEFORE {operation} ON {table} BEGIN SELECT RAISE(IGNORE); END;")).unwrap();
            assert!(
                provider
                    .deactivate(TENANT, original.id, &hash("initial"), &hash("source"))
                    .await
                    .is_err(),
                "{table}"
            );
            assert_eq!(
                provider
                    .by_registration_access_token(TENANT, "deletion", &hash("initial"))
                    .await
                    .unwrap()
                    .unwrap()
                    .client,
                original
            );
            database.execute_sql("CREATE TEMP TABLE assertion(ok INTEGER CHECK(ok=1)); INSERT INTO assertion SELECT CASE WHEN EXISTS(SELECT 1 FROM nazo_refresh_families WHERE revoked_at IS NULL) AND EXISTS(SELECT 1 FROM nazo_grants) AND NOT EXISTS(SELECT 1 FROM nazo_audit WHERE event_type='dynamic_client_deleted') THEN 1 ELSE 0 END;").unwrap();
        }
    });
}

#[test]
fn registration_downgrade_requires_each_family_revocation_audit() {
    block_on(async {
        let (database, provider) = fixture().await;
        let original = insert(&provider, "downgrade-audit", true).await;
        family(&database, &original);
        let mut replacement = original.clone();
        replacement.registration.client_type = "public".into();
        replacement.registration.token_endpoint_auth_method = "none".into();
        database.execute_sql("CREATE TRIGGER suppress BEFORE INSERT ON nazo_audit WHEN NEW.event_type='refresh_family_security_revoked' BEGIN SELECT RAISE(IGNORE); END;").unwrap();
        assert!(
            provider
                .replace_registration(
                    &replacement,
                    None,
                    &hash("initial"),
                    Some(&hash("next")),
                    &hash("source")
                )
                .await
                .is_err()
        );
        assert_eq!(
            provider
                .by_registration_access_token(TENANT, "downgrade-audit", &hash("initial"))
                .await
                .unwrap()
                .unwrap()
                .client,
            original
        );
    });
}

#[test]
fn credential_rotation_has_one_concurrent_winner_and_preserves_public_identity() {
    let (_, provider) = block_on(fixture());
    let client = block_on(insert(&provider, "race", true));
    let provider = Arc::new(provider);
    let barrier = Arc::new(Barrier::new(12));
    let tasks = (0..12)
        .map(|index| {
            let provider = provider.clone();
            let barrier = barrier.clone();
            let mut client = client.clone();
            std::thread::spawn(move || {
                client.registration.client_id = "generated-during-prepare".into();
                client.registration.client_name = format!("winner-{index}");
                client.registration.allowed_audiences = vec!["https://attacker.example".into()];
                barrier.wait();
                let token = hash(&format!("next-{index}"));
                (
                    index,
                    block_on(provider.replace_registration(
                        &client,
                        Some("client-secret-v1:new:digest"),
                        &hash("initial"),
                        Some(&token),
                        &hash("source"),
                    )),
                )
            })
        })
        .collect::<Vec<_>>();
    let results = tasks
        .into_iter()
        .map(|task| task.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        results.iter().filter(|(_, result)| result.is_ok()).count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|(_, result)| matches!(result, Err(Error::StaleCredentials)))
            .count(),
        11
    );
    let (index, winner) = results
        .into_iter()
        .find(|(_, result)| result.is_ok())
        .unwrap();
    let winner = winner.unwrap();
    assert_eq!(winner.client_id, "race");
    assert_eq!(winner.allowed_audiences, ["https://api.example"]);
    block_on(async {
        assert!(
            provider
                .by_registration_access_token(TENANT, "race", &hash("initial"))
                .await
                .unwrap()
                .is_none()
        );
        let snapshot = provider
            .by_registration_access_token(TENANT, "race", &hash(&format!("next-{index}")))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.client.client_name, format!("winner-{index}"));
        assert_eq!(snapshot.secret_salt.as_deref(), Some("new"));
    });
}

#[test]
fn updates_recheck_live_scope_and_administrator_policy_before_rotating_authority() {
    block_on(async {
        for change in ["scopes", "policy"] {
            let (database, provider) = fixture().await;
            let client = insert(&provider, "ceiling", true).await;
            let change = if change == "scopes" {
                "json_set(registration,'$.scopes',json('[\"openid\"]'))"
            } else {
                "json_set(registration,'$.security_policy.require_pushed_authorization_requests',json('true'))"
            };
            database
                .execute_sql(&format!(
                    "UPDATE nazo_clients SET registration={change} WHERE id='{}'",
                    client.id
                ))
                .unwrap();
            assert_eq!(
                provider
                    .replace_registration(
                        &client,
                        Some("replacement-secret"),
                        &hash("initial"),
                        Some(&hash("next")),
                        &hash("source")
                    )
                    .await
                    .err(),
                Some(Error::PolicyChanged)
            );
            let current = provider
                .by_registration_access_token(TENANT, "ceiling", &hash("initial"))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(current.secret_salt.as_deref(), Some("salt"));
            assert!(
                provider
                    .by_registration_access_token(TENANT, "ceiling", &hash("next"))
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    });
}

#[test]
fn confidential_to_public_change_retires_existing_refresh_authority_atomically() {
    block_on(async {
        let (database, provider) = fixture().await;
        let mut client = insert(&provider, "downgrade", true).await;
        let family = family(&database, &client);
        assert!(
            provider
                .refresh_family_active(TENANT, family, USER)
                .await
                .unwrap()
        );
        client.registration.client_type = "public".into();
        client.registration.token_endpoint_auth_method = "none".into();
        let updated = provider
            .replace_registration(
                &client,
                None,
                &hash("initial"),
                Some(&hash("public")),
                &hash("source"),
            )
            .await
            .unwrap();
        assert_eq!(updated.client_type, "public");
        assert!(
            !provider
                .refresh_family_active(TENANT, family, USER)
                .await
                .unwrap()
        );
        database.execute_sql(&format!(
            "CREATE TABLE retained_family(value INTEGER CHECK(value=1));
             INSERT INTO retained_family SELECT count(*) FROM nazo_refresh_families WHERE id='{family}' AND revoked_at IS NOT NULL;
             INSERT INTO retained_family SELECT count(*) FROM nazo_audit WHERE event_type='refresh_family_security_revoked'
               AND json_extract(payload,'$.token_family_id')='{family}' AND json_extract(payload,'$.reason')='client_authentication_class_downgrade';"
        )).unwrap();
        let current = provider
            .by_registration_access_token(TENANT, "downgrade", &hash("public"))
            .await
            .unwrap()
            .unwrap();
        assert!(!current.has_client_secret);
    });
}

#[test]
fn deletion_revokes_refresh_grants_and_management_token_together() {
    block_on(async {
        let (database, provider) = fixture().await;
        let client = insert(&provider, "deleted", true).await;
        let family = family(&database, &client);
        assert!(
            provider
                .deactivate(TENANT, client.id, &hash("initial"), &hash("source"))
                .await
                .unwrap()
        );
        assert!(
            !provider
                .refresh_family_active(TENANT, family, USER)
                .await
                .unwrap()
        );
        assert!(
            provider
                .by_registration_access_token(TENANT, "deleted", &hash("initial"))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            !AdminClientRepositoryPort::by_client_id(&provider, TENANT, "deleted")
                .await
                .unwrap()
                .unwrap()
                .is_active
        );
        database.execute_sql(&format!(
            "CREATE TABLE no_grants(value INTEGER CHECK(value=0)); INSERT INTO no_grants SELECT count(*) FROM nazo_grants WHERE client_id='{}';",client.id
        )).unwrap();
        assert_eq!(
            provider
                .deactivate(TENANT, client.id, &hash("initial"), &hash("source"))
                .await
                .err(),
            Some(Error::StaleCredentials)
        );
    });
}

#[test]
fn required_audit_failure_rolls_back_insert_replacement_rotation_and_deletion() {
    block_on(async {
        let (database, provider) = fixture().await;
        let mut client = insert(&provider, "preserved", true).await;
        let family = family(&database, &client);
        database.execute_sql("CREATE TRIGGER fail_client_audit BEFORE INSERT ON nazo_audit WHEN NEW.category='client_lifecycle' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END;").unwrap();
        let mut failed_insert = prepared("failed", false);
        failed_insert.registration_access_token_blake3 = Some(hash("failed-insert"));
        assert!(
            DynamicRegistrationClientStore::insert(&provider, failed_insert, &hash("source"))
                .await
                .is_err()
        );
        assert!(
            AdminClientRepositoryPort::by_client_id(&provider, TENANT, "failed")
                .await
                .unwrap()
                .is_none()
        );
        client.registration.client_type = "public".into();
        client.registration.token_endpoint_auth_method = "none".into();
        assert!(
            provider
                .replace_registration(
                    &client,
                    None,
                    &hash("initial"),
                    Some(&hash("replaced")),
                    &hash("source")
                )
                .await
                .is_err()
        );
        assert!(
            provider
                .rotate_credentials(TENANT, client.id, None, &hash("initial"), &hash("rotated"))
                .await
                .is_err()
        );
        assert!(
            provider
                .deactivate(TENANT, client.id, &hash("initial"), &hash("source"))
                .await
                .is_err()
        );
        let current = provider
            .by_registration_access_token(TENANT, "preserved", &hash("initial"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.client.client_type, "confidential");
        assert!(current.has_client_secret);
        assert!(
            provider
                .refresh_family_active(TENANT, family, USER)
                .await
                .unwrap()
        );
    });
}

#[test]
fn adapter_preserves_shared_prepared_documents_ciba_and_mtls_binding_through_management() {
    block_on(async {
        let (_, provider) = fixture().await;
        let mut input = prepared("remote", true);
        input.registration.request_uris = vec!["https://client.example/request.jwt".into()];
        input.registration.jwks_uri = Some("https://client.example/jwks".into());
        input.registration.sector_identifier_uri = Some("https://client.example/sector".into());
        input.registration.backchannel_logout_uri = Some("https://client.example/logout".into());
        input
            .registration
            .grant_types
            .push("urn:openid:params:grant-type:ciba".into());
        input.require_mtls_bound_tokens = true;
        let inserted = DynamicRegistrationClientStore::insert(&provider, input, &hash("source"))
            .await
            .unwrap();
        assert!(inserted.require_mtls_bound_tokens);
        let stored = AdminClientRepositoryPort::by_client_id(&provider, TENANT, "remote")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored, inserted);
        let rotated = provider
            .rotate_credentials(
                TENANT,
                stored.id,
                Some("client-secret-v1:next:digest"),
                &hash("initial"),
                &hash("rotated"),
            )
            .await
            .unwrap();
        assert!(rotated.require_mtls_bound_tokens);
        let mut changed = rotated.clone();
        changed.require_mtls_bound_tokens = false;
        let replaced = provider
            .replace_registration(
                &changed,
                Some("client-secret-v1:next:digest"),
                &hash("rotated"),
                Some(&hash("final")),
                &hash("source"),
            )
            .await
            .unwrap();
        assert_eq!(replaced, changed);
        let snapshot = provider
            .by_registration_access_token(TENANT, "remote", &hash("final"))
            .await
            .unwrap()
            .unwrap();
        assert!(!snapshot.client.require_mtls_bound_tokens);
        assert_eq!(snapshot.client.registration, inserted.registration);
    });
}

#[test]
fn late_token_write_failure_rolls_back_policy_refresh_retirement_and_required_audit() {
    block_on(async {
        let (database, provider) = fixture().await;
        let mut client = insert(&provider, "late-failure", true).await;
        let family = family(&database, &client);
        database.execute_sql("CREATE TRIGGER fail_management_rotation BEFORE UPDATE ON nazo_client_registrations BEGIN SELECT RAISE(ABORT,'token store unavailable'); END;").unwrap();
        client.registration.client_type = "public".into();
        client.registration.token_endpoint_auth_method = "none".into();
        assert!(
            provider
                .replace_registration(
                    &client,
                    None,
                    &hash("initial"),
                    Some(&hash("next")),
                    &hash("source")
                )
                .await
                .is_err()
        );
        let current = provider
            .by_registration_access_token(TENANT, "late-failure", &hash("initial"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.client.client_type, "confidential");
        assert!(current.has_client_secret);
        assert!(
            provider
                .refresh_family_active(TENANT, family, USER)
                .await
                .unwrap()
        );
        database.execute_sql("CREATE TABLE no_committed_mutation(value INTEGER CHECK(value=0)); INSERT INTO no_committed_mutation SELECT count(*) FROM nazo_audit WHERE event_type IN ('dynamic_client_configuration_updated','refresh_family_security_revoked');").unwrap();
    });
}
