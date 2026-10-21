use super::*;

use crate::repositories::query_counter;

#[tokio::test]
async fn apply_mappings_reuse_inserted_ids_and_batch_existing_active_clients() {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .expect("mapping regression requires the test database");
    crate::run_pending_migrations(&url).await.unwrap();
    let mut connection = AsyncPgConnection::establish(&url).await.unwrap();
    let tenant_id = Uuid::now_v7();
    let realm_id = Uuid::now_v7();
    let organization_id = Uuid::now_v7();
    sql_query("INSERT INTO tenants (id, slug, display_name, status) VALUES ($1, $2, 'mapping test', 'active')")
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Text, _>(format!("mapping-{tenant_id}"))
        .execute(&mut connection).await.unwrap();
    sql_query("INSERT INTO realms (id, tenant_id, slug, display_name) VALUES ($1, $2, $3, 'mapping test')")
        .bind::<sql_types::Uuid, _>(realm_id)
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Text, _>(format!("mapping-{realm_id}"))
        .execute(&mut connection).await.unwrap();
    sql_query("INSERT INTO organizations (id, tenant_id, slug, display_name) VALUES ($1, $2, $3, 'mapping test')")
        .bind::<sql_types::Uuid, _>(organization_id)
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Text, _>(format!("mapping-{organization_id}"))
        .execute(&mut connection).await.unwrap();
    let existing_ids = [Uuid::now_v7(), Uuid::now_v7()];
    let existing_public_ids = existing_ids.map(|id| format!("public-{id}"));
    for (id, public_id) in existing_ids.iter().zip(&existing_public_ids) {
        sql_query(
            "INSERT INTO oauth_clients
                (id, tenant_id, realm_id, organization_id, client_id, client_name,
                 client_type, redirect_uris, scopes, grant_types,
                 token_endpoint_auth_method, security_policy)
             VALUES ($1, $2, $3, $4, $5, 'mapping client', 'public',
                     '[]'::JSONB, '[\"openid\"]'::JSONB,
                     '[\"authorization_code\"]'::JSONB, 'none', $6)",
        )
        .bind::<sql_types::Uuid, _>(id)
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Uuid, _>(realm_id)
        .bind::<sql_types::Uuid, _>(organization_id)
        .bind::<sql_types::Text, _>(public_id)
        .bind::<sql_types::Jsonb, _>(
            serde_json::to_value(nazo_auth::ClientSecurityPolicy::default()).unwrap(),
        )
        .execute(&mut connection)
        .await
        .unwrap();
    }
    let new_id = Uuid::now_v7();
    let new_clients = BTreeMap::from([(new_id, "already-inserted-public-id")]);
    let mut locators = BTreeMap::new();
    let resources: Vec<_> = [new_id, existing_ids[0], existing_ids[1]]
        .into_iter()
        .enumerate()
        .map(|(index, id)| {
            let identity = TenantResourceIdentity {
                kind: TenantResourceKind::OauthClient,
                resource_id: format!("client-{index}"),
                digest: "a".repeat(64),
            };
            locators.insert(
                ResourceKey::from_identity(&identity),
                oauth_client_locator(id),
            );
            PreparedTenantResource {
                identity,
                payload: None,
            }
        })
        .collect();
    let counter = query_counter::QueryCounter::new();
    connection.set_instrumentation(counter.clone());
    let before = counter.snapshot();
    let created = collect_apply_resource_mappings(
        &mut connection,
        tenant_id,
        &resources[..1],
        &locators,
        &new_clients,
    )
    .await
    .unwrap();
    assert_eq!(created[0].public_id, "already-inserted-public-id");
    assert_eq!(counter.since(before).data_queries, 0);

    let before = counter.snapshot();
    let mixed = collect_apply_resource_mappings(
        &mut connection,
        tenant_id,
        &resources,
        &locators,
        &new_clients,
    )
    .await
    .unwrap();
    assert_eq!(counter.since(before).data_queries, 1);
    assert_eq!(mixed[0], created[0]);
    assert_eq!(mixed[1].public_id, existing_public_ids[0]);
    assert_eq!(mixed[2].public_id, existing_public_ids[1]);

    let wrong_tenant = collect_apply_resource_mappings(
        &mut connection,
        Uuid::now_v7(),
        &resources[1..],
        &locators,
        &new_clients,
    )
    .await;
    assert!(matches!(
        wrong_tenant,
        Err(ExecutorTransactionError::Executor(
            TenantResourceExecutorError::Conflict
        ))
    ));

    sql_query("UPDATE oauth_clients SET is_active = FALSE WHERE id = $1")
        .bind::<sql_types::Uuid, _>(existing_ids[0])
        .execute(&mut connection)
        .await
        .unwrap();
    let inactive = collect_apply_resource_mappings(
        &mut connection,
        tenant_id,
        &resources,
        &locators,
        &new_clients,
    )
    .await;
    assert!(matches!(
        inactive,
        Err(ExecutorTransactionError::Executor(
            TenantResourceExecutorError::Conflict
        ))
    ));
}

#[test]
fn replay_outcome_json_is_closed() {
    let outcome = StoredControlOutcome {
        revision: 4,
        resources: Vec::new(),
        resource_mappings: Vec::new(),
        resource_manifest_sha256: "a".repeat(64),
    };
    let encoded = serde_json::to_value(&outcome).unwrap();
    assert_eq!(
        serde_json::from_value::<StoredControlOutcome>(encoded).unwrap(),
        outcome
    );
    assert!(
        serde_json::from_value::<StoredControlOutcome>(serde_json::json!({
            "revision": 4,
            "resources": [],
            "resource_mappings": [],
            "resource_manifest_sha256": "a".repeat(64),
            "legacy_receipt": "forbidden"
        }))
        .is_err()
    );
}

#[test]
fn executor_rejects_an_outcome_that_the_journal_cannot_publish() {
    let outcome = StoredControlOutcome {
        revision: u64::MAX,
        resources: (0..nazo_operator_protocol::MAX_TENANT_RESOURCE_IDENTITIES)
            .map(|index| TenantResourceIdentity {
                kind: TenantResourceKind::User,
                resource_id: format!("resource-{index:03}-{}", "x".repeat(115)),
                digest: "f".repeat(64),
            })
            .collect(),
        resource_mappings: (0..nazo_operator_protocol::MAX_TENANT_RESOURCE_IDENTITIES)
            .map(|index| TenantResourceMapping {
                kind: TenantResourceKind::User,
                resource_id: format!("resource-{index:03}-{}", "x".repeat(115)),
                public_id: "00000000-0000-0000-0000-000000000001".to_owned(),
            })
            .collect(),
        resource_manifest_sha256: "a".repeat(64),
    };

    assert_eq!(
        outcome.into_result(TenantResourceAction::Apply),
        Err(TenantResourceExecutorError::TooLarge)
    );
}

#[tokio::test]
async fn managed_users_reapply_in_place_and_datasets_have_one_physical_owner() {
    use diesel_async::SimpleAsyncConnection as _;
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .expect("ownership regression requires real PostgreSQL");
    crate::run_pending_migrations(&url).await.unwrap();
    let mut connection = AsyncPgConnection::establish(&url).await.unwrap();
    connection.begin_test_transaction().await.unwrap();
    let tenant = TenantContext::default_system();
    let tenant_id = tenant.tenant_id.as_uuid();
    let suffix = Uuid::now_v7().simple().to_string();
    let user = TenantResourceIdentity {
        kind: TenantResourceKind::User,
        resource_id: format!("owner-{suffix}"),
        digest: "a".repeat(64),
    };
    let user_resources = vec![PreparedTenantResource {
        identity: user.clone(),
        payload: None,
    }];
    let user_payloads = vec![PreparedApplyPayload::User(Box::new(PreparedUser {
        identity: user.clone(),
        username: format!("owner-{suffix}"),
        email: format!("{suffix}@example.test"),
        password_hash: "fixture".into(),
        email_verified: true,
        profile: UserProfileFields::default(),
    }))];
    let key = Some([42; 32]);
    apply_resources(
        &mut connection,
        tenant_id,
        tenant,
        &user_resources,
        &user_payloads,
        &key,
    )
    .await
    .unwrap();
    let original = active_binding_map(&mut connection, tenant_id)
        .await
        .unwrap();
    let original = &original[&ResourceKey::from_identity(&user)].locator;
    revoke_resources(&mut connection, tenant_id, tenant, &user_resources)
        .await
        .unwrap();
    apply_resources(
        &mut connection,
        tenant_id,
        tenant,
        &user_resources,
        &user_payloads,
        &key,
    )
    .await
    .unwrap();
    let restored = active_binding_map(&mut connection, tenant_id)
        .await
        .unwrap();
    assert_eq!(
        &restored[&ResourceKey::from_identity(&user)].locator,
        original
    );
    let subject = parse_uuid_locator(original, TenantResourceKind::User).unwrap();
    #[derive(QueryableByName)]
    struct Epoch {
        #[diesel(sql_type=sql_types::BigInt)]
        epoch: i64,
    }
    let epoch = sql_query("SELECT access_token_epoch AS epoch FROM users WHERE id=$1")
        .bind::<sql_types::Uuid, _>(subject)
        .get_result::<Epoch>(&mut connection)
        .await
        .unwrap();
    assert_eq!(
        epoch.epoch, 1,
        "reactivation must retain the revocation epoch"
    );
    let dataset = |name: &str, claim: i64| {
        let identity = TenantResourceIdentity {
            kind: TenantResourceKind::Openid4vcDataset,
            resource_id: format!("{name}-{suffix}"),
            digest: "b".repeat(64),
        };
        (
            PreparedTenantResource {
                identity: identity.clone(),
                payload: None,
            },
            PreparedApplyPayload::Dataset(Box::new(PreparedDataset {
                identity,
                user_resource_id: user.resource_id.clone(),
                configuration_id: "credential".into(),
                claims: json!({"value":claim}),
            })),
        )
    };
    let (first, first_payload) = dataset("first", 1);
    apply_resources(
        &mut connection,
        tenant_id,
        tenant,
        &[first],
        &[first_payload],
        &key,
    )
    .await
    .unwrap();
    let (alias, alias_payload) = dataset("alias", 2);
    let rejected = apply_resources(
        &mut connection,
        tenant_id,
        tenant,
        &[alias],
        &[alias_payload],
        &key,
    )
    .await;
    assert!(matches!(
        rejected,
        Err(ExecutorTransactionError::Executor(
            TenantResourceExecutorError::Conflict
        ))
    ));
    // The database also enforces ownership for races whose initial snapshot did not
    // contain the other identity. The conflicting transaction must roll back.
    let duplicate = connection.transaction::<(),diesel::result::Error,_>(async |connection| {
        sql_query("INSERT INTO tenant_resource_bindings (id,tenant_id,resource_kind,resource_id,resource_digest,active,locator) VALUES ($1,$2,'openid4vc-dataset',$3,$4,true,$5)")
            .bind::<sql_types::Uuid,_>(Uuid::now_v7()).bind::<sql_types::Uuid,_>(tenant_id)
            .bind::<sql_types::Text,_>(format!("racing-{suffix}"))
            .bind::<sql_types::Text,_>("c".repeat(64))
            .bind::<sql_types::Text,_>(dataset_locator(subject,"credential"))
            .execute(connection).await?;
        Ok(())
    }).await;
    assert!(matches!(
        duplicate,
        Err(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _
        ))
    ));
    connection.batch_execute("ROLLBACK").await.unwrap();
}
