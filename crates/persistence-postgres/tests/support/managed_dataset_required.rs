//! Real encrypted dataset, source-event and canonical Required owner failures.
use super::*;
use futures_util::FutureExt as _;

#[derive(QueryableByName)]
struct SnapshotRow {
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    value: serde_json::Value,
}

struct DatasetFixture {
    tenant: Uuid,
    admin: Uuid,
    subject: Uuid,
    configuration: String,
}

async fn fixture(url: &str) -> DatasetFixture {
    nazo_postgres::run_pending_migrations(url).await.unwrap();
    let f = DatasetFixture {
        tenant: Uuid::from_u128(1), admin: Uuid::now_v7(), subject: Uuid::now_v7(),
        configuration: format!("required-dataset-{}", Uuid::now_v7().simple()),
    };
    let mut connection = AsyncPgConnection::establish(url).await.unwrap();
    for (id, role, level) in [(f.admin,"admin",1),(f.subject,"user",0)] {
        sql_query("INSERT INTO users (id,tenant_id,realm_id,organization_id,username,email,password_hash,role,admin_level) VALUES ($1,$2,$3,$4,$5,$6,'fixture',$7,$8)")
            .bind::<SqlUuid,_>(id).bind::<SqlUuid,_>(f.tenant)
            .bind::<SqlUuid,_>(Uuid::from_u128(2)).bind::<SqlUuid,_>(Uuid::from_u128(3))
            .bind::<Text,_>(format!("required-dataset-{id}"))
            .bind::<Text,_>(format!("required-dataset-{id}@example.test"))
            .bind::<Text,_>(role).bind::<diesel::sql_types::Integer,_>(level)
            .execute(&mut connection).await.unwrap();
    }
    f
}

async fn cleanup(connection: &mut AsyncPgConnection, f: &DatasetFixture) {
    sql_query("DELETE FROM users WHERE tenant_id=$1 AND (id=$2 OR id=$3)")
        .bind::<SqlUuid,_>(f.tenant).bind::<SqlUuid,_>(f.admin).bind::<SqlUuid,_>(f.subject)
        .execute(connection).await.unwrap();
}

async fn snapshot(connection: &mut AsyncPgConnection, f: &DatasetFixture) -> serde_json::Value {
    sql_query("SELECT jsonb_build_object('dataset',COALESCE((SELECT jsonb_agg(to_jsonb(d)) FROM openid4vci_credential_datasets d WHERE tenant_id=$1 AND subject_id=$2 AND credential_configuration_id=$3),'[]'::jsonb),'source_events',COALESCE((SELECT jsonb_agg(to_jsonb(e) ORDER BY id) FROM openid4vci_credential_dataset_events e WHERE tenant_id=$1 AND subject_id=$2 AND credential_configuration_id=$3),'[]'::jsonb),'required_events',COALESCE((SELECT jsonb_agg(to_jsonb(e) ORDER BY event_id) FROM security_audit_events e WHERE event_type IN ('openid4vci_credential_dataset_updated','openid4vci_credential_dataset_deleted') AND payload->>'tenant_id'=$1::text AND payload->>'subject_id'=$2::text AND payload->>'credential_configuration_id'=$3),'[]'::jsonb)) AS value")
        .bind::<SqlUuid,_>(f.tenant).bind::<SqlUuid,_>(f.subject).bind::<Text,_>(&f.configuration)
        .get_result::<SnapshotRow>(connection).await.unwrap().value
}

async fn put(repo: &Openid4vciDatasetRepository, f: &DatasetFixture, claims: &serde_json::Value) -> Result<bool, CredentialStoreError> {
    repo.upsert_managed_dataset(ManagedCredentialDatasetWrite {
        tenant_id:f.tenant, actor_user_id:f.admin, subject_id:f.subject,
        credential_configuration_id:&f.configuration, claims,
        valid_from:Some(Utc::now()-Duration::hours(1)), valid_until:Some(Utc::now()+Duration::hours(1)),
    }).await
}

#[tokio::test]
async fn required_dataset_append_fault_rolls_back_exact_ciphertext_source_events_and_ledger() {
    let Some(url)=database_url() else { return; };
    let f=fixture(&url).await;
    let repo=Openid4vciDatasetRepository::new(create_pool(&url,1).unwrap(),[0x71;32]);
    assert!(put(&repo,&f,&serde_json::json!({"given_name":"original"})).await.unwrap());
    let mut connection=AsyncPgConnection::establish(&url).await.unwrap();
    let before=snapshot(&mut connection,&f).await;
    let name=format!("dataset_required_fault_{}",Uuid::now_v7().simple());
    connection.batch_execute(&format!("CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture required dataset append fault'; END $$; CREATE TRIGGER {name} BEFORE INSERT ON security_audit_events FOR EACH ROW WHEN (NEW.event_type IN ('openid4vci_credential_dataset_updated','openid4vci_credential_dataset_deleted') AND NEW.payload->>'subject_id'='{}') EXECUTE FUNCTION {name}();",f.subject)).await.unwrap();
    let body=std::panic::AssertUnwindSafe(async {
        assert!(matches!(put(&repo,&f,&serde_json::json!({"given_name":"replacement"})).await,Err(CredentialStoreError::Unavailable)));
        assert_eq!(snapshot(&mut connection,&f).await,before);
        assert!(matches!(repo.delete_managed_dataset(f.tenant,f.admin,f.subject,&f.configuration).await,Err(CredentialStoreError::Unavailable)));
        assert_eq!(snapshot(&mut connection,&f).await,before);
    }).catch_unwind().await;
    connection.batch_execute(&format!("DROP TRIGGER {name} ON security_audit_events; DROP FUNCTION {name}();")).await.unwrap();
    cleanup(&mut connection,&f).await;
    if let Err(error)=body { std::panic::resume_unwind(error); }
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn cancelled_dataset_required_owner_releases_peer_row_lock_without_pool_checkout() {
    let Some(url)=database_url() else { return; };
    for delete in [false,true] {
        let f=fixture(&url).await;
        let application=format!("dataset-owner-{}",Uuid::now_v7().simple());
        let separator=if url.contains('?') {'&'} else {'?'};
        let pool=create_pool(format!("{url}{separator}application_name={application}"),1).unwrap();
        let repo=Openid4vciDatasetRepository::new(pool.clone(),[0x72;32]);
        assert!(put(&repo,&f,&serde_json::json!({"given_name":"original"})).await.unwrap());
        let mut coordinator=AsyncPgConnection::establish(&url).await.unwrap();
        let mut observer=AsyncPgConnection::establish(&url).await.unwrap();
        let before=snapshot(&mut observer,&f).await;
        let name=format!("dataset_required_gate_{}",Uuid::now_v7().simple());
        let gate=i64::from_be_bytes(Uuid::now_v7().as_bytes()[..8].try_into().unwrap());
        coordinator.batch_execute(&format!("CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock({gate}); RETURN NEW; END $$; CREATE TRIGGER {name} BEFORE INSERT ON security_audit_events FOR EACH ROW WHEN (NEW.event_type IN ('openid4vci_credential_dataset_updated','openid4vci_credential_dataset_deleted') AND NEW.payload->>'subject_id'='{}') EXECUTE FUNCTION {name}();",f.subject)).await.unwrap();
        sql_query("SELECT pg_advisory_lock($1)").bind::<BigInt,_>(gate).execute(&mut coordinator).await.unwrap();
        let tenant=f.tenant;let admin=f.admin;let subject=f.subject;let configuration=f.configuration.clone();
        let mut task=tokio::spawn(async move {
            if delete { repo.delete_managed_dataset(tenant,admin,subject,&configuration).await }
            else { repo.upsert_managed_dataset(ManagedCredentialDatasetWrite {tenant_id:tenant,actor_user_id:admin,subject_id:subject,credential_configuration_id:&configuration,claims:&serde_json::json!({"given_name":"replacement"}),valid_from:None,valid_until:None}).await }
        });
        let body=std::panic::AssertUnwindSafe(async {
            tokio::time::timeout(std::time::Duration::from_secs(5),async {
                loop {
                    assert!(!task.is_finished(),"owner must reach the actual canonical append wait");
                    let waiting=sql_query("SELECT COUNT(*)::bigint AS count FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock'").bind::<Text,_>(&application).get_result::<CountRow>(&mut coordinator).await.unwrap();
                    if waiting.count==1 { break; }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }).await.expect("actual owner reached the append barrier");
            task.abort();assert!((&mut task).await.unwrap_err().is_cancelled());
            observer.batch_execute("BEGIN; SET LOCAL lock_timeout='3s'").await.unwrap();
            sql_query("SELECT subject_id FROM openid4vci_credential_datasets WHERE tenant_id=$1 AND subject_id=$2 AND credential_configuration_id=$3 FOR UPDATE")
                .bind::<SqlUuid,_>(f.tenant).bind::<SqlUuid,_>(f.subject).bind::<Text,_>(&f.configuration)
                .execute(&mut observer).await.expect("independent peer acquires the original dataset row while retained owner pool has no checkout");
            assert_eq!(snapshot(&mut observer,&f).await,before);
        }).catch_unwind().await;
        if !task.is_finished() { task.abort();let _=task.await; }
        observer.batch_execute("ROLLBACK").await.unwrap();
        drop(pool);
        sql_query("SELECT pg_advisory_unlock($1)").bind::<BigInt,_>(gate).execute(&mut coordinator).await.unwrap();
        coordinator.batch_execute(&format!("DROP TRIGGER {name} ON security_audit_events; DROP FUNCTION {name}();")).await.unwrap();
        cleanup(&mut coordinator,&f).await;
        if let Err(error)=body { std::panic::resume_unwind(error); }
    }
}


// Fault-contract injection: production event validators currently return NEW.
// A zero-row source event or effect must never be confused with a real no-op.
#[tokio::test]
async fn dataset_fault_contract_rejects_suppressed_effect_source_and_required_events() {
    let Some(url) = database_url() else { return; };
    for (delete, fault) in [
        (false, "source"), (true, "source"),
        (false, "effect"), (true, "effect"),
        (false, "ciphertext"), (false, "required"), (true, "required"),
    ] {
        let f = fixture(&url).await;
        let repository = Openid4vciDatasetRepository::new(create_pool(&url, 1).unwrap(), [0x73; 32]);
        assert!(put(&repository, &f, &serde_json::json!({"given_name":"original"})).await.unwrap());
        let mut connection = AsyncPgConnection::establish(&url).await.unwrap();
        let before = snapshot(&mut connection, &f).await;
        let name = format!("dataset_contract_fault_{}", Uuid::now_v7().simple());
        let (table, operation, condition, body) = match fault {
            "source" => ("openid4vci_credential_dataset_events", "INSERT",
                format!("NEW.subject_id='{}'", f.subject), "RETURN NULL;"),
            "effect" => ("openid4vci_credential_datasets", if delete {"DELETE"} else {"UPDATE"},
                format!("OLD.subject_id='{}'", f.subject), "RETURN NULL;"),
            "ciphertext" => ("openid4vci_credential_datasets", "UPDATE",
                format!("OLD.subject_id='{}'", f.subject),
                "NEW.claims_ciphertext := decode(repeat('00', 29), 'hex'); RETURN NEW;"),
            _ => ("security_audit_events", "INSERT",
                format!("NEW.payload->>'subject_id'='{}' AND NEW.event_type IN ('openid4vci_credential_dataset_updated','openid4vci_credential_dataset_deleted')", f.subject),
                "RETURN NULL;"),
        };
        connection.batch_execute(&format!(
            "CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN {body} END $$; CREATE TRIGGER {name} BEFORE {operation} ON {table} FOR EACH ROW WHEN ({condition}) EXECUTE FUNCTION {name}();"
        )).await.unwrap();
        let result = std::panic::AssertUnwindSafe(async {
            let changed = if delete {
                repository.delete_managed_dataset(f.tenant, f.admin, f.subject, &f.configuration).await
            } else {
                put(&repository, &f, &serde_json::json!({"given_name":"replacement"})).await
            };
            assert_eq!(changed, Err(CredentialStoreError::Unavailable), "fault {fault}, delete={delete}");
            assert_eq!(snapshot(&mut connection, &f).await, before,
                "fault must preserve exact ciphertext, source events and canonical ledger");
        }).catch_unwind().await;
        connection.batch_execute(&format!("DROP TRIGGER {name} ON {table}; DROP FUNCTION {name}();")).await.unwrap();
        cleanup(&mut connection, &f).await;
        if let Err(error) = result { std::panic::resume_unwind(error); }
    }
}

#[tokio::test]
async fn dataset_put_returns_actual_stored_validity_before_ack() {
    let Some(url) = database_url() else { return; };
    let f = fixture(&url).await;
    let repository = Openid4vciDatasetRepository::new(create_pool(&url, 1).unwrap(), [0x74; 32]);
    assert!(put(&repository, &f, &serde_json::json!({"given_name":"original"})).await.unwrap());
    let mut connection = AsyncPgConnection::establish(&url).await.unwrap();
    let name = format!("dataset_projection_contract_{}", Uuid::now_v7().simple());
    connection.batch_execute(&format!(
        "CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.valid_from := now() - interval '2 hours'; RETURN NEW; END $$; CREATE TRIGGER {name} BEFORE UPDATE ON openid4vci_credential_datasets FOR EACH ROW WHEN (OLD.subject_id='{}') EXECUTE FUNCTION {name}();", f.subject
    )).await.unwrap();
    let result = std::panic::AssertUnwindSafe(async {
        let view = nazo_persistence::Openid4vciDatasetStore::upsert_managed_dataset(
            &repository, nazo_persistence::ManagedCredentialDatasetWrite {
                tenant_id:f.tenant, actor_user_id:f.admin, subject_id:f.subject,
                credential_configuration_id:f.configuration.clone(),
                claims:serde_json::json!({"given_name":"actual projection"}),
                valid_from:None, valid_until:None,
            },
        ).await.unwrap().unwrap();
        let durable = repository.managed_dataset(f.tenant, f.subject, &f.configuration).await.unwrap().unwrap();
        assert_eq!(view.claims, durable.claims);
        assert_eq!(view.valid_from, durable.valid_from);
        assert!(view.valid_from.is_some(), "request None must not replace the actual stored value");
        assert_eq!(view.valid_until, durable.valid_until);
        assert_eq!(view.updated_at, durable.updated_at);
        let after = snapshot(&mut connection, &f).await;
        assert_eq!(after["source_events"].as_array().unwrap().len(), 2);
        assert_eq!(after["required_events"].as_array().unwrap().len(), 2);
        assert!(after["required_events"].as_array().unwrap().iter().all(|event|
            event["event_category"] == "credential_lifecycle"
                && event["payload"]["event_category"] == "credential_lifecycle"));
    }).catch_unwind().await;
    connection.batch_execute(&format!("DROP TRIGGER {name} ON openid4vci_credential_datasets; DROP FUNCTION {name}();")).await.unwrap();
    cleanup(&mut connection, &f).await;
    if let Err(error) = result { std::panic::resume_unwind(error); }
}

#[tokio::test]
async fn dataset_real_noop_does_not_append_accepting_evidence() {
    let Some(url) = database_url() else { return; };
    let f = fixture(&url).await;
    let repository = Openid4vciDatasetRepository::new(create_pool(&url, 1).unwrap(), [0x75; 32]);
    let mut connection = AsyncPgConnection::establish(&url).await.unwrap();
    let empty = snapshot(&mut connection, &f).await;
    assert!(!repository.delete_managed_dataset(f.tenant, f.admin, f.subject, &f.configuration).await.unwrap());
    assert_eq!(snapshot(&mut connection, &f).await, empty);
    assert!(put(&repository, &f, &serde_json::json!({"given_name":"original"})).await.unwrap());
    sql_query("UPDATE users SET is_active=FALSE WHERE tenant_id=$1 AND id=$2")
        .bind::<SqlUuid,_>(f.tenant).bind::<SqlUuid,_>(f.admin).execute(&mut connection).await.unwrap();
    let before = snapshot(&mut connection, &f).await;
    assert!(!put(&repository, &f, &serde_json::json!({"given_name":"denied"})).await.unwrap());
    assert!(!repository.delete_managed_dataset(f.tenant, f.admin, f.subject, &f.configuration).await.unwrap());
    assert_eq!(snapshot(&mut connection, &f).await, before);
    sql_query("UPDATE users SET is_active=TRUE WHERE tenant_id=$1 AND id=$2")
        .bind::<SqlUuid,_>(f.tenant).bind::<SqlUuid,_>(f.admin).execute(&mut connection).await.unwrap();
    sql_query("UPDATE openid4vci_credential_datasets SET source='operator-managed' WHERE tenant_id=$1 AND subject_id=$2 AND credential_configuration_id=$3")
        .bind::<SqlUuid,_>(f.tenant).bind::<SqlUuid,_>(f.subject).bind::<Text,_>(&f.configuration).execute(&mut connection).await.unwrap();
    let before = snapshot(&mut connection, &f).await;
    assert!(!put(&repository, &f, &serde_json::json!({"given_name":"denied"})).await.unwrap());
    assert!(!repository.delete_managed_dataset(f.tenant, f.admin, f.subject, &f.configuration).await.unwrap());
    assert_eq!(snapshot(&mut connection, &f).await, before);
    cleanup(&mut connection, &f).await;
}

#[tokio::test(flavor="multi_thread", worker_threads=2)]
async fn dataset_owner_rechecks_actor_and_subject_after_real_row_lock_wait() {
    let Some(url) = database_url() else { return; };
    for (delete, disable_subject) in [(false,false),(false,true),(true,false)] {
        let f = fixture(&url).await;
        let application = format!("dataset-current-{}", Uuid::now_v7().simple());
        let separator = if url.contains('?') {'&'} else {'?'};
        let pool = create_pool(format!("{url}{separator}application_name={application}"), 1).unwrap();
        let repository = Openid4vciDatasetRepository::new(pool, [0x76; 32]);
        assert!(put(&repository, &f, &serde_json::json!({"given_name":"original"})).await.unwrap());
        let mut coordinator = AsyncPgConnection::establish(&url).await.unwrap();
        let mut observer = AsyncPgConnection::establish(&url).await.unwrap();
        let before = snapshot(&mut observer, &f).await;
        coordinator.batch_execute("BEGIN").await.unwrap();
        sql_query("UPDATE users SET is_active=FALSE WHERE tenant_id=$1 AND id=$2")
            .bind::<SqlUuid,_>(f.tenant).bind::<SqlUuid,_>(if disable_subject {f.subject} else {f.admin})
            .execute(&mut coordinator).await.unwrap();
        let owned = DatasetFixture {tenant:f.tenant,admin:f.admin,subject:f.subject,configuration:f.configuration.clone()};
        let mut task = tokio::spawn(async move {
            if delete { repository.delete_managed_dataset(owned.tenant,owned.admin,owned.subject,&owned.configuration).await }
            else { put(&repository,&owned,&serde_json::json!({"given_name":"denied after wait"})).await }
        });
        let result = std::panic::AssertUnwindSafe(async {
            tokio::time::timeout(std::time::Duration::from_secs(5),async {
                loop {
                    assert!(!task.is_finished(), "owner must wait on the actual authority row");
                    let waiting=sql_query("SELECT COUNT(*)::bigint AS count FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock'")
                        .bind::<Text,_>(&application).get_result::<CountRow>(&mut observer).await.unwrap();
                    if waiting.count==1 {break;}
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }).await.expect("actual actor/subject lock wait");
            coordinator.batch_execute("COMMIT").await.unwrap();
            assert!(!tokio::time::timeout(std::time::Duration::from_secs(5), &mut task).await.unwrap().unwrap().unwrap());
            assert_eq!(snapshot(&mut observer,&f).await,before);
        }).catch_unwind().await;
        if !task.is_finished() {task.abort();let _=task.await;}
        coordinator.batch_execute("ROLLBACK").await.unwrap();
        cleanup(&mut coordinator,&f).await;
        if let Err(error)=result {std::panic::resume_unwind(error);}
    }
}
