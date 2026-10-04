//! Exact trust-state/source-event/Required rollback and actual cancellation.
use super::*;
use diesel_async::{AsyncConnection,AsyncPgConnection,SimpleAsyncConnection};
use futures_util::FutureExt as _;

#[derive(QueryableByName)]
struct SnapshotRow {
    #[diesel(sql_type=Jsonb)] value:serde_json::Value,
}
#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type=diesel::sql_types::BigInt)] count:i64,
}
struct TrustFixture {
    tenant:TenantContext,requester:UserId,admin:UserId,client:Uuid,id:Uuid,
}

async fn fixture(url:&str, revoke:bool) -> TrustFixture {
    run_pending_migrations(url).await.unwrap();
    let tenant=TenantContext::default_system();let requester=UserId::new(Uuid::now_v7()).unwrap();
    let admin=UserId::new(Uuid::now_v7()).unwrap();let client=Uuid::now_v7();
    let suffix=Uuid::now_v7().simple().to_string();let client_id=format!("required-trust-{suffix}");
    let mut connection=AsyncPgConnection::establish(url).await.unwrap();
    for (user,role,level) in [(requester,"user",0),(admin,"admin",1)] {
        sql_query("INSERT INTO users (id,tenant_id,realm_id,organization_id,username,email,password_hash,role,admin_level) VALUES ($1,$2,$3,$4,$5,$6,'fixture',$7,$8)")
            .bind::<SqlUuid,_>(user.as_uuid()).bind::<SqlUuid,_>(tenant.tenant_id.as_uuid())
            .bind::<SqlUuid,_>(tenant.realm_id.as_uuid()).bind::<SqlUuid,_>(tenant.organization_id.as_uuid())
            .bind::<Text,_>(format!("required-trust-{role}-{suffix}"))
            .bind::<Text,_>(format!("required-trust-{role}-{suffix}@example.test"))
            .bind::<Text,_>(role).bind::<diesel::sql_types::Integer,_>(level).execute(&mut connection).await.unwrap();
    }
    sql_query("INSERT INTO oauth_clients (id,tenant_id,realm_id,organization_id,client_id,client_name,client_type,redirect_uris,scopes,grant_types,token_endpoint_auth_method,require_mtls_bound_tokens,security_policy) VALUES ($1,$2,$3,$4,$5,'required trust','confidential','[]'::jsonb,'[\"openid\"]'::jsonb,'[\"authorization_code\"]'::jsonb,'private_key_jwt',TRUE,$6)")
        .bind::<SqlUuid,_>(client).bind::<SqlUuid,_>(tenant.tenant_id.as_uuid())
        .bind::<SqlUuid,_>(tenant.realm_id.as_uuid()).bind::<SqlUuid,_>(tenant.organization_id.as_uuid())
        .bind::<Text,_>(&client_id).bind::<Jsonb,_>(serde_json::to_value(nazo_auth::ClientSecurityPolicy::default()).unwrap())
        .execute(&mut connection).await.unwrap();
    sql_query("INSERT INTO client_access_requests (tenant_id,user_id,site_name,site_url,request_description,status,resolved_by_user_id,approved_client_id,resolved_at) VALUES ($1,$2,'required trust','https://client.example','fixture',1,$3,$4,now())")
        .bind::<SqlUuid,_>(tenant.tenant_id.as_uuid()).bind::<SqlUuid,_>(requester.as_uuid())
        .bind::<SqlUuid,_>(admin.as_uuid()).bind::<SqlUuid,_>(client).execute(&mut connection).await.unwrap();
    let repository=MtlsTrustAnchorRepository::new(create_pool(url,1).unwrap());
    let id=repository.create_for_owned_client(request(tenant,requester,&client_id,'a')).await.unwrap().id;
    if revoke { repository.approve(tenant.tenant_id,id,admin,Some("initial approval".to_owned())).await.unwrap(); }
    TrustFixture{tenant,requester,admin,client,id}
}

async fn snapshot(connection:&mut AsyncPgConnection,f:&TrustFixture) -> serde_json::Value {
    sql_query("SELECT jsonb_build_object('request',COALESCE((SELECT jsonb_agg(to_jsonb(r)) FROM oauth_client_mtls_trust_anchor_requests r WHERE tenant_id=$1 AND id=$2),'[]'::jsonb),'source_events',COALESCE((SELECT jsonb_agg(to_jsonb(e) ORDER BY id) FROM oauth_client_mtls_trust_anchor_events e WHERE tenant_id=$1 AND request_id=$2),'[]'::jsonb),'required_events',COALESCE((SELECT jsonb_agg(to_jsonb(e) ORDER BY event_id) FROM security_audit_events e WHERE payload->>'tenant_id'=$1::text AND payload->>'request_id'=$2::text AND event_type IN ('mtls_trust_anchor_approved','mtls_trust_anchor_rejected','mtls_trust_anchor_revoked')),'[]'::jsonb)) AS value")
        .bind::<SqlUuid,_>(f.tenant.tenant_id.as_uuid()).bind::<SqlUuid,_>(f.id)
        .get_result::<SnapshotRow>(connection).await.unwrap().value
}

async fn cleanup(connection:&mut AsyncPgConnection,f:&TrustFixture) {
    sql_query("DELETE FROM oauth_client_mtls_trust_anchor_events WHERE request_id=$1").bind::<SqlUuid,_>(f.id).execute(connection).await.unwrap();
    sql_query("DELETE FROM oauth_client_mtls_trust_anchor_requests WHERE id=$1").bind::<SqlUuid,_>(f.id).execute(connection).await.unwrap();
    sql_query("DELETE FROM client_access_requests WHERE approved_client_id=$1").bind::<SqlUuid,_>(f.client).execute(connection).await.unwrap();
    sql_query("DELETE FROM oauth_clients WHERE id=$1").bind::<SqlUuid,_>(f.client).execute(connection).await.unwrap();
    sql_query("DELETE FROM users WHERE id=$1 OR id=$2").bind::<SqlUuid,_>(f.requester.as_uuid()).bind::<SqlUuid,_>(f.admin.as_uuid()).execute(connection).await.unwrap();
}

async fn mutate(repository:&MtlsTrustAnchorRepository,f:&TrustFixture,action:u8) -> Result<nazo_identity::MtlsTrustAnchorRequest,RepositoryError> {
    match action {
        0=>repository.approve(f.tenant.tenant_id,f.id,f.admin,Some("reviewed".to_owned())).await,
        1=>repository.reject(f.tenant.tenant_id,f.id,f.admin,Some("rejected".to_owned())).await,
        _=>repository.revoke(f.tenant.tenant_id,f.id,f.admin,"revoked".to_owned()).await,
    }
}

#[tokio::test]
async fn required_trust_append_fault_restores_approve_reject_revoke_and_every_event() {
    let Some(url)=database_url() else { return; };
    for action in [0,1,2] {
        let f=fixture(&url,action==2).await;
        let repository=MtlsTrustAnchorRepository::new(create_pool(&url,1).unwrap());
        let mut connection=AsyncPgConnection::establish(&url).await.unwrap();
        let before=snapshot(&mut connection,&f).await;
        let name=format!("trust_required_fault_{}",Uuid::now_v7().simple());
        connection.batch_execute(&format!("CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture required trust append fault'; END $$; CREATE TRIGGER {name} BEFORE INSERT ON security_audit_events FOR EACH ROW WHEN (NEW.event_type IN ('mtls_trust_anchor_approved','mtls_trust_anchor_rejected','mtls_trust_anchor_revoked') AND NEW.payload->>'request_id'='{}') EXECUTE FUNCTION {name}();",f.id)).await.unwrap();
        let body=std::panic::AssertUnwindSafe(async {
            assert_eq!(mutate(&repository,&f,action).await,Err(RepositoryError::Unavailable));
            assert_eq!(snapshot(&mut connection,&f).await,before);
        }).catch_unwind().await;
        connection.batch_execute(&format!("DROP TRIGGER {name} ON security_audit_events; DROP FUNCTION {name}();")).await.unwrap();
        cleanup(&mut connection,&f).await;
        if let Err(error)=body { std::panic::resume_unwind(error); }
    }
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn cancelled_trust_required_owner_releases_peer_lock_without_pool_checkout() {
    let Some(url)=database_url() else { return; };
    for action in [0,1,2] {
        let f=fixture(&url,action==2).await;
        let application=format!("trust-owner-{}",Uuid::now_v7().simple());let separator=if url.contains('?') {'&'} else {'?'};
        let pool=create_pool(format!("{url}{separator}application_name={application}"),1).unwrap();
        let repository=MtlsTrustAnchorRepository::new(pool.clone());
        let mut coordinator=AsyncPgConnection::establish(&url).await.unwrap();
        let mut observer=AsyncPgConnection::establish(&url).await.unwrap();
        let before=snapshot(&mut observer,&f).await;
        let name=format!("trust_required_gate_{}",Uuid::now_v7().simple());
        let gate=i64::from_be_bytes(Uuid::now_v7().as_bytes()[..8].try_into().unwrap());
        coordinator.batch_execute(&format!("CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock({gate}); RETURN NEW; END $$; CREATE TRIGGER {name} BEFORE INSERT ON security_audit_events FOR EACH ROW WHEN (NEW.event_type IN ('mtls_trust_anchor_approved','mtls_trust_anchor_rejected','mtls_trust_anchor_revoked') AND NEW.payload->>'request_id'='{}') EXECUTE FUNCTION {name}();",f.id)).await.unwrap();
        sql_query("SELECT pg_advisory_lock($1)").bind::<diesel::sql_types::BigInt,_>(gate).execute(&mut coordinator).await.unwrap();
        let owned=TrustFixture{tenant:f.tenant,requester:f.requester,admin:f.admin,client:f.client,id:f.id};
        let mut task=tokio::spawn(async move { mutate(&repository,&owned,action).await });
        let body=std::panic::AssertUnwindSafe(async {
            tokio::time::timeout(std::time::Duration::from_secs(5),async {
                loop {
                    assert!(!task.is_finished(),"owner must reach actual Required append");
                    let waiting=sql_query("SELECT COUNT(*)::bigint AS count FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock'").bind::<Text,_>(&application).get_result::<CountRow>(&mut coordinator).await.unwrap();
                    if waiting.count==1 {break;}
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }).await.expect("owner reached the canonical append gate");
            task.abort();assert!((&mut task).await.unwrap_err().is_cancelled());
            observer.batch_execute("BEGIN; SET LOCAL lock_timeout='3s'").await.unwrap();
            sql_query("SELECT id FROM oauth_client_mtls_trust_anchor_requests WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
                .bind::<SqlUuid,_>(f.tenant.tenant_id.as_uuid()).bind::<SqlUuid,_>(f.id).execute(&mut observer).await
                .expect("independent peer locks unchanged request before retained owner pool has another checkout");
            assert_eq!(snapshot(&mut observer,&f).await,before);
        }).catch_unwind().await;
        if !task.is_finished() { task.abort();let _=task.await; }
        observer.batch_execute("ROLLBACK").await.unwrap();drop(pool);
        sql_query("SELECT pg_advisory_unlock($1)").bind::<diesel::sql_types::BigInt,_>(gate).execute(&mut coordinator).await.unwrap();
        coordinator.batch_execute(&format!("DROP TRIGGER {name} ON security_audit_events; DROP FUNCTION {name}();")).await.unwrap();
        cleanup(&mut coordinator,&f).await;
        if let Err(error)=body { std::panic::resume_unwind(error); }
    }
}


#[derive(QueryableByName)]
struct ExpiredRow {
    #[diesel(sql_type=diesel::sql_types::Bool)] expired:bool,
}

#[tokio::test(flavor="multi_thread", worker_threads=2)]
async fn trust_approval_samples_time_after_tenant_lock_wait_across_expiry() {
    let Some(url)=database_url() else {return;};
    let f=fixture(&url,false).await;
    let application=format!("trust-clock-{}",Uuid::now_v7().simple());
    let separator=if url.contains('?') {'&'} else {'?'};
    let repository=MtlsTrustAnchorRepository::new(create_pool(format!("{url}{separator}application_name={application}"),1).unwrap());
    let mut coordinator=AsyncPgConnection::establish(&url).await.unwrap();
    let mut observer=AsyncPgConnection::establish(&url).await.unwrap();
    sql_query("UPDATE oauth_client_mtls_trust_anchor_requests SET not_after=clock_timestamp()+interval '2 seconds' WHERE tenant_id=$1 AND id=$2")
        .bind::<SqlUuid,_>(f.tenant.tenant_id.as_uuid()).bind::<SqlUuid,_>(f.id).execute(&mut coordinator).await.unwrap();
    let before=snapshot(&mut observer,&f).await;
    sql_query("SELECT pg_advisory_lock(hashtextextended($1::text,8705))")
        .bind::<SqlUuid,_>(f.tenant.tenant_id.as_uuid()).execute(&mut coordinator).await.unwrap();
    let tenant=f.tenant.tenant_id;let id=f.id;let admin=f.admin;
    let mut task=tokio::spawn(async move {repository.approve(tenant,id,admin,Some("clock wait".to_owned())).await});
    let result=std::panic::AssertUnwindSafe(async {
        tokio::time::timeout(std::time::Duration::from_secs(5),async {
            loop {
                assert!(!task.is_finished(),"approval must reach the real tenant lock");
                let waiting=sql_query("SELECT COUNT(*)::bigint AS count FROM pg_stat_activity owner JOIN oauth_client_mtls_trust_anchor_requests r ON r.tenant_id=$2 AND r.id=$3 WHERE owner.application_name=$1 AND owner.wait_event_type='Lock' AND owner.xact_start < r.not_after")
                    .bind::<Text,_>(&application).bind::<SqlUuid,_>(tenant.as_uuid()).bind::<SqlUuid,_>(id)
                    .get_result::<CountRow>(&mut observer).await.unwrap();
                if waiting.count==1 {break;}
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }).await.expect("transaction began before expiry and is waiting on tenant lock");
        tokio::time::timeout(std::time::Duration::from_secs(5),async {
            loop {
                let expired=sql_query("SELECT clock_timestamp()>=not_after AS expired FROM oauth_client_mtls_trust_anchor_requests WHERE tenant_id=$1 AND id=$2")
                    .bind::<SqlUuid,_>(tenant.as_uuid()).bind::<SqlUuid,_>(id).get_result::<ExpiredRow>(&mut observer).await.unwrap();
                if expired.expired {break;}
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }).await.expect("actual database clock passed certificate expiry while owner remained blocked");
        sql_query("SELECT pg_advisory_unlock(hashtextextended($1::text,8705))")
            .bind::<SqlUuid,_>(tenant.as_uuid()).execute(&mut coordinator).await.unwrap();
        assert_eq!(tokio::time::timeout(std::time::Duration::from_secs(5),&mut task).await.unwrap().unwrap(),Err(RepositoryError::Conflict));
        assert_eq!(snapshot(&mut observer,&f).await,before,
            "expired after lock wait must leave pending request and all events unchanged");
    }).catch_unwind().await;
    if !task.is_finished() {task.abort();let _=task.await;}
    sql_query("SELECT pg_advisory_unlock(hashtextextended($1::text,8705))")
        .bind::<SqlUuid,_>(tenant.as_uuid()).execute(&mut coordinator).await.unwrap();
    cleanup(&mut coordinator,&f).await;
    if let Err(error)=result {std::panic::resume_unwind(error);}
}

#[tokio::test(flavor="multi_thread", worker_threads=2)]
async fn trust_owner_rechecks_current_actor_and_approval_client_after_row_lock_wait() {
    let Some(url)=database_url() else {return;};
    for (action,disable_client) in [(0,false),(0,true),(1,false),(2,false)] {
        let f=fixture(&url,action==2).await;
        let application=format!("trust-current-{}",Uuid::now_v7().simple());
        let separator=if url.contains('?') {'&'} else {'?'};
        let repository=MtlsTrustAnchorRepository::new(create_pool(format!("{url}{separator}application_name={application}"),1).unwrap());
        let mut coordinator=AsyncPgConnection::establish(&url).await.unwrap();
        let mut observer=AsyncPgConnection::establish(&url).await.unwrap();
        let before=snapshot(&mut observer,&f).await;
        coordinator.batch_execute("BEGIN").await.unwrap();
        if disable_client {
            sql_query("UPDATE oauth_clients SET is_active=FALSE WHERE tenant_id=$1 AND id=$2")
                .bind::<SqlUuid,_>(f.tenant.tenant_id.as_uuid()).bind::<SqlUuid,_>(f.client).execute(&mut coordinator).await.unwrap();
        } else {
            sql_query("UPDATE users SET is_active=FALSE WHERE tenant_id=$1 AND id=$2")
                .bind::<SqlUuid,_>(f.tenant.tenant_id.as_uuid()).bind::<SqlUuid,_>(f.admin.as_uuid()).execute(&mut coordinator).await.unwrap();
        }
        let owned=TrustFixture{tenant:f.tenant,requester:f.requester,admin:f.admin,client:f.client,id:f.id};
        let mut task=tokio::spawn(async move {mutate(&repository,&owned,action).await});
        let result=std::panic::AssertUnwindSafe(async {
            tokio::time::timeout(std::time::Duration::from_secs(5),async {
                loop {
                    assert!(!task.is_finished(),"owner must wait on actual current authority row");
                    let waiting=sql_query("SELECT COUNT(*)::bigint AS count FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock'")
                        .bind::<Text,_>(&application).get_result::<CountRow>(&mut observer).await.unwrap();
                    if waiting.count==1 {break;}
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }).await.expect("actual actor/client row lock wait");
            coordinator.batch_execute("COMMIT").await.unwrap();
            assert_eq!(tokio::time::timeout(std::time::Duration::from_secs(5),&mut task).await.unwrap().unwrap(),Err(RepositoryError::Conflict));
            assert_eq!(snapshot(&mut observer,&f).await,before);
        }).catch_unwind().await;
        if !task.is_finished() {task.abort();let _=task.await;}
        coordinator.batch_execute("ROLLBACK").await.unwrap();
        cleanup(&mut coordinator,&f).await;
        if let Err(error)=result {std::panic::resume_unwind(error);}
    }
}
