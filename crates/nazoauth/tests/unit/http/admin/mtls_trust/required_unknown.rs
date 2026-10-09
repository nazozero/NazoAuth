//! Real committed trust mutations with a semantic ACK hidden at the port.
use super::*;
use chrono::Utc;
use diesel::{
    sql_query,
    sql_types::{Jsonb, Text, Uuid as SqlUuid},
};
use diesel_async::RunQueryDsl;
use fred::interfaces::ClientLike;
use nazo_identity::ports::{MtlsTrustAnchorStore, RepositoryError, RepositoryFuture};
use nazo_identity::{
    MtlsTrustAnchorRequest, MtlsTrustAnchorRequestPage, MtlsTrustAnchorStatus,
    NewMtlsTrustAnchorRequest, TenantContext, TenantId, UserId,
};
use nazo_postgres::{MtlsTrustAnchorRepository, get_conn};
use serde_json::{Value, json};
use uuid::Uuid;

struct HiddenTrustCommitAck {
    inner: MtlsTrustAnchorRepository,
}
impl MtlsTrustAnchorStore for HiddenTrustCommitAck {
    fn create_for_owned_client(
        &self,
        request: NewMtlsTrustAnchorRequest,
    ) -> RepositoryFuture<'_, MtlsTrustAnchorRequest> {
        MtlsTrustAnchorStore::create_for_owned_client(&self.inner, request)
    }
    fn list_for_user(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> RepositoryFuture<'_, Vec<MtlsTrustAnchorRequest>> {
        MtlsTrustAnchorStore::list_for_user(&self.inner, tenant, user)
    }
    fn page(
        &self,
        tenant: TenantId,
        status: Option<MtlsTrustAnchorStatus>,
        limit: i64,
        offset: i64,
    ) -> RepositoryFuture<'_, MtlsTrustAnchorRequestPage> {
        MtlsTrustAnchorStore::page(&self.inner, tenant, status, limit, offset)
    }
    fn by_id(
        &self,
        tenant: TenantId,
        id: Uuid,
    ) -> RepositoryFuture<'_, Option<MtlsTrustAnchorRequest>> {
        MtlsTrustAnchorStore::by_id(&self.inner, tenant, id)
    }
    fn approve(
        &self,
        tenant: TenantId,
        id: Uuid,
        actor: UserId,
        note: Option<String>,
    ) -> RepositoryFuture<'_, MtlsTrustAnchorRequest> {
        Box::pin(async move {
            self.inner.approve(tenant, id, actor, note).await?;
            Err(RepositoryError::Unavailable)
        })
    }
    fn reject(
        &self,
        tenant: TenantId,
        id: Uuid,
        actor: UserId,
        note: Option<String>,
    ) -> RepositoryFuture<'_, MtlsTrustAnchorRequest> {
        Box::pin(async move {
            self.inner.reject(tenant, id, actor, note).await?;
            Err(RepositoryError::Unavailable)
        })
    }
    fn revoke(
        &self,
        tenant: TenantId,
        id: Uuid,
        actor: UserId,
        note: String,
    ) -> RepositoryFuture<'_, MtlsTrustAnchorRequest> {
        Box::pin(async move {
            self.inner.revoke(tenant, id, actor, note).await?;
            Err(RepositoryError::Unavailable)
        })
    }
    fn active_bundle(
        &self,
        tenant: TenantId,
        client: Option<Uuid>,
    ) -> RepositoryFuture<'_, String> {
        MtlsTrustAnchorStore::active_bundle(&self.inner, tenant, client)
    }
}

#[derive(diesel::QueryableByName)]
struct Evidence {
    #[diesel(sql_type=Jsonb)]
    value: Value,
}

#[actix_web::test]
async fn hidden_committed_trust_ack_is_503_for_approve_reject_and_revoke_with_required_evidence() {
    let Some(database_url) = std::env::var("DATABASE_URL").ok() else {
        return;
    };
    let Some(valkey_url) = std::env::var("VALKEY_URL").ok() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .unwrap();
    let valkey =
        fred::prelude::Builder::from_config(fred::prelude::Config::from_url(&valkey_url).unwrap())
            .build()
            .unwrap();
    valkey.init().await.unwrap();
    let pool = create_pool(&database_url, 4).unwrap();
    crate::test_support::initialize_audit_dependencies(&pool);
    let state = TestInfrastructure {
        diesel_db: pool.clone(),
        valkey,
        settings: Arc::new(Settings::from_config(&ConfigSource::default()).unwrap()),
        keyset: crate::test_support::test_key_manager(),
    };
    let tenant = TenantContext::default_system();
    let admin = UserId::new(Uuid::now_v7()).unwrap();
    let requester = UserId::new(Uuid::now_v7()).unwrap();
    let client = Uuid::now_v7();
    let suffix = Uuid::now_v7().simple().to_string();
    let client_id = format!("http-required-trust-{suffix}");
    let mut connection = get_conn(&pool).await.unwrap();
    for (user, role, level) in [(admin, "admin", 1), (requester, "user", 0)] {
        sql_query("INSERT INTO users (id,tenant_id,realm_id,organization_id,username,email,password_hash,role,admin_level,mfa_enabled) VALUES ($1,$2,$3,$4,$5,$6,'fixture',$7,$8,TRUE)")
            .bind::<SqlUuid,_>(user.as_uuid()).bind::<SqlUuid,_>(tenant.tenant_id.as_uuid()).bind::<SqlUuid,_>(tenant.realm_id.as_uuid()).bind::<SqlUuid,_>(tenant.organization_id.as_uuid())
            .bind::<Text,_>(format!("http-required-trust-{role}-{suffix}")).bind::<Text,_>(format!("http-required-trust-{role}-{suffix}@example.test"))
            .bind::<Text,_>(role).bind::<diesel::sql_types::Integer,_>(level).execute(&mut connection).await.unwrap();
    }
    sql_query("INSERT INTO oauth_clients (id,tenant_id,realm_id,organization_id,client_id,client_name,client_type,redirect_uris,scopes,grant_types,token_endpoint_auth_method,require_mtls_bound_tokens,security_policy) VALUES ($1,$2,$3,$4,$5,'HTTP required trust','confidential','[]'::jsonb,'[\"openid\"]'::jsonb,'[\"authorization_code\"]'::jsonb,'private_key_jwt',TRUE,$6)")
        .bind::<SqlUuid,_>(client).bind::<SqlUuid,_>(tenant.tenant_id.as_uuid()).bind::<SqlUuid,_>(tenant.realm_id.as_uuid()).bind::<SqlUuid,_>(tenant.organization_id.as_uuid())
        .bind::<Text,_>(&client_id).bind::<Jsonb,_>(serde_json::to_value(nazo_auth::ClientSecurityPolicy::default()).unwrap()).execute(&mut connection).await.unwrap();
    sql_query("INSERT INTO client_access_requests (tenant_id,user_id,site_name,site_url,request_description,status,resolved_by_user_id,approved_client_id,resolved_at) VALUES ($1,$2,'HTTP trust','https://client.example','fixture',1,$3,$4,now())")
        .bind::<SqlUuid,_>(tenant.tenant_id.as_uuid()).bind::<SqlUuid,_>(requester.as_uuid()).bind::<SqlUuid,_>(admin.as_uuid()).bind::<SqlUuid,_>(client).execute(&mut connection).await.unwrap();
    drop(connection);
    let sid = format!("trust-required-sid-{suffix}");
    let csrf = format!("trust-required-csrf-{suffix}");
    let key = nazo_valkey::test_support::state_storage_key(format!("oauth:session:{sid}"));
    let payload = nazo_oauth_server::sessions::SessionPayload {
        user_id: admin.as_uuid(),
        auth_time: Utc::now().timestamp(),
        amr: vec!["pwd".to_owned(), "otp".to_owned(), "mfa".to_owned()],
        pending_mfa: false,
        oidc_sid: Some(format!("oidc-{sid}")),
    };
    crate::test_support::valkey::valkey_set_ex(
        &state.valkey,
        key.clone(),
        serde_json::to_string(&payload).unwrap(),
        state.settings.session.session_ttl_seconds,
    )
    .await
    .unwrap();
    let sessions = web::Data::new(admin_session_handles(&state));
    let repository = MtlsTrustAnchorRepository::new(pool.clone());
    let service: web::Data<super::super::MtlsTrustAnchorService> =
        web::Data::from(Arc::new(HiddenTrustCommitAck {
            inner: repository.clone(),
        }) as Arc<dyn MtlsTrustAnchorStore>);
    let body = std::panic::AssertUnwindSafe(async {
        for action in [0, 1, 2] {
            let id = repository
                .create_for_owned_client(NewMtlsTrustAnchorRequest {
                    tenant_id: tenant.tenant_id,
                    user_id: requester,
                    client_id: client_id.clone(),
                    certificate_pem:
                        "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n".to_owned(),
                    certificate_sha256: std::iter::repeat_n(['a', 'b', 'c'][action], 64).collect(),
                    subject_dn: "CN=Required trust fixture".to_owned(),
                    not_before: Utc::now() - chrono::Duration::hours(1),
                    not_after: Utc::now() + chrono::Duration::hours(1),
                })
                .await
                .unwrap()
                .id;
            if action == 2 {
                repository
                    .approve(
                        tenant.tenant_id,
                        id,
                        admin,
                        Some("initial approval".to_owned()),
                    )
                    .await
                    .unwrap();
            }
            let req = TestRequest::post()
                .cookie(actix_web::cookie::Cookie::new(
                    state.settings.session.session_cookie_name.clone(),
                    sid.clone(),
                ))
                .cookie(actix_web::cookie::Cookie::new(
                    state.settings.session.csrf_cookie_name.clone(),
                    csrf.clone(),
                ))
                .insert_header(("x-csrf-token", csrf.clone()))
                .to_http_request();
            let response = match action {
                0 => {
                    super::super::admin_approve_mtls_trust_request(
                        sessions.clone(),
                        service.clone(),
                        req,
                        web::Path::from(id),
                        web::Json(super::super::TrustDecision {
                            admin_note: Some("reviewed".to_owned()),
                        }),
                    )
                    .await
                }
                1 => {
                    super::super::admin_reject_mtls_trust_request(
                        sessions.clone(),
                        service.clone(),
                        req,
                        web::Path::from(id),
                        web::Json(super::super::TrustDecision {
                            admin_note: Some("rejected".to_owned()),
                        }),
                    )
                    .await
                }
                _ => {
                    super::super::admin_revoke_mtls_trust_anchor(
                        sessions.clone(),
                        service.clone(),
                        req,
                        web::Path::from(id),
                        web::Json(super::super::TrustRevocation {
                            reason: "revoked".to_owned(),
                        }),
                    )
                    .await
                }
            };
            assert_eq!(
                response.status(),
                actix_web::http::StatusCode::SERVICE_UNAVAILABLE
            );
            let response: Value = serde_json::from_slice(
                &actix_web::body::to_bytes(response.into_body())
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(response["error"], "server_error");
            assert!(response.get("certificate_pem").is_none());
            assert_eq!(
                repository
                    .by_id(tenant.tenant_id, id)
                    .await
                    .unwrap()
                    .unwrap()
                    .status,
                [1, 2, 3][action]
            );
            let expected_type = [
                "mtls_trust_anchor_approved",
                "mtls_trust_anchor_rejected",
                "mtls_trust_anchor_revoked",
            ][action];
            let mut connection = get_conn(&pool).await.unwrap();
            let evidence=sql_query("SELECT jsonb_build_object('source_events',COALESCE((SELECT jsonb_agg(action ORDER BY created_at,id) FROM oauth_client_mtls_trust_anchor_events WHERE tenant_id=$1 AND request_id=$2),'[]'::jsonb),'required_events',COALESCE((SELECT jsonb_agg(payload ORDER BY event_id) FROM security_audit_events WHERE payload->>'tenant_id'=$1::text AND payload->>'request_id'=$2::text AND event_type=$3),'[]'::jsonb)) AS value")
                .bind::<SqlUuid,_>(tenant.tenant_id.as_uuid()).bind::<SqlUuid,_>(id).bind::<Text,_>(expected_type).get_result::<Evidence>(&mut connection).await.unwrap().value;
            assert_eq!(
                evidence["source_events"],
                if action == 2 {
                    json!([0, 1, 3])
                } else {
                    json!([0, action + 1])
                }
            );
            assert_eq!(evidence["required_events"].as_array().unwrap().len(), 1);
            assert_eq!(
                evidence["required_events"][0]["admin_user_id"],
                admin.as_uuid().to_string()
            );
            assert_eq!(
                evidence["required_events"][0]["schema_version"],
                nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION
            );
            assert!(
                evidence["required_events"][0]
                    .get("certificate_pem")
                    .is_none()
            );
        }
    });
    let result = futures_util::FutureExt::catch_unwind(body).await;
    crate::test_support::valkey::valkey_del(&state.valkey, key)
        .await
        .unwrap();
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("DELETE FROM oauth_client_mtls_trust_anchor_events WHERE request_id IN (SELECT id FROM oauth_client_mtls_trust_anchor_requests WHERE client_id=$1)").bind::<SqlUuid,_>(client).execute(&mut connection).await.unwrap();
    sql_query("DELETE FROM oauth_client_mtls_trust_anchor_requests WHERE client_id=$1")
        .bind::<SqlUuid, _>(client)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM client_access_requests WHERE approved_client_id=$1")
        .bind::<SqlUuid, _>(client)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM oauth_clients WHERE id=$1")
        .bind::<SqlUuid, _>(client)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM users WHERE id=$1 OR id=$2")
        .bind::<SqlUuid, _>(admin.as_uuid())
        .bind::<SqlUuid, _>(requester.as_uuid())
        .execute(&mut connection)
        .await
        .unwrap();
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

#[actix_web::test]
async fn bundle_export_waits_for_real_required_audit_commit_and_rejects_late_failure() {
    use diesel_async::SimpleAsyncConnection;
    let database_url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    let valkey_url = std::env::var("VALKEY_URL").ok();
    if (database_url.is_none() || valkey_url.is_none()) && std::env::var_os("CI").is_some() {
        panic!("real HTTP audit test requires isolated PostgreSQL and Valkey");
    }
    let (Some(database_url), Some(valkey_url)) = (database_url, valkey_url) else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .unwrap();
    let pool = create_pool(&database_url, 4).unwrap();
    let unhealthy_anchor = std::env::var_os("NAZO_TEST_BUNDLE_UNHEALTHY_ANCHOR").is_some();
    if unhealthy_anchor {
        let preflight = crate::adapters::audit_anchor::AuditAnchorPreflight::new(
            crate::adapters::audit_anchor::AuditAnchorPreflightConfig {
                mode: crate::adapters::audit_anchor::config::AuditAnchorMode::Required,
                deployment_id: Uuid::now_v7().to_string(),
                freshness: std::time::Duration::from_secs(1),
                max_lag: std::time::Duration::from_secs(1),
            },
        )
        .unwrap();
        crate::adapters::audit::install_persistent_audit_sink(
            Arc::new(nazo_postgres::AuditLedgerRepository::new(pool.clone())),
            false,
            preflight,
        )
        .unwrap();
    } else {
        crate::test_support::initialize_audit_dependencies(&pool);
    }
    let valkey =
        fred::prelude::Builder::from_config(fred::prelude::Config::from_url(&valkey_url).unwrap())
            .build()
            .unwrap();
    valkey.init().await.unwrap();
    let state = TestInfrastructure {
        diesel_db: pool.clone(),
        valkey,
        settings: Arc::new(Settings::from_config(&ConfigSource::default()).unwrap()),
        keyset: crate::test_support::test_key_manager(),
    };
    let admin = Uuid::now_v7();
    let suffix = admin.simple().to_string();
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("INSERT INTO users (id,username,email,password_hash,role,admin_level) VALUES ($1,$2,$3,'fixture','admin',1)")
         .bind::<SqlUuid,_>(admin).bind::<Text,_>(format!("bundle-{suffix}")).bind::<Text,_>(format!("bundle-{suffix}@example.test")).execute(&mut connection).await.unwrap();
    let sid = format!("bundle-{suffix}");
    let key = nazo_valkey::test_support::state_storage_key(format!("oauth:session:{sid}"));
    let payload = nazo_oauth_server::sessions::SessionPayload {
        user_id: admin,
        auth_time: Utc::now().timestamp(),
        amr: vec!["pwd".into()],
        pending_mfa: false,
        oidc_sid: Some(sid.clone()),
    };
    crate::test_support::valkey::valkey_set_ex(
        &state.valkey,
        key.clone(),
        serde_json::to_string(&payload).unwrap(),
        300,
    )
    .await
    .unwrap();
    let sessions = web::Data::new(admin_session_handles(&state));
    let service: web::Data<super::super::MtlsTrustAnchorService> = web::Data::from(Arc::new(
        MtlsTrustAnchorRepository::new(pool.clone()),
    )
        as Arc<dyn MtlsTrustAnchorStore>);
    let function = format!("bundle_late_{suffix}");
    connection.batch_execute(&format!(r#"
         CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN
             IF NEW.event_type='mtls_trust_bundle_exported' AND NEW.payload->>'admin_user_id'='{admin}' THEN
                 RAISE EXCEPTION 'bundle audit late commit failure' USING ERRCODE='23514';
             END IF;
             RETURN NULL;
         END $$;
         CREATE CONSTRAINT TRIGGER {function} AFTER INSERT ON security_audit_events
           DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION {function}();
     "#)).await.unwrap();
    let failure=futures_util::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(async {
         let req=TestRequest::get().cookie(actix_web::cookie::Cookie::new(state.settings.session.session_cookie_name.clone(),sid.clone())).to_http_request();
         let response=super::super::admin_mtls_trust_bundle(sessions.clone(),service.clone(),req).await;
         assert_eq!(response.status(),actix_web::http::StatusCode::SERVICE_UNAVAILABLE);
         assert!(!response.headers().contains_key("content-disposition"));
         let body=actix_web::body::to_bytes(response.into_body()).await.unwrap();
         assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["error"],"server_error");
         let rows=sql_query("SELECT jsonb_agg(payload) AS value FROM security_audit_events WHERE event_type='mtls_trust_bundle_exported' AND payload->>'admin_user_id'=$1 HAVING count(*)>0")
             .bind::<Text,_>(admin.to_string()).load::<Evidence>(&mut connection).await.unwrap();
         assert!(rows.is_empty(),"late failure must leave no export evidence");
     })).await;
    connection
        .batch_execute(&format!(
            "DROP TRIGGER {function} ON security_audit_events; DROP FUNCTION {function}()"
        ))
        .await
        .unwrap();
    let success=futures_util::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(async {
         let req=TestRequest::get().cookie(actix_web::cookie::Cookie::new(state.settings.session.session_cookie_name.clone(),sid.clone())).to_http_request();
         let response=super::super::admin_mtls_trust_bundle(sessions,service,req).await;
         if unhealthy_anchor {
             assert_eq!(response.status(),actix_web::http::StatusCode::SERVICE_UNAVAILABLE);
             assert!(!response.headers().contains_key("content-disposition"));
             let rows=sql_query("SELECT jsonb_agg(payload) AS value FROM security_audit_events WHERE event_type='mtls_trust_bundle_exported' AND payload->>'admin_user_id'=$1 HAVING count(*)>0")
                 .bind::<Text,_>(admin.to_string()).load::<Evidence>(&mut connection).await.unwrap();
             assert!(rows.is_empty(), "unhealthy anchor must reject before disclosure or event append");
             println!("mTLS bundle HTTP: writable audit database plus unhealthy Required anchor -> 503/no attachment/no event");
             return;
         }
         assert_eq!(response.status(),actix_web::http::StatusCode::OK);
         assert!(response.headers().contains_key("content-disposition"));
         let rows=sql_query("SELECT jsonb_agg(payload) AS value FROM security_audit_events WHERE event_type='mtls_trust_bundle_exported' AND payload->>'admin_user_id'=$1")
             .bind::<Text,_>(admin.to_string()).get_result::<Evidence>(&mut connection).await.unwrap();
         assert_eq!(rows.value.as_array().unwrap().len(),1);
         println!("mTLS bundle HTTP: deferred PG commit error -> 503/no attachment/no row; restored commit -> 200/attachment/exactly one Required event");
     })).await;
    crate::test_support::valkey::valkey_del(&state.valkey, key)
        .await
        .unwrap();
    sql_query("DELETE FROM users WHERE id=$1")
        .bind::<SqlUuid, _>(admin)
        .execute(&mut connection)
        .await
        .unwrap();
    if let Err(error) = failure {
        std::panic::resume_unwind(error);
    }
    if let Err(error) = success {
        std::panic::resume_unwind(error);
    }
}

#[test]
fn bundle_export_rejects_unhealthy_required_anchor_in_isolated_process() {
    let configured = (std::env::var_os("NAZO_TEST_DATABASE_URL").is_some()
        || std::env::var_os("DATABASE_URL").is_some())
        && std::env::var_os("VALKEY_URL").is_some();
    if !configured {
        assert!(
            std::env::var_os("CI").is_none(),
            "real bundle test requires PostgreSQL and Valkey"
        );
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("bundle_export_waits_for_real_required_audit_commit_and_rejects_late_failure")
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env("NAZO_TEST_BUNDLE_UNHEALTHY_ANCHOR", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("writable audit database plus unhealthy Required anchor"),
        "child did not execute real database proof: {stdout}"
    );
}
