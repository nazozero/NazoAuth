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
