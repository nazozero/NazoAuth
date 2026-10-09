use super::*;
use crate::test_support::admin_mutations::{LiveAdminUsersFixture, admin_user_dependencies};
use actix_web::cookie::Cookie;
use fred::prelude::{
    Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use crate::config::ConfigSource;
use crate::settings::Settings;
use crate::test_support::{DatabaseUserFixture, TestInfrastructure};
use chrono::Utc;
use nazo_postgres::{UserRepository, create_pool};

fn user_row() -> PublicAccount {
    let now = Utc::now();
    DatabaseUserFixture {
        id: Uuid::now_v7(),
        tenant_id: Uuid::now_v7(),
        realm_id: Uuid::now_v7(),
        organization_id: Uuid::now_v7(),
        username: "admin@example.com".to_owned(),
        email: "admin@example.com".to_owned(),
        display_name: Some("Admin".to_owned()),
        avatar_url: None,
        given_name: None,
        family_name: None,
        middle_name: None,
        nickname: None,
        profile_url: None,
        website_url: None,
        gender: None,
        birthdate: None,
        zoneinfo: None,
        locale: None,
        role: "admin".to_owned(),
        admin_level: 10,
        address_formatted: None,
        address_street_address: None,
        address_locality: None,
        address_region: None,
        address_postal_code: None,
        address_country: None,
        phone_number: None,
        phone_number_verified: false,
        email_verified: true,
        mfa_enabled: true,
        password_hash: "argon2-password-hash".to_owned(),
        is_active: true,
        created_at: now,
        updated_at: now,
    }
    .identity()
}

fn unavailable_valkey_client() -> fred::prelude::Client {
    let mut builder = ValkeyBuilder::from_config(
        ValkeyConfig::from_url("redis://127.0.0.1:1").expect("unavailable Valkey URL should parse"),
    );
    builder.with_performance_config(|performance: &mut PerformanceConfig| {
        performance.default_command_timeout = StdDuration::from_millis(200);
    });
    builder.with_connection_config(|connection: &mut ConnectionConfig| {
        connection.connection_timeout = StdDuration::from_millis(200);
        connection.internal_command_timeout = StdDuration::from_millis(200);
        connection.max_command_attempts = 1;
    });
    builder
        .build()
        .expect("unavailable valkey client construction should not connect")
}

fn test_state() -> TestInfrastructure {
    TestInfrastructure {
        diesel_db: create_pool(
            "postgres://nazo_admin_users_test_invalid:nazo_admin_users_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: unavailable_valkey_client(),
        settings: Arc::new(
            Settings::from_config(&ConfigSource::default()).expect("default settings should load"),
        ),
        keyset: crate::test_support::test_key_manager(),
    }
}

async fn invoke_admin_users(
    state: Data<TestInfrastructure>,
    req: HttpRequest,
    query: Query<HashMap<String, String>>,
) -> HttpResponse {
    let (admin_sessions, users, _) = admin_user_dependencies(&state);
    admin_users(admin_sessions, users, req, query).await
}

async fn invoke_admin_patch_user(
    state: Data<TestInfrastructure>,
    req: HttpRequest,
    path: actix_web::web::Path<Uuid>,
    payload: Json<PatchUserRequest>,
) -> HttpResponse {
    let (admin_sessions, users, client_ip_config) = admin_user_dependencies(&state);
    admin_patch_user(admin_sessions, users, client_ip_config, req, path, payload).await
}

async fn invoke_admin_create_user(
    state: Data<TestInfrastructure>,
    req: HttpRequest,
    payload: Json<CreateUserRequest>,
) -> HttpResponse {
    let (admin_sessions, _, client_ip_config) = admin_user_dependencies(&state);
    let accounts: Data<dyn nazo_identity::ports::RegistrationAccountRepositoryPort> =
        Data::from(Arc::new(UserRepository::new(state.diesel_db.clone()))
            as Arc<dyn nazo_identity::ports::RegistrationAccountRepositoryPort>);
    admin_create_user(admin_sessions, accounts, client_ip_config, req, payload).await
}

async fn oauth_error_name(response: actix_web::HttpResponse) -> Option<String> {
    let bytes = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("OAuth response body should collect");
    let body: serde_json::Value =
        serde_json::from_slice(&bytes).expect("OAuth response body should be JSON");
    body.get("error")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

fn empty_patch() -> PatchUserRequest {
    PatchUserRequest {
        role: None,
        admin_level: None,
        is_active: None,
    }
}

#[actix_web::test]
async fn admin_users_list_response_omits_password_hash_and_tenant_context() {
    let response = admin_users_list_response(1, 20, 1, vec![user_row()]);

    assert_eq!(response.status(), StatusCode::OK);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("admin user list body should collect");
    let body: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(body["total"], json!(1));
    assert_eq!(body["page"], json!(1));
    assert_eq!(body["page_size"], json!(20));
    let item = &body["items"].as_array().expect("items should be array")[0];
    assert_eq!(item["email"], "admin@example.com");
    assert_eq!(item["role"], "admin");
    assert!(item.get("password_hash").is_none());
    assert!(item.get("tenant_id").is_none());
    assert!(item.get("realm_id").is_none());
    assert!(item.get("organization_id").is_none());
}

#[actix_web::test]
async fn patch_user_validation_allows_only_supported_roles() {
    let mut patch = empty_patch();
    patch.role = Some("owner".to_owned());

    let response = patch_user_validation_error(&patch)
        .expect("unsupported roles must fail before any database mutation");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_name(response).await.as_deref(),
        Some("invalid_request")
    );
}

#[actix_web::test]
async fn patch_user_validation_rejects_negative_admin_level() {
    let mut patch = empty_patch();
    patch.role = Some("admin".to_owned());
    patch.admin_level = Some(-1);

    let response = patch_user_validation_error(&patch)
        .expect("negative privilege levels must fail before any database mutation");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_name(response).await.as_deref(),
        Some("invalid_request")
    );
}

#[test]
fn patch_user_validation_accepts_user_and_admin_roles_with_non_negative_level() {
    for role in ["user", "admin"] {
        let mut patch = empty_patch();
        patch.role = Some(role.to_owned());
        patch.admin_level = Some(0);

        assert!(
            patch_user_validation_error(&patch).is_none(),
            "supported role {role} with non-negative level must reach the transactional update"
        );
    }
}

#[actix_web::test]
async fn admin_users_requires_admin_before_database_lookup() {
    let state = Data::new(test_state());
    let req = actix_web::test::TestRequest::get()
        .uri("/admin/users")
        .to_http_request();

    let response = invoke_admin_users(state, req, Query(HashMap::new())).await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        oauth_error_name(response).await.as_deref(),
        Some("access_denied")
    );
}

#[actix_web::test]
async fn admin_patch_user_rejects_missing_csrf_before_auth_or_mutation() {
    let state = Data::new(test_state());
    let req = actix_web::test::TestRequest::post()
        .uri("/admin/users/user-id")
        .cookie(Cookie::new(
            state.settings.session.session_cookie_name.clone(),
            "session-id",
        ))
        .to_http_request();

    let response = invoke_admin_patch_user(
        state,
        req,
        actix_web::web::Path::from(Uuid::now_v7()),
        Json(empty_patch()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_name(response).await.as_deref(),
        Some("invalid_request")
    );
}

#[actix_web::test]
async fn admin_create_user_rejects_missing_csrf_before_hashing_or_mutation() {
    let state = Data::new(test_state());
    let req = actix_web::test::TestRequest::post()
        .uri("/admin/users")
        .cookie(Cookie::new(
            state.settings.session.session_cookie_name.clone(),
            "session-id",
        ))
        .to_http_request();

    let response = invoke_admin_create_user(
        state,
        req,
        Json(CreateUserRequest {
            email: "new-user@example.com".to_owned(),
            password: "not-used-password".to_owned(),
        }),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_name(response).await.as_deref(),
        Some("invalid_request")
    );
}

#[actix_web::test]
async fn admin_create_user_uses_authenticated_tenant_and_returns_no_password_material() {
    let Some(fixture) = LiveAdminUsersFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let admin = fixture
        .create_user(&format!("{suffix}-admin"), "admin", 10)
        .await;
    let sid = format!("sid-{suffix}");
    let csrf = format!("csrf-{suffix}");
    let email = format!("provisioned-{suffix}@example.com");
    fixture.store_session(&admin, &sid).await;

    let response = invoke_admin_create_user(
        fixture.state.clone(),
        fixture.admin_post_request(&sid, &csrf, "/admin/users"),
        Json(CreateUserRequest {
            email: email.clone(),
            password: format!("safe-test-password-{suffix}"),
        }),
    )
    .await;

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("created user response should collect");
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["email"], email);
    assert_eq!(body["role"], "user");
    assert!(body.get("password").is_none());
    assert!(body.get("password_hash").is_none());
}

#[actix_web::test]
async fn admin_patch_user_requires_admin_even_with_valid_csrf() {
    let Some(fixture) = LiveAdminUsersFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let non_admin = fixture
        .create_user(&format!("{suffix}-user"), "user", 0)
        .await;
    let target = fixture
        .create_user(&format!("{suffix}-target"), "user", 0)
        .await;
    let sid = format!("sid-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&non_admin, &sid).await;

    let response = invoke_admin_patch_user(
        fixture.state.clone(),
        fixture.admin_post_request(&sid, &csrf, "/admin/users/update"),
        actix_web::web::Path::from(target.id),
        Json(PatchUserRequest {
            role: Some("admin".to_owned()),
            admin_level: Some(5),
            is_active: Some(false),
        }),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        oauth_error_name(response).await.as_deref(),
        Some("access_denied")
    );
}

#[actix_web::test]
async fn admin_patch_user_rejects_peer_self_demotion_and_own_level_grant() {
    let Some(fixture) = LiveAdminUsersFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let actor = fixture
        .create_user(&format!("{suffix}-actor"), "admin", 5)
        .await;
    let peer = fixture
        .create_user(&format!("{suffix}-peer"), "admin", 5)
        .await;
    let user = fixture
        .create_user(&format!("{suffix}-user"), "user", 0)
        .await;
    let sid = format!("sid-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&actor, &sid).await;

    for (target, payload) in [
        (
            peer.id,
            PatchUserRequest {
                role: None,
                admin_level: None,
                is_active: Some(false),
            },
        ),
        (
            actor.id,
            PatchUserRequest {
                role: None,
                admin_level: Some(4),
                is_active: None,
            },
        ),
        (
            user.id,
            PatchUserRequest {
                role: Some("admin".to_owned()),
                admin_level: Some(5),
                is_active: None,
            },
        ),
    ] {
        let response = invoke_admin_patch_user(
            fixture.state.clone(),
            fixture.admin_post_request(&sid, &csrf, "/admin/users/update"),
            actix_web::web::Path::from(target),
            Json(payload),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            oauth_error_name(response).await.as_deref(),
            Some("access_denied")
        );
    }

    let actor_after = fixture.load_user(actor.id).await;
    let peer_after = fixture.load_user(peer.id).await;
    let user_after = fixture.load_user(user.id).await;
    assert_eq!(actor_after.admin_level, 5);
    assert!(actor_after.is_active);
    assert_eq!(peer_after.admin_level, 5);
    assert!(peer_after.is_active);
    assert_eq!(user_after.role, "user");
    assert_eq!(user_after.admin_level, 0);
}

#[actix_web::test]
async fn admin_users_list_returns_admin_view_without_secret_fields() {
    let Some(fixture) = LiveAdminUsersFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let admin = fixture
        .create_user(&format!("{suffix}-admin"), "admin", 10)
        .await;
    let listed = fixture
        .create_user(&format!("{suffix}-listed"), "user", 0)
        .await;
    let sid = format!("sid-{suffix}");
    fixture.store_session(&admin, &sid).await;

    let response = invoke_admin_users(
        fixture.state.clone(),
        fixture.admin_get_request(&sid, "/admin/users?page=1&page_size=20"),
        Query(HashMap::from([
            ("page".to_owned(), "1".to_owned()),
            ("page_size".to_owned(), "20".to_owned()),
        ])),
    )
    .await;

    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let body: Value = serde_json::from_slice(&body).expect("response should be JSON");

    assert_eq!(status, StatusCode::OK);
    let items = body["items"].as_array().expect("items should be an array");
    let target = items
        .iter()
        .find(|item| item["id"] == json!(listed.id))
        .expect("inserted user should be present");
    assert_eq!(target["email"], listed.email);
    assert!(target.get("password_hash").is_none());
    assert!(target.get("tenant_id").is_none());
    assert!(target.get("realm_id").is_none());
    assert!(target.get("organization_id").is_none());
}

#[actix_web::test]
async fn admin_patch_user_validates_role_and_admin_level_before_mutation() {
    let Some(fixture) = LiveAdminUsersFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let admin = fixture
        .create_user(&format!("{suffix}-admin"), "admin", 10)
        .await;
    let user = fixture
        .create_user(&format!("{suffix}-user"), "user", 0)
        .await;
    let sid = format!("sid-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&admin, &sid).await;

    let invalid_role = invoke_admin_patch_user(
        fixture.state.clone(),
        fixture.admin_post_request(&sid, &csrf, "/admin/users/update"),
        actix_web::web::Path::from(user.id),
        Json(PatchUserRequest {
            role: Some("owner".to_owned()),
            admin_level: None,
            is_active: None,
        }),
    )
    .await;
    assert_eq!(invalid_role.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_name(invalid_role).await.as_deref(),
        Some("invalid_request")
    );

    let invalid_level = invoke_admin_patch_user(
        fixture.state.clone(),
        fixture.admin_post_request(&sid, &csrf, "/admin/users/update"),
        actix_web::web::Path::from(user.id),
        Json(PatchUserRequest {
            role: None,
            admin_level: Some(-1),
            is_active: None,
        }),
    )
    .await;
    assert_eq!(invalid_level.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_name(invalid_level).await.as_deref(),
        Some("invalid_request")
    );

    let persisted = fixture.load_user(user.id).await;
    assert_eq!(persisted.role, "user");
    assert_eq!(persisted.admin_level, 0);
    assert!(persisted.is_active);
}

#[actix_web::test]
async fn admin_patch_user_rejects_nil_user_id_without_panicking() {
    let Some(fixture) = LiveAdminUsersFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let admin = fixture
        .create_user(&format!("{suffix}-admin"), "admin", 10)
        .await;
    let sid = format!("sid-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&admin, &sid).await;

    let response = invoke_admin_patch_user(
        fixture.state.clone(),
        fixture.admin_post_request(&sid, &csrf, "/admin/users/update"),
        actix_web::web::Path::from(Uuid::nil()),
        Json(empty_patch()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_name(response).await.as_deref(),
        Some("invalid_request")
    );
}

#[actix_web::test]
async fn admin_patch_user_empty_payload_is_noop_and_preserves_updated_at() {
    let Some(fixture) = LiveAdminUsersFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let admin = fixture
        .create_user(&format!("{suffix}-admin"), "admin", 10)
        .await;
    let user = fixture
        .create_user(&format!("{suffix}-user"), "user", 0)
        .await;
    let updated_at = user.updated_at;
    let sid = format!("sid-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&admin, &sid).await;

    let response = invoke_admin_patch_user(
        fixture.state.clone(),
        fixture.admin_post_request(&sid, &csrf, "/admin/users/update"),
        actix_web::web::Path::from(user.id),
        Json(empty_patch()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let persisted = fixture.load_user(user.id).await;
    assert_eq!(persisted.updated_at, updated_at);
    assert_eq!(persisted.role, user.role);
    assert_eq!(persisted.admin_level, user.admin_level);
    assert_eq!(persisted.is_active, user.is_active);
}

#[actix_web::test]
async fn admin_patch_user_rejects_invalid_partial_role_level_without_mutation() {
    let Some(fixture) = LiveAdminUsersFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let admin = fixture
        .create_user(&format!("{suffix}-admin"), "admin", 10)
        .await;
    let user = fixture
        .create_user(&format!("{suffix}-user"), "user", 0)
        .await;
    let sid = format!("sid-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&admin, &sid).await;

    let response = invoke_admin_patch_user(
        fixture.state.clone(),
        fixture.admin_post_request(&sid, &csrf, "/admin/users/update"),
        actix_web::web::Path::from(user.id),
        Json(PatchUserRequest {
            role: None,
            admin_level: Some(7),
            is_active: None,
        }),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_name(response).await.as_deref(),
        Some("invalid_request")
    );
    let persisted = fixture.load_user(user.id).await;
    assert_eq!(persisted.role, "user");
    assert_eq!(persisted.admin_level, 0);
}

#[actix_web::test]
async fn admin_patch_user_updates_role_level_and_active_state_and_reports_missing_users() {
    let Some(fixture) = LiveAdminUsersFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let admin = fixture
        .create_user(&format!("{suffix}-admin"), "admin", 10)
        .await;
    let user = fixture
        .create_user(&format!("{suffix}-user"), "user", 0)
        .await;
    let sid = format!("sid-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&admin, &sid).await;

    let response = invoke_admin_patch_user(
        fixture.state.clone(),
        fixture.admin_post_request(&sid, &csrf, "/admin/users/update"),
        actix_web::web::Path::from(user.id),
        Json(PatchUserRequest {
            role: Some("admin".to_owned()),
            admin_level: Some(5),
            is_active: Some(false),
        }),
    )
    .await;

    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let body: Value = serde_json::from_slice(&body).expect("response should be JSON");

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"], json!(user.id));
    assert_eq!(body["role"], "admin");
    assert_eq!(body["admin_level"], 5);
    assert_eq!(body["is_active"], false);
    assert!(body.get("password_hash").is_none());

    let missing = invoke_admin_patch_user(
        fixture.state.clone(),
        fixture.admin_post_request(&sid, &csrf, "/admin/users/update"),
        actix_web::web::Path::from(Uuid::now_v7()),
        Json(empty_patch()),
    )
    .await;

    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        oauth_error_name(missing).await.as_deref(),
        Some("invalid_request")
    );
}

#[actix_web::test]
async fn admin_patch_user_reports_not_found_for_each_requested_field_update() {
    let Some(fixture) = LiveAdminUsersFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let admin = fixture
        .create_user(&format!("{suffix}-admin"), "admin", 10)
        .await;
    let sid = format!("sid-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&admin, &sid).await;
    let missing_user_id = Uuid::now_v7();

    for payload in [
        PatchUserRequest {
            role: Some("admin".to_owned()),
            admin_level: None,
            is_active: None,
        },
        PatchUserRequest {
            role: None,
            admin_level: Some(7),
            is_active: None,
        },
        PatchUserRequest {
            role: None,
            admin_level: None,
            is_active: Some(false),
        },
    ] {
        let response = invoke_admin_patch_user(
            fixture.state.clone(),
            fixture.admin_post_request(&sid, &csrf, "/admin/users/update"),
            actix_web::web::Path::from(missing_user_id),
            Json(payload),
        )
        .await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            oauth_error_name(response).await.as_deref(),
            Some("invalid_request")
        );
    }
}

#[actix_web::test]
async fn system_tenant_admin_update_commits_state_and_registered_required_audit() {
    use diesel::{
        sql_query,
        sql_types::{Text, Uuid as SqlUuid},
    };
    use diesel_async::RunQueryDsl;
    use nazo_identity::{OrganizationId, RealmId, TenantContext, TenantDirectoryBinding, TenantId};
    let Some(fixture) = LiveAdminUsersFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let admin = fixture
        .create_user(&format!("{suffix}-system-admin"), "admin", 10)
        .await;
    let target = fixture
        .create_user(&format!("{suffix}-tenant-admin"), "user", 0)
        .await;
    let tenant = Uuid::now_v7();
    let realm = Uuid::now_v7();
    let organization = Uuid::now_v7();
    let mut conn = nazo_postgres::get_conn(&fixture.state.diesel_db)
        .await
        .unwrap();
    sql_query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, 'Audit regression')")
        .bind::<SqlUuid, _>(tenant)
        .bind::<Text, _>(format!("audit-{suffix}"))
        .execute(&mut conn)
        .await
        .unwrap();
    sql_query("INSERT INTO realms (id, tenant_id, slug, display_name) VALUES ($1, $2, 'default', 'Default')")
        .bind::<SqlUuid,_>(realm).bind::<SqlUuid,_>(tenant).execute(&mut conn).await.unwrap();
    sql_query("INSERT INTO organizations (id, tenant_id, slug, display_name) VALUES ($1, $2, 'default', 'Default')")
        .bind::<SqlUuid,_>(organization).bind::<SqlUuid,_>(tenant).execute(&mut conn).await.unwrap();
    sql_query("UPDATE users SET tenant_id=$1, realm_id=$2, organization_id=$3 WHERE id=$4")
        .bind::<SqlUuid, _>(tenant)
        .bind::<SqlUuid, _>(realm)
        .bind::<SqlUuid, _>(organization)
        .bind::<SqlUuid, _>(target.id)
        .execute(&mut conn)
        .await
        .unwrap();
    drop(conn);
    let tenant = TenantId::new(tenant).unwrap();
    let registry = crate::bootstrap::test_support::registry(TenantDirectoryBinding {
        tenant: TenantContext {
            tenant_id: tenant,
            realm_id: RealmId::new(realm).unwrap(),
            organization_id: OrganizationId::new(organization).unwrap(),
        },
        runtime_revision: 1,
        issuer: "https://tenant-audit.example".to_owned(),
        external_host: "tenant-audit.example".to_owned(),
    });
    let sid = format!("sid-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&admin, &sid).await;
    let (sessions, users, ip) = admin_user_dependencies(&fixture.state);
    let control = fixture.state.settings.tenant.context.tenant_id;
    let response = crate::adapters::audit::REQUEST_TENANT
        .scope(
            control,
            system_set_tenant_admin(
                sessions,
                users,
                Data::new(registry),
                Data::new(crate::bootstrap::routes::ControlTenantId(control)),
                ip,
                fixture.admin_post_request(&sid, &csrf, "/system/tenants/admin"),
                actix_web::web::Path::from((tenant.as_uuid(), target.id)),
                Json(SetTenantAdminRequest { admin_level: 3 }),
            ),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let persisted = fixture.load_user(target.id).await;
    assert_eq!(persisted.role, "admin");
    assert_eq!(persisted.admin_level, 3);
    assert_eq!(
        fixture
            .audit_count(
                "system_tenant_admin_updated",
                "target_user_id",
                &target.id.to_string()
            )
            .await,
        1
    );
    #[derive(diesel::QueryableByName)]
    struct Ledger {
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        payload: serde_json::Value,
    }
    let mut conn = nazo_postgres::get_conn(&fixture.state.diesel_db)
        .await
        .unwrap();
    let audit = sql_query("SELECT payload FROM security_audit_events WHERE event_type='system_tenant_admin_updated' AND payload->>'target_user_id'=$1")
        .bind::<Text,_>(target.id.to_string()).get_result::<Ledger>(&mut conn).await.unwrap();
    assert_eq!(audit.payload["tenant_id"], json!(tenant.as_uuid()));
    assert_eq!(audit.payload["actor_tenant_id"], json!(control.as_uuid()));
    assert_eq!(audit.payload["actor_user_id"], json!(admin.id));
    assert_eq!(audit.payload["outcome"], "success");
    #[derive(diesel::QueryableByName)]
    struct LocalEvent {
        #[diesel(sql_type = diesel::sql_types::Nullable<SqlUuid>)]
        actor_id: Option<Uuid>,
    }
    let local = sql_query("SELECT actor_id FROM identity_security_events WHERE tenant_id=$1 AND target_user_id=$2 AND reason_code='admin_updated'")
        .bind::<SqlUuid,_>(tenant.as_uuid()).bind::<SqlUuid,_>(target.id).get_result::<LocalEvent>(&mut conn).await.unwrap();
    assert!(local.actor_id.is_none());
}
