use super::*;
use diesel::sql_query;
use diesel::sql_types::Text;
use diesel_async::RunQueryDsl;
use std::sync::Arc;

use crate::config::ConfigSource;
use crate::db::{create_pool, get_conn};
use crate::domain::{ActiveSigningKey, Keyset, KeysetStore};

fn uuid_fixture(value: u128) -> Uuid {
    Uuid::from_u128(value)
}

fn test_state_with_scim_bearer_token(scim_bearer_token: Option<&str>) -> AppState {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.scim_bearer_token = scim_bearer_token.map(ToOwned::to_owned);
    AppState {
        diesel_db: create_pool(
            "postgres://nazo_scim_test_invalid:nazo_scim_test_invalid@127.0.0.1:1/nazo".to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(settings),
        keyset: KeysetStore::new(Keyset {
            active_kid: "test-kid".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
            verification_keys: Vec::new(),
        }),
    }
}

fn test_state() -> AppState {
    test_state_with_scim_bearer_token(None)
}

fn database_url_with_search_path(schema: &str) -> Option<String> {
    let base = std::env::var("DATABASE_URL").ok()?;
    let separator = if base.contains('?') { "&" } else { "?" };
    Some(format!(
        "{base}{separator}options=-csearch_path%3D{schema}%2Cpublic"
    ))
}

async fn live_state_with_scim_bearer_token(scim_bearer_token: &str) -> Option<Data<AppState>> {
    let database_url = std::env::var("DATABASE_URL").ok()?;
    live_state_for_database_url(scim_bearer_token, database_url).await
}

async fn live_state_with_isolated_scim_bearer_token(
    scim_bearer_token: &str,
    schema: &str,
    tables: &[&str],
) -> Option<Data<AppState>> {
    let database_url = database_url_with_search_path(schema)?;
    let state = live_state_for_database_url(scim_bearer_token, database_url).await?;
    create_isolated_scim_schema(&state, schema, tables).await;
    Some(state)
}

async fn live_state_for_database_url(
    scim_bearer_token: &str,
    database_url: String,
) -> Option<Data<AppState>> {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.scim_bearer_token = Some(scim_bearer_token.to_owned());
    Some(Data::new(AppState {
        diesel_db: create_pool(database_url, 4).expect("database pool should build"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(settings),
        keyset: KeysetStore::new(Keyset {
            active_kid: "test-kid".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
            verification_keys: Vec::new(),
        }),
    }))
}

async fn exec_scim_schema_sql(state: &AppState, sql: &str) {
    let mut conn = get_conn(&state.diesel_db)
        .await
        .expect("database connection should be available");
    sql_query(sql)
        .execute(&mut conn)
        .await
        .expect("schema mutation should succeed");
}

async fn create_isolated_scim_schema(state: &AppState, schema: &str, tables: &[&str]) {
    exec_scim_schema_sql(
        state,
        &format!(r#"CREATE SCHEMA IF NOT EXISTS "{}""#, schema),
    )
    .await;
    for table in tables {
        exec_scim_schema_sql(
            state,
            &format!(
                r#"CREATE TABLE "{}"."{}" (LIKE public."{}" INCLUDING ALL)"#,
                schema, table, table
            ),
        )
        .await;
    }
}

async fn rename_scim_column(state: &AppState, schema: &str, table: &str, from: &str, to: &str) {
    exec_scim_schema_sql(
        state,
        &format!(
            r#"ALTER TABLE "{}"."{}" RENAME COLUMN "{}" TO "{}""#,
            schema, table, from, to
        ),
    )
    .await;
}

async fn cleanup_scim_schema(state: &AppState, schema: &str) {
    exec_scim_schema_sql(
        state,
        &format!(r#"DROP SCHEMA IF EXISTS "{}" CASCADE"#, schema),
    )
    .await;
}

async fn cleanup_scim_user_by_email(state: &AppState, email: &str) {
    let mut conn = get_conn(&state.diesel_db)
        .await
        .expect("database connection should be available");
    sql_query("DELETE FROM users WHERE email = $1")
        .bind::<Text, _>(email.to_owned())
        .execute(&mut conn)
        .await
        .expect("SCIM test user cleanup should succeed");
}

fn user_row(id: Uuid, email: &str) -> UserRow {
    let now = Utc::now();
    UserRow {
        id,
        tenant_id: uuid_fixture(0x11111111111111111111111111111111),
        realm_id: uuid_fixture(0x22222222222222222222222222222222),
        organization_id: uuid_fixture(0x33333333333333333333333333333333),
        username: email.to_owned(),
        email: email.to_owned(),
        display_name: Some("Alice Example".to_owned()),
        avatar_url: Some("https://cdn.example/avatar.png".to_owned()),
        given_name: Some("Alice".to_owned()),
        family_name: Some("Example".to_owned()),
        middle_name: Some("Q".to_owned()),
        nickname: Some("alice".to_owned()),
        profile_url: Some("https://example.test/alice".to_owned()),
        website_url: Some("https://alice.example".to_owned()),
        gender: Some("unspecified".to_owned()),
        birthdate: Some("1970-01-01".to_owned()),
        zoneinfo: Some("UTC".to_owned()),
        locale: Some("en-US".to_owned()),
        role: "admin".to_owned(),
        admin_level: 99,
        address_formatted: Some("Internal address".to_owned()),
        address_street_address: Some("Secret street".to_owned()),
        address_locality: Some("Secret city".to_owned()),
        address_region: Some("Secret region".to_owned()),
        address_postal_code: Some("Secret postal".to_owned()),
        address_country: Some("Secret country".to_owned()),
        phone_number: Some("+15555555555".to_owned()),
        phone_number_verified: true,
        email_verified: true,
        mfa_enabled: true,
        password_hash: "argon2-secret-hash".to_owned(),
        is_active: true,
        created_at: now,
        updated_at: now,
    }
}

fn scim_user_request_fixture() -> ScimUserRequest {
    ScimUserRequest {
        user_name: Some("user@example.test".to_owned()),
        active: Some(true),
        name: None,
        emails: Some(vec![ScimEmail {
            value: Some("user@example.test".to_owned()),
            primary: Some(true),
        }]),
    }
}

fn scim_user_request_mismatched_identity_fixture() -> ScimUserRequest {
    ScimUserRequest {
        user_name: Some("user@example.test".to_owned()),
        active: Some(true),
        name: None,
        emails: Some(vec![ScimEmail {
            value: Some("other@example.test".to_owned()),
            primary: Some(true),
        }]),
    }
}

fn scim_user_request_for_email(email: &str) -> ScimUserRequest {
    ScimUserRequest {
        user_name: Some(email.to_owned()),
        active: Some(true),
        name: Some(ScimName {
            given_name: Some("Lifecycle".to_owned()),
            family_name: Some("User".to_owned()),
            formatted: Some("Lifecycle User".to_owned()),
        }),
        emails: Some(vec![ScimEmail {
            value: Some(email.to_owned()),
            primary: Some(true),
        }]),
    }
}

fn bearer_request(token: &str) -> HttpRequest {
    actix_web::test::TestRequest::default()
        .insert_header((header::AUTHORIZATION, format!("Bearer {token}")))
        .to_http_request()
}

async fn response_json(response: HttpResponse) -> (StatusCode, Value) {
    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let json = serde_json::from_slice(&body).expect("response should be json");
    (status, json)
}

async fn create_scim_user_id(state: Data<AppState>, req: &HttpRequest, email: &str) -> Uuid {
    let (status, body) = response_json(
        scim_create_user(state, req.clone(), Json(scim_user_request_for_email(email))).await,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    serde_json::from_value::<Uuid>(body["id"].clone())
        .expect("SCIM create response should include a UUID id")
}

async fn assert_missing_bearer_is_scim_unauthorized(response: HttpResponse) {
    let (status, body) = response_json(response).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["schemas"], json!([SCIM_ERROR_SCHEMA]));
    assert_eq!(body["status"], "401");
    assert_eq!(body["scimType"], "unauthorized");
    assert_eq!(body["detail"], "missing bearer token");
    assert!(body.get("Resources").is_none());
    assert!(body.get("password_hash").is_none());
}

async fn assert_scim_error_response(
    response: HttpResponse,
    expected_status: StatusCode,
    expected_scim_type: &str,
    expected_detail: &str,
) {
    let (status, body) = response_json(response).await;
    assert_eq!(status, expected_status);
    assert_eq!(body["schemas"], json!([SCIM_ERROR_SCHEMA]));
    assert_eq!(body["status"], expected_status.as_u16().to_string());
    assert_eq!(body["scimType"], expected_scim_type);
    assert_eq!(body["detail"], expected_detail);
}

#[test]
fn scim_user_filter_accepts_user_name_eq_quoted_email() {
    assert_eq!(
        normalize_scim_user_filter(Some(r#"userName eq "USER@example.com""#))
            .unwrap()
            .as_deref(),
        Some("user@example.com")
    );
}

#[test]
fn scim_user_filter_rejects_other_fields() {
    assert!(normalize_scim_user_filter(Some(r#"email eq "user@example.com""#)).is_err());
}

#[test]
fn patch_requires_replace_operations() {
    let operation = ScimPatchOperation {
        op: "add".to_owned(),
        path: Some("active".to_owned()),
        value: json!(true),
    };

    assert!(normalize_patch(vec![operation]).is_err());
}

#[test]
fn bearer_token_accepts_only_non_empty_bearer_scheme() {
    let req = actix_web::test::TestRequest::default()
        .insert_header((header::AUTHORIZATION, "Bearer scim-secret"))
        .to_http_request();
    assert_eq!(bearer_token(&req), Some("scim-secret"));

    let req = actix_web::test::TestRequest::default()
        .insert_header((header::AUTHORIZATION, "Basic scim-secret"))
        .to_http_request();
    assert_eq!(bearer_token(&req), None);

    let req = actix_web::test::TestRequest::default()
        .insert_header((header::AUTHORIZATION, "Bearer   "))
        .to_http_request();
    assert_eq!(bearer_token(&req), None);

    let req = actix_web::test::TestRequest::default()
        .insert_header((header::AUTHORIZATION, "Bearer token extra"))
        .to_http_request();
    assert_eq!(bearer_token(&req), None);
}

#[test]
fn scim_scope_values_accepts_only_non_empty_strings() {
    assert_eq!(
        scim_scope_values(&json!([SCIM_SCOPE_READ, "", 7, SCIM_SCOPE_WRITE])),
        vec![SCIM_SCOPE_READ, SCIM_SCOPE_WRITE]
    );
}

#[test]
fn scim_credentials_enforce_read_write_and_wildcard_scopes() {
    let tenant = default_tenant_context();
    let read_only = ScimCredential {
        token_id: None,
        tenant_id: tenant.tenant_id,
        scopes: vec![SCIM_SCOPE_READ.to_owned()],
        source: "test",
    };
    let wildcard = ScimCredential {
        scopes: vec![SCIM_SCOPE_ALL.to_owned()],
        ..read_only.clone()
    };

    assert!(scim_credential_allows(&read_only, ScimRequiredScope::Read));
    assert!(!scim_credential_allows(
        &read_only,
        ScimRequiredScope::Write
    ));
    assert!(scim_credential_allows(&wildcard, ScimRequiredScope::Read));
    assert!(scim_credential_allows(&wildcard, ScimRequiredScope::Write));
}

#[test]
fn scim_payload_requires_user_name_and_primary_email_to_match() {
    let payload = ScimUserRequest {
        user_name: Some("user@example.com".to_owned()),
        active: Some(true),
        name: None,
        emails: Some(vec![ScimEmail {
            value: Some("other@example.com".to_owned()),
            primary: Some(true),
        }]),
    };

    assert!(normalize_scim_user_payload(payload, true).is_err());
}

#[test]
fn scim_payload_normalizes_primary_email_identity() {
    let payload = ScimUserRequest {
        user_name: Some("USER@example.com".to_owned()),
        active: None,
        name: Some(ScimName {
            given_name: Some(" Alice ".to_owned()),
            family_name: Some(" Example ".to_owned()),
            formatted: Some(" Alice Example ".to_owned()),
        }),
        emails: Some(vec![ScimEmail {
            value: Some("user@example.com".to_owned()),
            primary: Some(true),
        }]),
    };

    let normalized = normalize_scim_user_payload(payload, true).unwrap();
    assert_eq!(normalized.user_name, "user@example.com");
    assert_eq!(normalized.email, "user@example.com");
    assert_eq!(normalized.display_name.as_deref(), Some("Alice Example"));
    assert!(normalized.active);
}

#[test]
fn patch_syncs_user_name_and_email_identity() {
    let patch = normalize_patch(vec![ScimPatchOperation {
        op: "replace".to_owned(),
        path: Some("userName".to_owned()),
        value: json!("USER@example.com"),
    }])
    .unwrap();

    assert_eq!(patch.user_name.as_deref(), Some("user@example.com"));
    assert_eq!(patch.email.as_deref(), Some("user@example.com"));
}

#[test]
fn patch_rejects_conflicting_user_name_and_email_identity() {
    let patch = normalize_patch(vec![ScimPatchOperation {
        op: "replace".to_owned(),
        path: None,
        value: json!({
            "userName": "user@example.com",
            "emails": [{"value": "other@example.com", "primary": true}]
        }),
    }]);

    assert!(patch.is_err());
}

#[actix_web::test]
async fn scim_error_response_uses_scim_error_schema_and_exact_status() {
    let response = scim_error(StatusCode::FORBIDDEN, "forbidden", "SCIM token lacks scope");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["schemas"], json!([SCIM_ERROR_SCHEMA]));
    assert_eq!(value["status"], "403");
    assert_eq!(value["scimType"], "forbidden");
    assert_eq!(value["detail"], "SCIM token lacks scope");
}

#[test]
fn scim_user_schema_declares_core_identity_fields() {
    let schema = scim_user_schema();
    assert_eq!(schema["schemas"], json!([SCIM_SCHEMA_SCHEMA]));
    assert_eq!(schema["id"], SCIM_USER_SCHEMA);

    let names = schema["attributes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|attribute| attribute["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(names.contains(&"userName"));
    assert!(names.contains(&"emails"));
    assert!(names.contains(&"active"));
    assert!(names.contains(&"name"));
}

#[actix_web::test]
async fn scim_service_provider_config_advertises_only_supported_capabilities() {
    let (status, body) = response_json(scim_service_provider_config_response()).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["schemas"],
        json!([SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA])
    );
    assert_eq!(body["patch"]["supported"], true);
    assert_eq!(body["bulk"]["supported"], false);
    assert_eq!(body["filter"]["supported"], true);
    assert_eq!(body["filter"]["maxResults"], 200);
    assert_eq!(body["authenticationSchemes"][0]["type"], "oauthbearertoken");
    assert!(body.get("scim_bearer_token").is_none());
}

#[actix_web::test]
async fn scim_schemas_and_resource_types_use_list_response_shape() {
    let (schemas_status, schemas) = response_json(scim_schemas_response()).await;
    let (types_status, resource_types) = response_json(scim_resource_types_response()).await;

    assert_eq!(schemas_status, StatusCode::OK);
    assert_eq!(schemas["schemas"], json!([SCIM_LIST_SCHEMA]));
    assert_eq!(schemas["totalResults"], 1);
    assert_eq!(schemas["itemsPerPage"], 1);
    assert_eq!(schemas["Resources"][0]["id"], SCIM_USER_SCHEMA);

    assert_eq!(types_status, StatusCode::OK);
    assert_eq!(resource_types["schemas"], json!([SCIM_LIST_SCHEMA]));
    assert_eq!(resource_types["Resources"][0]["id"], "User");
    assert_eq!(resource_types["Resources"][0]["endpoint"], "/Users");
    assert_eq!(resource_types["Resources"][0]["schema"], SCIM_USER_SCHEMA);
}

#[actix_web::test]
async fn scim_list_users_response_preserves_pagination_and_hides_internal_user_fields() {
    let user = user_row(
        uuid_fixture(0x44444444444444444444444444444444),
        "alice@example.test",
    );

    let (status, body) = response_json(scim_list_users_response(10, 3, vec![user.clone()])).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["schemas"], json!([SCIM_LIST_SCHEMA]));
    assert_eq!(body["totalResults"], 10);
    assert_eq!(body["startIndex"], 3);
    assert_eq!(body["itemsPerPage"], 1);
    let resource = body["Resources"][0]
        .as_object()
        .expect("SCIM resource should be an object");
    assert_eq!(resource["schemas"], json!([SCIM_USER_SCHEMA]));
    assert_eq!(resource["id"], json!(user.id));
    assert_eq!(resource["userName"], "alice@example.test");
    assert_eq!(resource["emails"][0]["value"], "alice@example.test");
    assert_eq!(
        resource["meta"]["location"],
        format!("/scim/v2/Users/{}", user.id)
    );
    for forbidden in [
        "tenant_id",
        "realm_id",
        "organization_id",
        "password_hash",
        "role",
        "admin_level",
        "mfa_enabled",
        "phone_number",
    ] {
        assert!(
            resource.get(forbidden).is_none(),
            "{forbidden} must not be exposed through SCIM user projection"
        );
    }
}

#[actix_web::test]
async fn scim_create_user_response_returns_created_public_projection() {
    let user = user_row(
        uuid_fixture(0x55555555555555555555555555555555),
        "created@example.test",
    );

    let (status, body) = response_json(scim_create_user_response(user)).await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["schemas"], json!([SCIM_USER_SCHEMA]));
    assert_eq!(body["userName"], "created@example.test");
    assert!(body.get("password_hash").is_none());
    assert!(body.get("tenant_id").is_none());
}

#[actix_web::test]
async fn scim_conflict_and_not_found_errors_use_exact_scim_error_shape() {
    let (conflict_status, conflict) = response_json(scim_uniqueness_conflict_response()).await;
    assert_eq!(conflict_status, StatusCode::CONFLICT);
    assert_eq!(conflict["schemas"], json!([SCIM_ERROR_SCHEMA]));
    assert_eq!(conflict["status"], "409");
    assert_eq!(conflict["scimType"], "uniqueness");
    assert_eq!(conflict["detail"], "userName or email already exists");

    let (missing_status, missing) = response_json(scim_user_not_found_response()).await;
    assert_eq!(missing_status, StatusCode::NOT_FOUND);
    assert_eq!(missing["schemas"], json!([SCIM_ERROR_SCHEMA]));
    assert_eq!(missing["status"], "404");
    assert_eq!(missing["scimType"], "notFound");
    assert_eq!(missing["detail"], "user not found");
}

#[actix_web::test]
async fn scim_delete_response_is_not_found_or_empty_no_content() {
    let (missing_status, missing) = response_json(scim_delete_user_response(0)).await;
    assert_eq!(missing_status, StatusCode::NOT_FOUND);
    assert_eq!(missing["scimType"], "notFound");

    let response = scim_delete_user_response(1);
    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(body.is_empty());
}

#[actix_web::test]
async fn scim_metadata_endpoints_require_bearer_before_disclosing_capabilities() {
    let state = Data::new(test_state());
    let req = actix_web::test::TestRequest::default().to_http_request();

    assert_missing_bearer_is_scim_unauthorized(
        scim_service_provider_config(state.clone(), req.clone()).await,
    )
    .await;
    assert_missing_bearer_is_scim_unauthorized(scim_schemas(state.clone(), req.clone()).await)
        .await;
    assert_missing_bearer_is_scim_unauthorized(scim_resource_types(state, req).await).await;
}

#[actix_web::test]
async fn scim_metadata_endpoints_accept_configured_legacy_bearer_token() {
    let state = Data::new(test_state_with_scim_bearer_token(Some(
        "legacy-scim-secret",
    )));
    let req = bearer_request("legacy-scim-secret");

    let (config_status, config) =
        response_json(scim_service_provider_config(state.clone(), req.clone()).await).await;
    assert_eq!(config_status, StatusCode::OK);
    assert_eq!(
        config["schemas"],
        json!([SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA])
    );

    let (schemas_status, schemas) =
        response_json(scim_schemas(state.clone(), req.clone()).await).await;
    assert_eq!(schemas_status, StatusCode::OK);
    assert_eq!(schemas["schemas"], json!([SCIM_LIST_SCHEMA]));
    assert_eq!(schemas["Resources"][0]["id"], SCIM_USER_SCHEMA);

    let (types_status, resource_types) = response_json(scim_resource_types(state, req).await).await;
    assert_eq!(types_status, StatusCode::OK);
    assert_eq!(resource_types["schemas"], json!([SCIM_LIST_SCHEMA]));
    assert_eq!(resource_types["Resources"][0]["schema"], SCIM_USER_SCHEMA);
}

#[actix_web::test]
async fn scim_list_users_rejects_invalid_filter_before_database_access() {
    let state = Data::new(test_state_with_scim_bearer_token(Some(
        "legacy-scim-secret",
    )));
    let req = bearer_request("legacy-scim-secret");

    assert_scim_error_response(
        scim_list_users(
            state,
            req,
            Query(ScimListQuery {
                start_index: Some(1),
                count: Some(10),
                filter: Some(r#"email eq "user@example.test""#.to_owned()),
            }),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "invalidFilter",
        "only userName filters are supported",
    )
    .await;
}

#[actix_web::test]
async fn scim_create_and_replace_user_reject_identity_mismatch_before_database_access() {
    let state = Data::new(test_state_with_scim_bearer_token(Some(
        "legacy-scim-secret",
    )));
    let req = bearer_request("legacy-scim-secret");
    let user_id = uuid_fixture(0x77777777777777777777777777777777);

    assert_scim_error_response(
        scim_create_user(
            state.clone(),
            req.clone(),
            Json(scim_user_request_mismatched_identity_fixture()),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "invalidValue",
        "primary email must match userName",
    )
    .await;
    assert_scim_error_response(
        scim_replace_user(
            state,
            req,
            actix_web::web::Path::from(user_id),
            Json(scim_user_request_mismatched_identity_fixture()),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "invalidValue",
        "primary email must match userName",
    )
    .await;
}

#[actix_web::test]
async fn scim_patch_user_rejects_invalid_schema_and_invalid_path_before_database_access() {
    let state = Data::new(test_state_with_scim_bearer_token(Some(
        "legacy-scim-secret",
    )));
    let req = bearer_request("legacy-scim-secret");
    let user_id = uuid_fixture(0x88888888888888888888888888888888);

    assert_scim_error_response(
        scim_patch_user(
            state.clone(),
            req.clone(),
            actix_web::web::Path::from(user_id),
            Json(ScimPatchRequest {
                schemas: vec!["urn:example:unsupported:PatchOp".to_owned()],
                operations: vec![ScimPatchOperation {
                    op: "replace".to_owned(),
                    path: Some("active".to_owned()),
                    value: json!(false),
                }],
            }),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "invalidSyntax",
        "unsupported PATCH schema",
    )
    .await;
    assert_scim_error_response(
        scim_patch_user(
            state,
            req,
            actix_web::web::Path::from(user_id),
            Json(ScimPatchRequest {
                schemas: vec![SCIM_PATCH_SCHEMA.to_owned()],
                operations: vec![ScimPatchOperation {
                    op: "replace".to_owned(),
                    path: Some("password".to_owned()),
                    value: json!("secret"),
                }],
            }),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "invalidPath",
        "unsupported path",
    )
    .await;
}

#[actix_web::test]
async fn scim_read_endpoints_surface_backend_unavailable_after_legacy_auth() {
    let state = Data::new(test_state_with_scim_bearer_token(Some(
        "legacy-scim-secret",
    )));
    let req = bearer_request("legacy-scim-secret");
    let user_id = uuid_fixture(0x99999999999999999999999999999999);

    assert_scim_error_response(
        scim_list_users(
            state.clone(),
            req.clone(),
            Query(ScimListQuery {
                start_index: Some(1),
                count: Some(10),
                filter: Some(r#"userName eq "user@example.test""#.to_owned()),
            }),
        )
        .await,
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "backend unavailable",
    )
    .await;
    assert_scim_error_response(
        scim_get_user(state, req, actix_web::web::Path::from(user_id)).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "backend unavailable",
    )
    .await;
}

#[actix_web::test]
async fn scim_mutating_endpoints_surface_backend_unavailable_after_legacy_auth() {
    let state = Data::new(test_state_with_scim_bearer_token(Some(
        "legacy-scim-secret",
    )));
    let req = bearer_request("legacy-scim-secret");
    let user_id = uuid_fixture(0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa);
    let patch_payload = ScimPatchRequest {
        schemas: vec![SCIM_PATCH_SCHEMA.to_owned()],
        operations: vec![ScimPatchOperation {
            op: "replace".to_owned(),
            path: Some("active".to_owned()),
            value: json!(false),
        }],
    };

    assert_scim_error_response(
        scim_create_user(
            state.clone(),
            req.clone(),
            Json(scim_user_request_fixture()),
        )
        .await,
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "backend unavailable",
    )
    .await;
    assert_scim_error_response(
        scim_replace_user(
            state.clone(),
            req.clone(),
            actix_web::web::Path::from(user_id),
            Json(scim_user_request_fixture()),
        )
        .await,
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "backend unavailable",
    )
    .await;
    assert_scim_error_response(
        scim_patch_user(
            state.clone(),
            req.clone(),
            actix_web::web::Path::from(user_id),
            Json(patch_payload),
        )
        .await,
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "backend unavailable",
    )
    .await;
    assert_scim_error_response(
        scim_delete_user(state, req, actix_web::web::Path::from(user_id)).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "backend unavailable",
    )
    .await;
}

#[actix_web::test]
async fn scim_user_lifecycle_enforces_bearer_scope_identity_uniqueness_and_soft_delete() {
    let suffix = Uuid::now_v7().simple().to_string();
    let token = format!("legacy-scim-{suffix}");
    let Some(state) = live_state_with_scim_bearer_token(&token).await else {
        return;
    };
    let email = format!("scim-lifecycle-{suffix}@example.test");
    cleanup_scim_user_by_email(&state, &email).await;
    let req = bearer_request(&token);

    let (create_status, created) = response_json(
        scim_create_user(
            state.clone(),
            req.clone(),
            Json(scim_user_request_for_email(&email)),
        )
        .await,
    )
    .await;
    assert_eq!(create_status, StatusCode::CREATED);
    assert_eq!(created["schemas"], json!([SCIM_USER_SCHEMA]));
    assert_eq!(created["userName"], email);
    assert!(created.get("password_hash").is_none());
    let user_id = serde_json::from_value::<Uuid>(created["id"].clone())
        .expect("SCIM create response should include id");

    assert_scim_error_response(
        scim_create_user(
            state.clone(),
            req.clone(),
            Json(scim_user_request_for_email(&email)),
        )
        .await,
        StatusCode::CONFLICT,
        "uniqueness",
        "userName or email already exists",
    )
    .await;

    let (list_status, list) = response_json(
        scim_list_users(
            state.clone(),
            req.clone(),
            Query(ScimListQuery {
                start_index: Some(1),
                count: Some(10),
                filter: Some(format!(r#"userName eq "{email}""#)),
            }),
        )
        .await,
    )
    .await;
    assert_eq!(list_status, StatusCode::OK);
    assert_eq!(list["totalResults"], 1);
    assert_eq!(list["Resources"][0]["id"], json!(user_id));

    let (empty_list_status, empty_list) = response_json(
        scim_list_users(
            state.clone(),
            req.clone(),
            Query(ScimListQuery {
                start_index: Some(1),
                count: Some(0),
                filter: Some(format!(r#"userName eq "{email}""#)),
            }),
        )
        .await,
    )
    .await;
    assert_eq!(empty_list_status, StatusCode::OK);
    assert_eq!(empty_list["totalResults"], 1);
    assert_eq!(empty_list["itemsPerPage"], 0);
    assert!(empty_list["Resources"].as_array().unwrap().is_empty());

    let (get_status, got) = response_json(
        scim_get_user(
            state.clone(),
            req.clone(),
            actix_web::web::Path::from(user_id),
        )
        .await,
    )
    .await;
    assert_eq!(get_status, StatusCode::OK);
    assert_eq!(got["userName"], email);

    let replace_payload = ScimUserRequest {
        user_name: Some(email.clone()),
        active: Some(true),
        name: Some(ScimName {
            given_name: Some("Updated".to_owned()),
            family_name: Some("User".to_owned()),
            formatted: Some("Updated User".to_owned()),
        }),
        emails: Some(vec![ScimEmail {
            value: Some(email.clone()),
            primary: Some(true),
        }]),
    };
    let (replace_status, replaced) = response_json(
        scim_replace_user(
            state.clone(),
            req.clone(),
            actix_web::web::Path::from(user_id),
            Json(replace_payload),
        )
        .await,
    )
    .await;
    assert_eq!(replace_status, StatusCode::OK);
    assert_eq!(replaced["name"]["givenName"], "Updated");

    let (patch_status, patched) = response_json(
        scim_patch_user(
            state.clone(),
            req.clone(),
            actix_web::web::Path::from(user_id),
            Json(ScimPatchRequest {
                schemas: vec![SCIM_PATCH_SCHEMA.to_owned()],
                operations: vec![ScimPatchOperation {
                    op: "replace".to_owned(),
                    path: Some("active".to_owned()),
                    value: json!(false),
                }],
            }),
        )
        .await,
    )
    .await;
    assert_eq!(patch_status, StatusCode::OK);
    assert_eq!(patched["active"], false);

    let delete_response = scim_delete_user(
        state.clone(),
        req.clone(),
        actix_web::web::Path::from(user_id),
    )
    .await;
    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);

    assert_scim_error_response(
        scim_replace_user(
            state.clone(),
            req.clone(),
            actix_web::web::Path::from(Uuid::now_v7()),
            Json(scim_user_request_fixture()),
        )
        .await,
        StatusCode::NOT_FOUND,
        "notFound",
        "user not found",
    )
    .await;
    assert_scim_error_response(
        scim_get_user(state, req, actix_web::web::Path::from(Uuid::now_v7())).await,
        StatusCode::NOT_FOUND,
        "notFound",
        "user not found",
    )
    .await;
}

#[actix_web::test]
async fn scim_delete_is_a_soft_delete_and_keeps_resource_visible_as_inactive() {
    let suffix = Uuid::now_v7().simple().to_string();
    let token = format!("legacy-scim-soft-delete-{suffix}");
    let Some(state) = live_state_with_scim_bearer_token(&token).await else {
        return;
    };
    let email = format!("scim-soft-delete-{suffix}@example.test");
    cleanup_scim_user_by_email(&state, &email).await;
    let req = bearer_request(&token);
    let user_id = create_scim_user_id(state.clone(), &req, &email).await;

    let delete_response = scim_delete_user(
        state.clone(),
        req.clone(),
        actix_web::web::Path::from(user_id),
    )
    .await;
    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);

    let (get_status, got) = response_json(
        scim_get_user(
            state.clone(),
            req.clone(),
            actix_web::web::Path::from(user_id),
        )
        .await,
    )
    .await;
    assert_eq!(get_status, StatusCode::OK);
    assert_eq!(got["userName"], email);
    assert_eq!(got["active"], false);
    assert!(got.get("password_hash").is_none());
    assert!(got.get("tenant_id").is_none());

    let (list_status, list) = response_json(
        scim_list_users(
            state,
            req,
            Query(ScimListQuery {
                start_index: Some(1),
                count: Some(10),
                filter: Some(format!(r#"userName eq "{email}""#)),
            }),
        )
        .await,
    )
    .await;
    assert_eq!(list_status, StatusCode::OK);
    assert_eq!(list["totalResults"], 1);
    assert_eq!(list["Resources"][0]["id"], json!(user_id));
    assert_eq!(list["Resources"][0]["active"], false);
}

#[actix_web::test]
async fn scim_replace_and_patch_return_uniqueness_conflicts_without_internal_fields() {
    let suffix = Uuid::now_v7().simple().to_string();
    let token = format!("legacy-scim-uniqueness-{suffix}");
    let Some(state) = live_state_with_scim_bearer_token(&token).await else {
        return;
    };
    let first_email = format!("scim-uniqueness-a-{suffix}@example.test");
    let second_email = format!("scim-uniqueness-b-{suffix}@example.test");
    cleanup_scim_user_by_email(&state, &first_email).await;
    cleanup_scim_user_by_email(&state, &second_email).await;
    let req = bearer_request(&token);
    let first_id = create_scim_user_id(state.clone(), &req, &first_email).await;
    let _second_id = create_scim_user_id(state.clone(), &req, &second_email).await;

    let (replace_status, replace_body) = response_json(
        scim_replace_user(
            state.clone(),
            req.clone(),
            actix_web::web::Path::from(first_id),
            Json(scim_user_request_for_email(&second_email)),
        )
        .await,
    )
    .await;
    assert_eq!(replace_status, StatusCode::CONFLICT);
    assert_eq!(replace_body["schemas"], json!([SCIM_ERROR_SCHEMA]));
    assert_eq!(replace_body["scimType"], "uniqueness");
    assert_eq!(replace_body["detail"], "userName or email already exists");
    assert!(replace_body.get("password_hash").is_none());
    assert!(replace_body.get("tenant_id").is_none());

    let (patch_status, patch_body) = response_json(
        scim_patch_user(
            state,
            req,
            actix_web::web::Path::from(first_id),
            Json(ScimPatchRequest {
                schemas: vec![SCIM_PATCH_SCHEMA.to_owned()],
                operations: vec![ScimPatchOperation {
                    op: "replace".to_owned(),
                    path: None,
                    value: json!({
                        "userName": second_email,
                        "emails": [{"value": second_email, "primary": true}]
                    }),
                }],
            }),
        )
        .await,
    )
    .await;
    assert_eq!(patch_status, StatusCode::CONFLICT);
    assert_eq!(patch_body["schemas"], json!([SCIM_ERROR_SCHEMA]));
    assert_eq!(patch_body["scimType"], "uniqueness");
    assert_eq!(patch_body["detail"], "userName or email already exists");
    assert!(patch_body.get("password_hash").is_none());
    assert!(patch_body.get("tenant_id").is_none());
}

#[actix_web::test]
async fn scim_patch_bulk_replace_updates_identity_profile_and_filter_projection() {
    let suffix = Uuid::now_v7().simple().to_string();
    let token = format!("legacy-scim-patch-{suffix}");
    let Some(state) = live_state_with_scim_bearer_token(&token).await else {
        return;
    };
    let original_email = format!("scim-patch-a-{suffix}@example.test");
    let updated_email = format!("scim-patch-b-{suffix}@example.test");
    cleanup_scim_user_by_email(&state, &original_email).await;
    cleanup_scim_user_by_email(&state, &updated_email).await;
    let req = bearer_request(&token);
    let user_id = create_scim_user_id(state.clone(), &req, &original_email).await;

    let (patch_status, patched) = response_json(
        scim_patch_user(
            state.clone(),
            req.clone(),
            actix_web::web::Path::from(user_id),
            Json(ScimPatchRequest {
                schemas: vec![SCIM_PATCH_SCHEMA.to_owned()],
                operations: vec![ScimPatchOperation {
                    op: "replace".to_owned(),
                    path: None,
                    value: json!({
                        "userName": updated_email,
                        "emails": [{"value": updated_email, "primary": true}],
                        "active": false,
                        "name": {
                            "formatted": "Patched User",
                            "givenName": "Patched",
                            "familyName": "User"
                        }
                    }),
                }],
            }),
        )
        .await,
    )
    .await;
    assert_eq!(patch_status, StatusCode::OK);
    assert_eq!(patched["schemas"], json!([SCIM_USER_SCHEMA]));
    assert_eq!(patched["userName"], updated_email);
    assert_eq!(patched["emails"][0]["value"], updated_email);
    assert_eq!(patched["active"], false);
    assert_eq!(patched["name"]["formatted"], "Patched User");
    assert_eq!(patched["name"]["givenName"], "Patched");
    assert_eq!(patched["name"]["familyName"], "User");
    assert!(patched.get("password_hash").is_none());
    assert!(patched.get("tenant_id").is_none());

    let (list_status, list) = response_json(
        scim_list_users(
            state,
            req,
            Query(ScimListQuery {
                start_index: Some(1),
                count: Some(10),
                filter: Some(format!(r#"userName eq "{updated_email}""#)),
            }),
        )
        .await,
    )
    .await;
    assert_eq!(list_status, StatusCode::OK);
    assert_eq!(list["totalResults"], 1);
    assert_eq!(list["Resources"][0]["id"], json!(user_id));
    assert_eq!(list["Resources"][0]["userName"], updated_email);
    assert_eq!(list["Resources"][0]["active"], false);
}

#[actix_web::test]
async fn scim_patch_reports_not_found_for_missing_user_after_successful_authentication() {
    let suffix = Uuid::now_v7().simple().to_string();
    let token = format!("legacy-scim-missing-patch-{suffix}");
    let Some(state) = live_state_with_scim_bearer_token(&token).await else {
        return;
    };
    let req = bearer_request(&token);

    assert_scim_error_response(
        scim_patch_user(
            state,
            req,
            actix_web::web::Path::from(Uuid::now_v7()),
            Json(ScimPatchRequest {
                schemas: vec![SCIM_PATCH_SCHEMA.to_owned()],
                operations: vec![ScimPatchOperation {
                    op: "replace".to_owned(),
                    path: Some("active".to_owned()),
                    value: json!(false),
                }],
            }),
        )
        .await,
        StatusCode::NOT_FOUND,
        "notFound",
        "user not found",
    )
    .await;
}

#[actix_web::test]
async fn scim_user_endpoints_require_bearer_before_user_state_access() {
    let state = Data::new(test_state());
    let req = actix_web::test::TestRequest::default().to_http_request();
    let user_id = uuid_fixture(0x66666666666666666666666666666666);
    let patch_payload = ScimPatchRequest {
        schemas: vec![SCIM_PATCH_SCHEMA.to_owned()],
        operations: vec![ScimPatchOperation {
            op: "replace".to_owned(),
            path: Some("active".to_owned()),
            value: json!(false),
        }],
    };

    assert_missing_bearer_is_scim_unauthorized(
        scim_list_users(
            state.clone(),
            req.clone(),
            Query(ScimListQuery {
                start_index: Some(1),
                count: Some(10),
                filter: None,
            }),
        )
        .await,
    )
    .await;
    assert_missing_bearer_is_scim_unauthorized(
        scim_create_user(
            state.clone(),
            req.clone(),
            Json(scim_user_request_fixture()),
        )
        .await,
    )
    .await;
    assert_missing_bearer_is_scim_unauthorized(
        scim_get_user(
            state.clone(),
            req.clone(),
            actix_web::web::Path::from(user_id),
        )
        .await,
    )
    .await;
    assert_missing_bearer_is_scim_unauthorized(
        scim_replace_user(
            state.clone(),
            req.clone(),
            actix_web::web::Path::from(user_id),
            Json(scim_user_request_fixture()),
        )
        .await,
    )
    .await;
    assert_missing_bearer_is_scim_unauthorized(
        scim_patch_user(
            state.clone(),
            req.clone(),
            actix_web::web::Path::from(user_id),
            Json(patch_payload),
        )
        .await,
    )
    .await;
    assert_missing_bearer_is_scim_unauthorized(
        scim_delete_user(state, req, actix_web::web::Path::from(user_id)).await,
    )
    .await;
}

#[actix_web::test]
async fn scim_list_users_surfaces_backend_unavailable_when_projection_query_breaks() {
    let schema = format!("scim_projection_{}", Uuid::now_v7().simple());
    let token = "legacy-scim-projection-token";
    let Some(state) = live_state_with_isolated_scim_bearer_token(token, &schema, &["users"]).await
    else {
        return;
    };
    let req = bearer_request(token);
    let email = format!("projection-{}@example.test", Uuid::now_v7().simple());
    let _ = create_scim_user_id(state.clone(), &req, &email).await;
    rename_scim_column(
        &state,
        &schema,
        "users",
        "display_name",
        "display_name_unavailable",
    )
    .await;

    let response = scim_list_users(
        state.clone(),
        req,
        Query(ScimListQuery {
            start_index: Some(1),
            count: Some(10),
            filter: Some(format!(r#"userName eq "{email}""#)),
        }),
    )
    .await;
    cleanup_scim_schema(&state, &schema).await;

    assert_scim_error_response(
        response,
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "backend unavailable",
    )
    .await;
}

#[actix_web::test]
async fn scim_create_user_surfaces_backend_unavailable_when_insert_query_breaks() {
    let schema = format!("scim_create_write_{}", Uuid::now_v7().simple());
    let token = "legacy-scim-create-write-token";
    let Some(state) = live_state_with_isolated_scim_bearer_token(token, &schema, &["users"]).await
    else {
        return;
    };
    rename_scim_column(
        &state,
        &schema,
        "users",
        "display_name",
        "display_name_unavailable",
    )
    .await;

    let response = scim_create_user(
        state.clone(),
        bearer_request(token),
        Json(scim_user_request_for_email(&format!(
            "create-write-{}@example.test",
            Uuid::now_v7().simple()
        ))),
    )
    .await;
    cleanup_scim_schema(&state, &schema).await;

    assert_scim_error_response(
        response,
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "backend unavailable",
    )
    .await;
}

#[actix_web::test]
async fn scim_get_user_surfaces_backend_unavailable_when_projection_query_breaks() {
    let schema = format!("scim_get_projection_{}", Uuid::now_v7().simple());
    let token = "legacy-scim-get-projection-token";
    let Some(state) = live_state_with_isolated_scim_bearer_token(token, &schema, &["users"]).await
    else {
        return;
    };
    let req = bearer_request(token);
    let email = format!("get-projection-{}@example.test", Uuid::now_v7().simple());
    let user_id = create_scim_user_id(state.clone(), &req, &email).await;
    rename_scim_column(
        &state,
        &schema,
        "users",
        "display_name",
        "display_name_unavailable",
    )
    .await;

    let response = scim_get_user(state.clone(), req, actix_web::web::Path::from(user_id)).await;
    cleanup_scim_schema(&state, &schema).await;

    assert_scim_error_response(
        response,
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "backend unavailable",
    )
    .await;
}

#[actix_web::test]
async fn scim_replace_user_surfaces_backend_unavailable_when_update_query_breaks() {
    let schema = format!("scim_replace_write_{}", Uuid::now_v7().simple());
    let token = "legacy-scim-replace-write-token";
    let Some(state) = live_state_with_isolated_scim_bearer_token(token, &schema, &["users"]).await
    else {
        return;
    };
    let req = bearer_request(token);
    let email = format!("replace-write-{}@example.test", Uuid::now_v7().simple());
    let user_id = create_scim_user_id(state.clone(), &req, &email).await;
    rename_scim_column(
        &state,
        &schema,
        "users",
        "updated_at",
        "updated_at_unavailable",
    )
    .await;

    let response = scim_replace_user(
        state.clone(),
        req,
        actix_web::web::Path::from(user_id),
        Json(scim_user_request_for_email(&format!(
            "replace-after-failure-{}@example.test",
            Uuid::now_v7().simple()
        ))),
    )
    .await;
    cleanup_scim_schema(&state, &schema).await;

    assert_scim_error_response(
        response,
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "backend unavailable",
    )
    .await;
}

#[actix_web::test]
async fn scim_delete_user_surfaces_backend_unavailable_when_soft_delete_query_breaks() {
    let schema = format!("scim_delete_write_{}", Uuid::now_v7().simple());
    let token = "legacy-scim-delete-write-token";
    let Some(state) = live_state_with_isolated_scim_bearer_token(token, &schema, &["users"]).await
    else {
        return;
    };
    let req = bearer_request(token);
    let email = format!("delete-write-{}@example.test", Uuid::now_v7().simple());
    let user_id = create_scim_user_id(state.clone(), &req, &email).await;
    rename_scim_column(
        &state,
        &schema,
        "users",
        "updated_at",
        "updated_at_unavailable",
    )
    .await;

    let response = scim_delete_user(state.clone(), req, actix_web::web::Path::from(user_id)).await;
    cleanup_scim_schema(&state, &schema).await;

    assert_scim_error_response(
        response,
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "backend unavailable",
    )
    .await;
}
