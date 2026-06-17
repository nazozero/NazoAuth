use super::*;
use std::sync::Arc;

use crate::config::ConfigSource;
use crate::db::create_pool;
use crate::domain::{ActiveSigningKey, Keyset};

fn test_state(scim_bearer_token: Option<&str>) -> AppState {
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
        keyset: Arc::new(Keyset {
            active_kid: "test-kid".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
            verification_keys: Vec::new(),
        }),
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

async fn assert_scim_error_response(
    response: HttpResponse,
    expected_status: StatusCode,
    expected_scim_type: &str,
    expected_detail: &str,
) {
    let (status, body) = response_json(response).await;
    assert_eq!(status, expected_status);
    assert_eq!(body["status"], expected_status.as_u16().to_string());
    assert_eq!(body["scimType"], expected_scim_type);
    assert_eq!(body["detail"], expected_detail);
}

// bearer_token

#[test]
fn bearer_token_extracts_valid_bearer_token() {
    let req = actix_web::test::TestRequest::default()
        .insert_header((header::AUTHORIZATION, "Bearer scim-secret-token"))
        .to_http_request();
    assert_eq!(bearer_token(&req), Some("scim-secret-token"));
}

#[test]
fn bearer_token_rejects_basic_scheme() {
    let req = actix_web::test::TestRequest::default()
        .insert_header((header::AUTHORIZATION, "Basic dXNlcjpwYXNz"))
        .to_http_request();
    assert_eq!(bearer_token(&req), None);
}

#[test]
fn bearer_token_rejects_digest_scheme() {
    let req = actix_web::test::TestRequest::default()
        .insert_header((header::AUTHORIZATION, "Digest token"))
        .to_http_request();
    assert_eq!(bearer_token(&req), None);
}

#[test]
fn bearer_token_is_case_insensitive_for_scheme() {
    let req = actix_web::test::TestRequest::default()
        .insert_header((header::AUTHORIZATION, "bearer token123"))
        .to_http_request();
    assert_eq!(bearer_token(&req), Some("token123"));
}

#[test]
fn bearer_token_rejects_empty_token() {
    let req = actix_web::test::TestRequest::default()
        .insert_header((header::AUTHORIZATION, "Bearer   "))
        .to_http_request();
    assert_eq!(bearer_token(&req), None);
}

#[test]
fn bearer_token_rejects_token_with_inner_whitespace() {
    let req = actix_web::test::TestRequest::default()
        .insert_header((header::AUTHORIZATION, "Bearer token with spaces"))
        .to_http_request();
    assert_eq!(bearer_token(&req), None);
}

#[test]
fn bearer_token_returns_none_when_authorization_header_missing() {
    let req = actix_web::test::TestRequest::default().to_http_request();
    assert_eq!(bearer_token(&req), None);
}

#[test]
fn bearer_token_trims_whitespace_around_scheme() {
    let req = actix_web::test::TestRequest::default()
        .insert_header((header::AUTHORIZATION, "  Bearer token123  "))
        .to_http_request();
    assert_eq!(bearer_token(&req), Some("token123"));
}

#[test]
fn bearer_token_handles_token_with_hyphens_and_underscores() {
    let req = actix_web::test::TestRequest::default()
        .insert_header((header::AUTHORIZATION, "Bearer scim_token-v2_secret"))
        .to_http_request();
    assert_eq!(bearer_token(&req), Some("scim_token-v2_secret"));
}

#[test]
fn legacy_scim_credential_requires_exact_configured_token() {
    let state = test_state(Some("legacy-scim-secret"));
    let credential = legacy_scim_credential(&state, "legacy-scim-secret")
        .expect("configured legacy token should be accepted");
    assert_eq!(credential.token_id, None);
    assert_eq!(credential.tenant_id, default_tenant_context().tenant_id);
    assert_eq!(
        credential.scopes,
        vec![SCIM_SCOPE_READ.to_owned(), SCIM_SCOPE_WRITE.to_owned()]
    );
    assert_eq!(credential.source, "legacy-env");
    assert!(legacy_scim_credential(&state, "legacy-scim-secret ").is_none());
    assert!(legacy_scim_credential(&state, "different-secret").is_none());
    assert!(legacy_scim_credential(&test_state(None), "legacy-scim-secret").is_none());
}

#[actix_web::test]
async fn require_scim_bearer_accepts_legacy_token_when_database_lookup_fails() {
    let state = test_state(Some("legacy-scim-secret"));
    let req = bearer_request("legacy-scim-secret");

    let credential = require_scim_bearer(&state, &req, ScimRequiredScope::Write)
        .await
        .expect("legacy token should authorize when database lookup is unavailable");

    assert_eq!(credential.token_id, None);
    assert_eq!(credential.tenant_id, default_tenant_context().tenant_id);
    assert_eq!(
        credential.scopes,
        vec![SCIM_SCOPE_READ.to_owned(), SCIM_SCOPE_WRITE.to_owned()]
    );
    assert_eq!(credential.source, "legacy-env");
}

#[actix_web::test]
async fn require_scim_bearer_surfaces_backend_unavailable_for_unknown_token_during_lookup_error() {
    let state = test_state(Some("legacy-scim-secret"));
    let req = bearer_request("not-the-legacy-token");

    let response = match require_scim_bearer(&state, &req, ScimRequiredScope::Read).await {
        Ok(_) => panic!("unknown token should not bypass lookup failure"),
        Err(response) => response,
    };

    assert_scim_error_response(
        response,
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "backend unavailable",
    )
    .await;
}

#[actix_web::test]
async fn authorize_scim_credential_rejects_insufficient_scope() {
    let state = test_state(None);
    let req = bearer_request("ignored");
    let credential = ScimCredential {
        token_id: None,
        tenant_id: default_tenant_context().tenant_id,
        scopes: vec![SCIM_SCOPE_READ.to_owned()],
        source: "test",
    };

    let response =
        match authorize_scim_credential(&state, &req, ScimRequiredScope::Write, credential).await {
            Ok(_) => panic!("read-only credential must not authorize write access"),
            Err(response) => response,
        };

    assert_scim_error_response(
        response,
        StatusCode::FORBIDDEN,
        "forbidden",
        "SCIM token lacks the required scope",
    )
    .await;
}

// scim_credential_allows

#[test]
fn credential_allows_read_with_read_scope() {
    let credential = ScimCredential {
        token_id: None,
        tenant_id: default_tenant_context().tenant_id,
        scopes: vec![SCIM_SCOPE_READ.to_owned()],
        source: "test",
    };
    assert!(scim_credential_allows(&credential, ScimRequiredScope::Read));
}

#[test]
fn credential_denies_write_with_read_only_scope() {
    let credential = ScimCredential {
        token_id: None,
        tenant_id: default_tenant_context().tenant_id,
        scopes: vec![SCIM_SCOPE_READ.to_owned()],
        source: "test",
    };
    assert!(!scim_credential_allows(
        &credential,
        ScimRequiredScope::Write
    ));
}

#[test]
fn credential_allows_write_with_write_scope() {
    let credential = ScimCredential {
        token_id: None,
        tenant_id: default_tenant_context().tenant_id,
        scopes: vec![SCIM_SCOPE_WRITE.to_owned()],
        source: "test",
    };
    assert!(scim_credential_allows(
        &credential,
        ScimRequiredScope::Write
    ));
}

#[test]
fn credential_denies_read_with_write_only_scope() {
    let credential = ScimCredential {
        token_id: None,
        tenant_id: default_tenant_context().tenant_id,
        scopes: vec![SCIM_SCOPE_WRITE.to_owned()],
        source: "test",
    };
    assert!(!scim_credential_allows(
        &credential,
        ScimRequiredScope::Read
    ));
}

#[test]
fn credential_allows_any_scope_with_wildcard() {
    let credential = ScimCredential {
        token_id: None,
        tenant_id: default_tenant_context().tenant_id,
        scopes: vec![SCIM_SCOPE_ALL.to_owned()],
        source: "test",
    };
    assert!(scim_credential_allows(&credential, ScimRequiredScope::Read));
    assert!(scim_credential_allows(
        &credential,
        ScimRequiredScope::Write
    ));
}

#[test]
fn credential_allows_with_both_read_and_write_scopes() {
    let credential = ScimCredential {
        token_id: None,
        tenant_id: default_tenant_context().tenant_id,
        scopes: vec![SCIM_SCOPE_READ.to_owned(), SCIM_SCOPE_WRITE.to_owned()],
        source: "test",
    };
    assert!(scim_credential_allows(&credential, ScimRequiredScope::Read));
    assert!(scim_credential_allows(
        &credential,
        ScimRequiredScope::Write
    ));
}

#[test]
fn credential_denies_when_scope_list_empty() {
    let credential = ScimCredential {
        token_id: None,
        tenant_id: default_tenant_context().tenant_id,
        scopes: vec![],
        source: "test",
    };
    assert!(!scim_credential_allows(
        &credential,
        ScimRequiredScope::Read
    ));
    assert!(!scim_credential_allows(
        &credential,
        ScimRequiredScope::Write
    ));
}

#[test]
fn credential_denies_when_scope_does_not_match() {
    let credential = ScimCredential {
        token_id: None,
        tenant_id: default_tenant_context().tenant_id,
        scopes: vec!["other:scope".to_owned()],
        source: "test",
    };
    assert!(!scim_credential_allows(
        &credential,
        ScimRequiredScope::Read
    ));
    assert!(!scim_credential_allows(
        &credential,
        ScimRequiredScope::Write
    ));
}

#[test]
fn credential_allows_wildcard_among_other_scopes() {
    let credential = ScimCredential {
        token_id: None,
        tenant_id: default_tenant_context().tenant_id,
        scopes: vec![SCIM_SCOPE_READ.to_owned(), SCIM_SCOPE_ALL.to_owned()],
        source: "test",
    };
    assert!(scim_credential_allows(&credential, ScimRequiredScope::Read));
    assert!(scim_credential_allows(
        &credential,
        ScimRequiredScope::Write
    ));
}

// ScimRequiredScope::as_str

#[test]
fn required_scope_read_returns_scim_read() {
    assert_eq!(ScimRequiredScope::Read.as_str(), SCIM_SCOPE_READ);
}

#[test]
fn required_scope_write_returns_scim_write() {
    assert_eq!(ScimRequiredScope::Write.as_str(), SCIM_SCOPE_WRITE);
}

#[test]
fn scope_constants_have_correct_values() {
    assert_eq!(SCIM_SCOPE_READ, "scim:read");
    assert_eq!(SCIM_SCOPE_WRITE, "scim:write");
    assert_eq!(SCIM_SCOPE_ALL, "scim:*");
}

// scim_scope_values

#[test]
fn scope_values_extracts_strings_from_json_array() {
    let scopes = scim_scope_values(&json!(["scim:read", "scim:write"]));
    assert_eq!(
        scopes,
        vec!["scim:read".to_owned(), "scim:write".to_owned()]
    );
}

#[test]
fn scope_values_skips_non_string_elements() {
    let scopes = scim_scope_values(&json!(["scim:read", 7, true, "scim:write"]));
    assert_eq!(
        scopes,
        vec!["scim:read".to_owned(), "scim:write".to_owned()]
    );
}

#[test]
fn scope_values_skips_empty_strings() {
    let scopes = scim_scope_values(&json!(["scim:read", "", "scim:write"]));
    assert_eq!(
        scopes,
        vec!["scim:read".to_owned(), "scim:write".to_owned()]
    );
}

#[test]
fn scope_values_trims_whitespace() {
    let scopes = scim_scope_values(&json!(["  scim:read  ", "scim:write"]));
    assert_eq!(
        scopes,
        vec!["scim:read".to_owned(), "scim:write".to_owned()]
    );
}

#[test]
fn scope_values_returns_empty_for_non_array() {
    let scopes = scim_scope_values(&json!("not-an-array"));
    assert!(scopes.is_empty());
}

#[test]
fn scope_values_returns_empty_for_null() {
    let scopes = scim_scope_values(&json!(null));
    assert!(scopes.is_empty());
}

#[test]
fn scope_values_returns_empty_for_object() {
    let scopes = scim_scope_values(&json!({"key": "value"}));
    assert!(scopes.is_empty());
}

#[test]
fn scope_values_returns_empty_for_empty_array() {
    let scopes = scim_scope_values(&json!([]));
    assert!(scopes.is_empty());
}

#[test]
fn scope_values_skips_whitespace_only_strings() {
    let scopes = scim_scope_values(&json!(["scim:read", "   ", "scim:write"]));
    assert_eq!(
        scopes,
        vec!["scim:read".to_owned(), "scim:write".to_owned()]
    );
}
