use super::*;

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
