use super::*;

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
