use super::*;

fn user_row() -> UserRow {
    let now = Utc::now();
    UserRow {
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

#[test]
fn patch_user_validation_allows_only_supported_roles() {
    let mut patch = empty_patch();
    patch.role = Some("owner".to_owned());

    let response = patch_user_validation_error(&patch)
        .expect("unsupported roles must fail before any database mutation");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("invalid_request")
    );
}

#[test]
fn patch_user_validation_rejects_negative_admin_level() {
    let mut patch = empty_patch();
    patch.role = Some("admin".to_owned());
    patch.admin_level = Some(-1);

    let response = patch_user_validation_error(&patch)
        .expect("negative privilege levels must fail before any database mutation");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
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
