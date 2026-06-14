use super::*;

fn register_request() -> RegisterRequest {
    RegisterRequest {
        email: "User@Example.com".to_owned(),
        verification_code: "  123456  ".to_owned(),
        password: "correct horse battery staple".to_owned(),
    }
}

fn user_row() -> UserRow {
    let now = Utc::now();
    UserRow {
        id: Uuid::now_v7(),
        tenant_id: Uuid::now_v7(),
        realm_id: Uuid::now_v7(),
        organization_id: Uuid::now_v7(),
        username: "user@example.com".to_owned(),
        email: "user@example.com".to_owned(),
        display_name: None,
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
        role: "user".to_owned(),
        admin_level: 0,
        address_formatted: None,
        address_street_address: None,
        address_locality: None,
        address_region: None,
        address_postal_code: None,
        address_country: None,
        phone_number: None,
        phone_number_verified: false,
        email_verified: true,
        mfa_enabled: false,
        password_hash: "argon2-secret-hash".to_owned(),
        is_active: true,
        created_at: now,
        updated_at: now,
    }
}

#[test]
fn verification_code_for_lookup_trims_transport_whitespace_only() {
    let payload = register_request();

    assert_eq!(verification_code_for_lookup(&payload), "123456");
}

#[actix_web::test]
async fn register_success_response_exposes_only_public_identity() {
    let user = user_row();
    let response = register_success_response(user.clone());

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("register success response should collect");
    let body: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(body["id"], json!(user.id));
    assert_eq!(body["email"], "user@example.com");
    assert!(body.get("password_hash").is_none());
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());
    assert!(body.get("session").is_none());
    assert!(body.get("tenant_id").is_none());
}
