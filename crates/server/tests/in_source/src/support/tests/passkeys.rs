use super::*;
use crate::support::OAuthJsonErrorFields;
use passkey_auth::{CosePublicKey, CredentialId, PasskeyCredential};

fn passkey_user_fixture() -> DatabaseUserFixture {
    DatabaseUserFixture {
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
        password_hash: "hash".to_owned(),
        is_active: true,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn passkey_user() -> PublicAccount {
    passkey_user_fixture().identity()
}

#[test]
fn passkey_user_handle_binds_tenant_and_user() {
    let user = passkey_user();

    let handle = passkey_user_handle(&user).unwrap();
    assert_eq!(handle.len(), 32);
    assert!(handle.starts_with(user.tenant_id().as_bytes()));
    assert!(handle.ends_with(user.id().as_bytes()));
}

#[test]
fn passkey_user_handle_rejects_nil_persisted_tenant_id_without_panicking() {
    let user = DatabaseUserFixture {
        tenant_id: Uuid::nil(),
        ..passkey_user_fixture()
    };

    assert!(PublicAccount::try_from(user).is_err());
}

#[test]
fn passkey_user_handle_rejects_nil_persisted_user_id_without_panicking() {
    let user = DatabaseUserFixture {
        id: Uuid::nil(),
        ..passkey_user_fixture()
    };

    assert!(PublicAccount::try_from(user).is_err());
}

#[test]
fn passkey_credential_id_is_base64url() {
    let credential = PasskeyCredential {
        id: CredentialId(vec![1, 2, 3, 4]),
        public_key_cose: CosePublicKey(vec![5, 6, 7]),
        counter: 0,
        transports: vec!["internal".to_owned()],
        aaguid: [0; 16],
    };

    assert_eq!(passkey_credential_id(&credential), "AQIDBA");
}

#[test]
fn ceremony_id_rejects_malformed_values() {
    assert!(normalize_ceremony_id("short").is_err());
    assert!(normalize_ceremony_id("x".repeat(300).as_str()).is_err());
    assert!(normalize_ceremony_id("abc/def/ghi/jkl/mno/pqr/stu/vwx/yz1234567890").is_err());
}

#[test]
fn ceremony_id_accepts_urlsafe_tokens() {
    let value = "abcdefghijklmnopqrstuvwxyzABCDEF0123456789-_";
    assert_eq!(normalize_ceremony_id(value).unwrap(), value);
}

#[test]
fn passkey_label_defaults_trims_and_rejects_oversized_input() {
    assert_eq!(normalize_passkey_label(None).unwrap(), "Passkey");
    assert_eq!(
        normalize_passkey_label(Some("  Laptop key  ".to_owned())).unwrap(),
        "Laptop key"
    );
    assert_eq!(
        normalize_passkey_label(Some("   ".to_owned())).unwrap(),
        "Passkey"
    );

    let response = normalize_passkey_label(Some("x".repeat(121))).unwrap_err();
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
fn credential_id_from_response_accepts_only_base64url_credential_ids() {
    let credential = credential_id_from_response("AQIDBA").unwrap();
    assert_eq!(credential, CredentialId(vec![1, 2, 3, 4]));

    let response = credential_id_from_response("not+base64/standard").unwrap_err();
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
fn passkey_row_parsing_and_public_json_do_not_expose_private_row_context() {
    let now = Utc::now();
    let credential = PasskeyCredential {
        id: CredentialId(vec![1, 2, 3, 4]),
        public_key_cose: CosePublicKey(vec![5, 6, 7]),
        counter: 9,
        transports: vec!["internal".to_owned(), "hybrid".to_owned()],
        aaguid: [7; 16],
    };
    let row = DatabasePasskeyFixture {
        id: Uuid::now_v7(),
        tenant_id: Uuid::now_v7(),
        user_id: Uuid::now_v7(),
        credential_id: passkey_credential_id(&credential),
        credential: serde_json::to_value(&credential).unwrap(),
        label: "Laptop".to_owned(),
        sign_count: 9,
        last_used_at: Some(now),
        created_at: now,
        updated_at: now,
    };

    let row = row.credential();
    let parsed = passkey_credential_from_row(&row).unwrap();
    assert_eq!(parsed.id, credential.id);
    assert_eq!(
        passkey_credential_ids(std::slice::from_ref(&row)).unwrap(),
        vec![credential.id]
    );

    let public = passkey_public_json(&row);
    assert_eq!(public["id"], json!(row.id));
    assert_eq!(public["label"], "Laptop");
    assert_eq!(public["credential_id"], row.credential_id);
    assert_eq!(public["sign_count"], 9);
    assert!(public.get("tenant_id").is_none());
    assert!(public.get("user_id").is_none());
    assert!(public.get("credential").is_none());
}

#[test]
fn malformed_passkey_credential_rows_fail_closed() {
    let now = Utc::now();
    let row = DatabasePasskeyFixture {
        id: Uuid::now_v7(),
        tenant_id: Uuid::now_v7(),
        user_id: Uuid::now_v7(),
        credential_id: "not-a-real-credential".to_owned(),
        credential: json!({"id": "not enough fields"}),
        label: "Broken".to_owned(),
        sign_count: 0,
        last_used_at: None,
        created_at: now,
        updated_at: now,
    };

    assert!(
        passkey_credential_from_row(&row.credential()).is_err(),
        "malformed stored passkey credential JSON must not be accepted"
    );
    assert!(
        passkey_credential_ids(&[row.credential()]).is_err(),
        "credential-id extraction must fail when any stored credential is malformed"
    );
}
