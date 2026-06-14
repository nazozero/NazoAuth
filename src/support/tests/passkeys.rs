use super::*;
use passkey_auth::{CosePublicKey, CredentialId, PasskeyCredential};

#[test]
fn passkey_user_handle_binds_tenant_and_user() {
    let user = UserRow {
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
    };

    let handle = passkey_user_handle(&user);
    assert_eq!(handle.len(), 32);
    assert!(handle.starts_with(user.tenant_id.as_bytes()));
    assert!(handle.ends_with(user.id.as_bytes()));
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
