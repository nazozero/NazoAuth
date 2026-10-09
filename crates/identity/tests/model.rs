use nazo_identity::{
    IdentityModelError, OrganizationId, PostalAddress, Principal, RealmId, SubjectClaims,
    TenantContext, TenantId, UserId, UserRole,
};
use uuid::Uuid;

fn id(value: u128) -> Uuid {
    Uuid::from_u128(value)
}

#[test]
fn identity_ids_reject_nil_uuid_values() {
    assert_eq!(UserId::new(Uuid::nil()), Err(IdentityModelError::EmptyId));
    assert_eq!(TenantId::new(Uuid::nil()), Err(IdentityModelError::EmptyId));
    assert_eq!(RealmId::new(Uuid::nil()), Err(IdentityModelError::EmptyId));
    assert_eq!(
        OrganizationId::new(Uuid::nil()),
        Err(IdentityModelError::EmptyId)
    );
}

#[test]
fn identity_ids_reject_nil_uuid_during_deserialization() {
    let encoded = format!("\"{}\"", Uuid::nil());

    assert!(serde_json::from_str::<UserId>(&encoded).is_err());
    assert!(serde_json::from_str::<TenantId>(&encoded).is_err());
    assert!(serde_json::from_str::<RealmId>(&encoded).is_err());
    assert!(serde_json::from_str::<OrganizationId>(&encoded).is_err());
}

#[test]
fn principal_and_tenant_context_do_not_require_database_rows() {
    let principal = Principal {
        user_id: UserId::new(id(4)).unwrap(),
        tenant: TenantContext::default_system(),
        role: UserRole::Admin { level: 2 },
        active: true,
    };

    assert_eq!(principal.admin_level(), Some(2));
    assert!(principal.tenant.matches_raw(id(1), id(2), id(3)));
    assert!(!principal.tenant.matches_raw(id(9), id(2), id(3)));
}

#[test]
fn session_metadata_has_one_amr_source_and_rejects_invalid_time_or_sid() {
    use nazo_identity::session::{SessionRecord, valid_authentication_metadata};
    let mut session = SessionRecord::new(
        UserId::new(id(4)).unwrap(),
        1_000,
        vec!["password".to_owned()],
        false,
        Some("sid-1".to_owned()),
    );
    session.add_amr("otp");
    session.add_amr("mfa");
    session.add_amr("otp");
    assert_eq!(session.amr(), ["password", "otp", "mfa"]);
    assert!(valid_authentication_metadata(
        session.auth_time(),
        session.amr(),
        session.oidc_sid(),
        1_001
    ));
    assert!(!valid_authentication_metadata(
        0,
        session.amr(),
        session.oidc_sid(),
        1_001
    ));
    assert!(!valid_authentication_metadata(
        1_032,
        session.amr(),
        session.oidc_sid(),
        1_001
    ));
    assert!(!valid_authentication_metadata(
        1_000,
        &[],
        session.oidc_sid(),
        1_001
    ));
    assert!(!valid_authentication_metadata(
        1_000,
        session.amr(),
        Some(" "),
        1_001
    ));
}

#[test]
fn subject_claims_are_framework_and_storage_independent() {
    let claims = SubjectClaims {
        subject: UserId::new(id(4)).unwrap(),
        preferred_username: "alice".to_owned(),
        name: Some("Alice Example".to_owned()),
        given_name: Some("Alice".to_owned()),
        family_name: Some("Example".to_owned()),
        middle_name: None,
        nickname: None,
        profile: None,
        picture: None,
        website: None,
        gender: None,
        birthdate: None,
        zoneinfo: None,
        locale: Some("zh-CN".to_owned()),
        email: "alice@example.com".to_owned(),
        email_verified: true,
        address: Some(PostalAddress {
            formatted: None,
            street_address: None,
            locality: Some("Shanghai".to_owned()),
            region: None,
            postal_code: None,
            country: Some("CN".to_owned()),
        }),
        phone_number: None,
        phone_number_verified: false,
        updated_at: 1_700_000_000,
    };

    assert_eq!(claims.subject.as_uuid(), id(4));
    assert_eq!(claims.address.unwrap().country.as_deref(), Some("CN"));
}
