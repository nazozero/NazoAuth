use super::*;
use chrono::Utc;
use uuid::Uuid;

fn user_row() -> PublicAccountRow {
    PublicAccountRow {
        id: Uuid::now_v7(),
        tenant_id: Uuid::now_v7(),
        realm_id: Uuid::now_v7(),
        organization_id: Uuid::now_v7(),
        username: "user".into(),
        email: "user@example.test".into(),
        is_active: true,
        mfa_enabled: false,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        email_verified: true,
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
        role: "user".into(),
        admin_level: 0,
        address_formatted: None,
        address_street_address: None,
        address_locality: None,
        address_region: None,
        address_postal_code: None,
        address_country: None,
        phone_number: None,
        phone_number_verified: false,
    }
}

fn authentication_row(row: PublicAccountRow) -> AuthenticationIdentityRow {
    AuthenticationIdentityRow {
        id: row.id,
        tenant_id: row.tenant_id,
        realm_id: row.realm_id,
        organization_id: row.organization_id,
        username: row.username,
        email: row.email,
        password_hash: "hash".into(),
        is_active: row.is_active,
        mfa_enabled: row.mfa_enabled,
        email_verified: row.email_verified,
        role: row.role,
        admin_level: row.admin_level,
    }
}

fn subject_claims_row(row: PublicAccountRow) -> SubjectClaimsRow {
    SubjectClaimsRow {
        id: row.id,
        tenant_id: row.tenant_id,
        realm_id: row.realm_id,
        organization_id: row.organization_id,
        username: row.username,
        email: row.email,
        is_active: row.is_active,
        updated_at: row.updated_at,
        email_verified: row.email_verified,
        display_name: row.display_name,
        avatar_url: row.avatar_url,
        given_name: row.given_name,
        family_name: row.family_name,
        middle_name: row.middle_name,
        nickname: row.nickname,
        profile_url: row.profile_url,
        website_url: row.website_url,
        gender: row.gender,
        birthdate: row.birthdate,
        zoneinfo: row.zoneinfo,
        locale: row.locale,
        role: row.role,
        admin_level: row.admin_level,
        address_formatted: row.address_formatted,
        address_street_address: row.address_street_address,
        address_locality: row.address_locality,
        address_region: row.address_region,
        address_postal_code: row.address_postal_code,
        address_country: row.address_country,
        phone_number: row.phone_number,
        phone_number_verified: row.phone_number_verified,
    }
}

#[test]
fn subject_claims_uses_full_persisted_user_invariant() {
    let mut invalid_role = user_row();
    invalid_role.role = "admin".into();
    assert!(active_subject_claims(subject_claims_row(invalid_role)).is_err());

    let mut nil_user = user_row();
    nil_user.id = Uuid::nil();
    assert!(active_subject_claims(subject_claims_row(nil_user)).is_err());

    let mut nil_tenant = user_row();
    nil_tenant.tenant_id = Uuid::nil();
    assert!(active_subject_claims(subject_claims_row(nil_tenant)).is_err());
}

#[test]
fn persisted_blank_password_hash_is_rejected() {
    let mut row = authentication_row(user_row());
    row.password_hash = "   ".to_owned();

    let error = authentication_identity(row).unwrap_err();

    assert_eq!(error.0, "password hash must not be blank");
}

#[test]
fn display_summaries_reject_corrupt_tenant_and_user_identifiers() {
    let now = Utc::now();
    for corrupt_tenant in [true, false] {
        let tenant_id = if corrupt_tenant {
            Uuid::nil()
        } else {
            Uuid::now_v7()
        };
        let user_id = if corrupt_tenant {
            Uuid::now_v7()
        } else {
            Uuid::nil()
        };
        let passkey = PasskeyCredentialSummaryRow {
            id: Uuid::now_v7(),
            tenant_id,
            user_id,
            credential_id: "credential".into(),
            label: "Laptop".into(),
            sign_count: 3,
            last_used_at: Some(now),
            created_at: now,
            updated_at: now,
        };
        assert!(passkey_summary(passkey).is_err());
        let link = ExternalIdentityLinkSummaryRow {
            id: Uuid::now_v7(),
            tenant_id,
            user_id,
            provider_type: "oidc".into(),
            provider_id: "provider".into(),
            subject: "subject".into(),
            email: "user@example.test".into(),
            created_at: now,
            updated_at: now,
            last_login_at: Some(now),
        };
        assert!(federation_link_summary(link).is_err());
    }
}

fn passkey_row() -> PasskeyCredentialRow {
    PasskeyCredentialRow {
        id: Uuid::now_v7(),
        tenant_id: Uuid::now_v7(),
        user_id: Uuid::now_v7(),
        credential_id: "AQID".into(),
        label: "Laptop".into(),
        sign_count: 12,
        credential: serde_json::json!({"id": [1,2,3], "counter": 12,
          "public_key_cose": [164,1,1,3,39,32,6,33], "transports": ["internal"], "aaguid": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}),
        last_used_at: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[test]
fn passkey_adapter_rejects_conflicting_credential_authorities() {
    assert!(passkey(passkey_row()).is_ok());
    let mut row = passkey_row();
    row.sign_count = 13;
    assert!(
        passkey(row).is_err(),
        "legacy JSON counter must agree with CAS column"
    );
    let mut row = passkey_row();
    row.credential_id = "BAUG".into();
    assert!(
        passkey(row).is_err(),
        "legacy JSON ID must agree with lookup column"
    );
}

#[test]
fn compact_passkey_material_has_one_id_and_counter_authority() {
    let original = passkey(passkey_row()).unwrap();
    let compact = encoded_passkey(&original.credential).unwrap();
    assert!(compact.get("id").is_none());
    assert!(compact.get("counter").is_none());
    let decoded = passkey_material("AQID", 12, compact.clone()).unwrap();
    assert_eq!(
        serde_json::to_value(decoded).unwrap(),
        serde_json::to_value(original.credential).unwrap()
    );
    assert!(passkey_material("AQID", -1, compact.clone()).is_err());
    assert!(passkey_material("AQID", i64::from(u32::MAX) + 1, compact).is_err());
}
