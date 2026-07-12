use crate::rows::identity::{ExternalIdentityLinkRow, PasskeyCredentialRow, UserRow};
use nazo_identity::{
    IdentityModelError, IdentityUser, LoginIdentity, OrganizationId, PasswordHash, PostalAddress,
    Principal, RealmId, SubjectClaims, TenantContext, TenantId, UserId, UserProfile, UserRole,
};

#[derive(Debug)]
pub(crate) struct ConversionError(pub(crate) String);
impl From<IdentityModelError> for ConversionError {
    fn from(error: IdentityModelError) -> Self {
        Self(error.to_string())
    }
}
fn tenant(row: &UserRow) -> Result<TenantContext, ConversionError> {
    Ok(TenantContext {
        tenant_id: TenantId::new(row.tenant_id)?,
        realm_id: RealmId::new(row.realm_id)?,
        organization_id: OrganizationId::new(row.organization_id)?,
    })
}

impl TryFrom<UserRow> for Principal {
    type Error = ConversionError;
    fn try_from(row: UserRow) -> Result<Self, Self::Error> {
        principal(&row)
    }
}

fn principal(row: &UserRow) -> Result<Principal, ConversionError> {
    let role = match (row.role.as_str(), row.admin_level) {
        ("user", 0) => UserRole::User,
        ("admin", level) if level > 0 => UserRole::Admin {
            level: u32::try_from(level).map_err(|error| ConversionError(error.to_string()))?,
        },
        _ => {
            return Err(ConversionError(
                "invalid persisted role/admin_level combination".into(),
            ));
        }
    };
    Ok(Principal {
        user_id: UserId::new(row.id)?,
        tenant: tenant(row)?,
        role,
        active: row.is_active,
    })
}

impl TryFrom<UserRow> for IdentityUser {
    type Error = ConversionError;

    fn try_from(row: UserRow) -> Result<Self, Self::Error> {
        let principal = principal(&row)?;
        Ok(Self {
            principal,
            login: LoginIdentity {
                username: row.username,
                email: row.email,
                password_hash: PasswordHash::new(row.password_hash)?,
                email_verified: row.email_verified,
                mfa_enabled: row.mfa_enabled,
            },
            profile: UserProfile {
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
                address: PostalAddress {
                    formatted: row.address_formatted,
                    street_address: row.address_street_address,
                    locality: row.address_locality,
                    region: row.address_region,
                    postal_code: row.address_postal_code,
                    country: row.address_country,
                },
                phone_number: row.phone_number,
                phone_number_verified: row.phone_number_verified,
            },
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

pub(crate) fn subject_claims(row: UserRow) -> Result<SubjectClaims, ConversionError> {
    let principal = principal(&row)?;
    let address = PostalAddress {
        formatted: row.address_formatted,
        street_address: row.address_street_address,
        locality: row.address_locality,
        region: row.address_region,
        postal_code: row.address_postal_code,
        country: row.address_country,
    };
    Ok(SubjectClaims {
        subject: principal.user_id,
        preferred_username: row.username,
        name: row.display_name,
        given_name: row.given_name,
        family_name: row.family_name,
        middle_name: row.middle_name,
        nickname: row.nickname,
        profile: row.profile_url,
        picture: row.avatar_url,
        website: row.website_url,
        gender: row.gender,
        birthdate: row.birthdate,
        zoneinfo: row.zoneinfo,
        locale: row.locale,
        email: row.email,
        email_verified: row.email_verified,
        address: (address != PostalAddress::default()).then_some(address),
        phone_number: row.phone_number,
        phone_number_verified: row.phone_number_verified,
        updated_at: row.updated_at.timestamp(),
    })
}

pub(crate) fn passkey(
    row: PasskeyCredentialRow,
) -> Result<nazo_identity::ports::PasskeyCredential, ConversionError> {
    Ok(nazo_identity::ports::PasskeyCredential {
        id: row.id,
        tenant_id: TenantId::new(row.tenant_id)?,
        user_id: UserId::new(row.user_id)?,
        credential_id: row.credential_id,
        credential: row.credential,
        label: row.label,
        sign_count: row.sign_count,
        last_used_at: row.last_used_at,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}
pub(crate) fn federation_link(
    row: ExternalIdentityLinkRow,
) -> Result<nazo_identity::ports::FederationLink, ConversionError> {
    Ok(nazo_identity::ports::FederationLink {
        id: row.id,
        tenant_id: TenantId::new(row.tenant_id)?,
        user_id: UserId::new(row.user_id)?,
        provider_type: row.provider_type,
        provider_id: row.provider_id,
        subject: row.subject,
        email: row.email,
        claims: row.claims,
        created_at: row.created_at,
        updated_at: row.updated_at,
        last_login_at: row.last_login_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn user_row() -> UserRow {
        UserRow {
            id: Uuid::now_v7(),
            tenant_id: Uuid::now_v7(),
            realm_id: Uuid::now_v7(),
            organization_id: Uuid::now_v7(),
            username: "user".into(),
            email: "user@example.test".into(),
            password_hash: "hash".into(),
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

    #[test]
    fn subject_claims_uses_full_persisted_user_invariant() {
        let mut invalid_role = user_row();
        invalid_role.role = "admin".into();
        assert!(subject_claims(invalid_role).is_err());

        let mut nil_user = user_row();
        nil_user.id = Uuid::nil();
        assert!(subject_claims(nil_user).is_err());

        let mut nil_tenant = user_row();
        nil_tenant.tenant_id = Uuid::nil();
        assert!(subject_claims(nil_tenant).is_err());
    }

    #[test]
    fn persisted_blank_password_hash_is_rejected() {
        let mut row = user_row();
        row.password_hash = "   ".to_owned();

        let error = IdentityUser::try_from(row).unwrap_err();

        assert_eq!(error.0, "password hash must not be blank");
    }
}
