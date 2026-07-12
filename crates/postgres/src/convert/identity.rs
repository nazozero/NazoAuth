use crate::rows::identity::{ExternalIdentityLinkRow, PasskeyCredentialRow, UserRow};
use nazo_identity::{
    IdentityModelError, IdentityUser, LoginIdentity, OrganizationId, PostalAddress, Principal,
    RealmId, SubjectClaims, TenantContext, TenantId, UserId, UserProfile, UserRole,
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
                password_hash: row.password_hash,
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
    let _ = tenant(&row)?;
    let address = PostalAddress {
        formatted: row.address_formatted,
        street_address: row.address_street_address,
        locality: row.address_locality,
        region: row.address_region,
        postal_code: row.address_postal_code,
        country: row.address_country,
    };
    Ok(SubjectClaims {
        subject: UserId::new(row.id)?,
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
