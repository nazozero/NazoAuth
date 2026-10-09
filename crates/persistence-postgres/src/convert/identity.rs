use crate::rows::identity::{
    AuthenticationIdentityRow, ExternalIdentityLinkRow, ExternalIdentityLinkSummaryRow,
    PasskeyCredentialRow, PasskeyCredentialSummaryRow, PrincipalRow, PublicAccountRow,
    SubjectClaimsRow,
};
use nazo_identity::{
    AccountIdentity, AuthenticationIdentity, IdentityModelError, LoginIdentity, OrganizationId,
    PasswordHash, PostalAddress, Principal, PublicAccount, RealmId, SubjectClaims, TenantContext,
    TenantId, UserId, UserProfile, UserRole,
};

#[derive(Debug)]
pub(crate) struct ConversionError(pub(crate) String);
impl From<IdentityModelError> for ConversionError {
    fn from(error: IdentityModelError) -> Self {
        Self(error.to_string())
    }
}
fn principal_parts(
    id: uuid::Uuid,
    tenant_id: uuid::Uuid,
    realm_id: uuid::Uuid,
    organization_id: uuid::Uuid,
    role: &str,
    admin_level: i32,
    active: bool,
) -> Result<Principal, ConversionError> {
    let role = match (role, admin_level) {
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
        user_id: UserId::new(id)?,
        tenant: TenantContext {
            tenant_id: TenantId::new(tenant_id)?,
            realm_id: RealmId::new(realm_id)?,
            organization_id: OrganizationId::new(organization_id)?,
        },
        role,
        active,
    })
}

pub(crate) fn principal_row(row: PrincipalRow) -> Result<Principal, ConversionError> {
    principal_parts(
        row.id,
        row.tenant_id,
        row.realm_id,
        row.organization_id,
        &row.role,
        row.admin_level,
        row.is_active,
    )
}

pub(crate) fn authentication_identity(
    row: AuthenticationIdentityRow,
) -> Result<AuthenticationIdentity, ConversionError> {
    let principal = principal_parts(
        row.id,
        row.tenant_id,
        row.realm_id,
        row.organization_id,
        &row.role,
        row.admin_level,
        row.is_active,
    )?;
    Ok(AuthenticationIdentity {
        principal,
        login: LoginIdentity {
            account: AccountIdentity {
                username: row.username,
                email: row.email,
                email_verified: row.email_verified,
                mfa_enabled: row.mfa_enabled,
            },
            password_hash: PasswordHash::new(row.password_hash)?,
        },
    })
}

impl TryFrom<PublicAccountRow> for PublicAccount {
    type Error = ConversionError;

    fn try_from(row: PublicAccountRow) -> Result<Self, Self::Error> {
        let principal = principal_parts(
            row.id,
            row.tenant_id,
            row.realm_id,
            row.organization_id,
            &row.role,
            row.admin_level,
            row.is_active,
        )?;
        Ok(Self {
            principal,
            account: AccountIdentity {
                username: row.username,
                email: row.email,
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

pub(crate) fn active_subject_claims(
    row: SubjectClaimsRow,
) -> Result<SubjectClaims, ConversionError> {
    let principal = principal_parts(
        row.id,
        row.tenant_id,
        row.realm_id,
        row.organization_id,
        &row.role,
        row.admin_level,
        row.is_active,
    )?;
    if !principal.active {
        return Err(ConversionError(
            "inactive account returned from active claims query".to_owned(),
        ));
    }
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
        credential: passkey_material(&row.credential_id, row.sign_count, row.credential)?,
        label: row.label,
        last_used_at: row.last_used_at,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

pub(crate) fn passkey_summary(
    row: PasskeyCredentialSummaryRow,
) -> Result<nazo_identity::ports::PasskeyCredentialSummary, ConversionError> {
    Ok(nazo_identity::ports::PasskeyCredentialSummary {
        id: row.id,
        tenant_id: TenantId::new(row.tenant_id)?,
        user_id: UserId::new(row.user_id)?,
        credential_id: row.credential_id,
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

pub(crate) fn federation_link_summary(
    row: ExternalIdentityLinkSummaryRow,
) -> Result<nazo_identity::ports::FederationLinkSummary, ConversionError> {
    Ok(nazo_identity::ports::FederationLinkSummary {
        id: row.id,
        tenant_id: TenantId::new(row.tenant_id)?,
        user_id: UserId::new(row.user_id)?,
        provider_type: row.provider_type,
        provider_id: row.provider_id,
        subject: row.subject,
        email: row.email,
        created_at: row.created_at,
        updated_at: row.updated_at,
        last_login_at: row.last_login_at,
    })
}

#[cfg(test)]
#[path = "../../tests/unit/convert/identity.rs"]
mod tests;

/// Relational lookup/CAS columns are the stored authority. Legacy JSON copies
/// must agree before decoding; new JSON contains only authenticator material.
fn passkey_material(
    credential_id: &str,
    sign_count: i64,
    mut value: serde_json::Value,
) -> Result<passkey_auth::PasskeyCredential, ConversionError> {
    let invalid = || ConversionError("stored passkey credential is malformed".into());
    let id = passkey_auth::CredentialId::from_b64url(credential_id).map_err(|_| invalid())?;
    let counter = u32::try_from(sign_count).map_err(|_| invalid())?;
    let object = value.as_object_mut().ok_or_else(invalid)?;
    let id_value = serde_json::to_value(&id).map_err(|_| invalid())?;
    let counter_value = serde_json::json!(counter);
    if object.get("id").is_some_and(|stored| stored != &id_value)
        || object
            .get("counter")
            .is_some_and(|stored| stored != &counter_value)
    {
        return Err(ConversionError(
            "passkey credential columns disagree".into(),
        ));
    }
    object.insert("id".into(), id_value);
    object.insert("counter".into(), counter_value);
    serde_json::from_value(value).map_err(|_| invalid())
}

pub(crate) fn encoded_passkey(
    credential: &passkey_auth::PasskeyCredential,
) -> Result<serde_json::Value, ConversionError> {
    let mut value = serde_json::to_value(credential)
        .map_err(|_| ConversionError("passkey credential serialization failed".into()))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| ConversionError("passkey credential serialization failed".into()))?;
    object.remove("id");
    object.remove("counter");
    Ok(value)
}

#[cfg(test)]
#[path = "../../tests/unit/convert/passkey_material.rs"]
mod passkey_tests;
