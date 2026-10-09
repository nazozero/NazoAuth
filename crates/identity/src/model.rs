use std::{error::Error, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{TenantContext, UserId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityModelError {
    EmptyId,
    EmptyPasswordHash,
}

impl fmt::Display for IdentityModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyId => "identity ID must not be nil",
            Self::EmptyPasswordHash => "password hash must not be blank",
        })
    }
}

impl Error for IdentityModelError {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum UserRole {
    User,
    Admin { level: u32 },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Principal {
    pub user_id: UserId,
    pub tenant: TenantContext,
    pub role: UserRole,
    pub active: bool,
}

impl Principal {
    #[must_use]
    pub const fn admin_level(&self) -> Option<u32> {
        match self.role {
            UserRole::User => None,
            UserRole::Admin { level } => Some(level),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PostalAddress {
    pub formatted: Option<String>,
    pub street_address: Option<String>,
    pub locality: Option<String>,
    pub region: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubjectClaims {
    pub subject: UserId,
    pub preferred_username: String,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub middle_name: Option<String>,
    pub nickname: Option<String>,
    pub profile: Option<String>,
    pub picture: Option<String>,
    pub website: Option<String>,
    pub gender: Option<String>,
    pub birthdate: Option<String>,
    pub zoneinfo: Option<String>,
    pub locale: Option<String>,
    pub email: String,
    pub email_verified: bool,
    pub address: Option<PostalAddress>,
    pub phone_number: Option<String>,
    pub phone_number_verified: bool,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountIdentity {
    pub username: String,
    pub email: String,
    pub email_verified: bool,
    pub mfa_enabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoginIdentity {
    pub account: AccountIdentity,
    pub password_hash: PasswordHash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationIdentity {
    pub principal: Principal,
    pub login: LoginIdentity,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UserProfile {
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub middle_name: Option<String>,
    pub nickname: Option<String>,
    pub profile_url: Option<String>,
    pub website_url: Option<String>,
    pub gender: Option<String>,
    pub birthdate: Option<String>,
    pub zoneinfo: Option<String>,
    pub locale: Option<String>,
    pub address: PostalAddress,
    pub phone_number: Option<String>,
    pub phone_number_verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicAccount {
    pub principal: Principal,
    pub account: AccountIdentity,
    pub profile: UserProfile,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A password verifier owned by the identity domain.
///
/// The inner verifier is deliberately unavailable to serializers and callers.
/// Candidate verification is completed inside this type and returns only a
/// boolean result.
///
/// ```compile_fail
/// fn assert_serialize<T: serde::Serialize>() {}
/// assert_serialize::<nazo_identity::PasswordHash>();
/// ```
///
/// ```compile_fail
/// fn assert_deserialize<T: serde::de::DeserializeOwned>() {}
/// assert_deserialize::<nazo_identity::PasswordHash>();
/// ```
///
/// Authentication-facing callers cannot extract the persisted verifier.
///
/// ```compile_fail
/// let hash = nazo_identity::PasswordHash::new("$argon2id$test").unwrap();
/// let _: String = hash.into_inner();
/// ```
///
/// ```compile_fail
/// let hash = nazo_identity::PasswordHash::new("$argon2id$test").unwrap();
/// let _: &str = hash.expose_for_verification();
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct PasswordHash(String);

impl PasswordHash {
    pub fn new(value: impl Into<String>) -> Result<Self, IdentityModelError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(IdentityModelError::EmptyPasswordHash);
        }
        Ok(Self(value))
    }

    /// Verifies a password candidate without releasing the persisted verifier.
    #[must_use]
    pub fn verify_password(&self, candidate: &str) -> bool {
        nazo_crypto::password::verify_argon2_phc(&self.0, candidate.as_bytes())
    }
}

impl fmt::Debug for PasswordHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PasswordHash([REDACTED])")
    }
}

impl PublicAccount {
    #[must_use]
    pub const fn id(&self) -> uuid::Uuid {
        self.principal.user_id.as_uuid()
    }
    #[must_use]
    pub const fn user_id(&self) -> UserId {
        self.principal.user_id
    }
    #[must_use]
    pub const fn tenant(&self) -> TenantContext {
        self.principal.tenant
    }
    #[must_use]
    pub const fn tenant_id(&self) -> uuid::Uuid {
        self.principal.tenant.tenant_id.as_uuid()
    }
    #[must_use]
    pub const fn realm_id(&self) -> uuid::Uuid {
        self.principal.tenant.realm_id.as_uuid()
    }
    #[must_use]
    pub const fn organization_id(&self) -> uuid::Uuid {
        self.principal.tenant.organization_id.as_uuid()
    }
    #[must_use]
    pub fn display_name(&self) -> &str {
        self.profile
            .display_name
            .as_deref()
            .unwrap_or(&self.account.username)
    }
    #[must_use]
    pub const fn role_name(&self) -> &'static str {
        match self.principal.role {
            UserRole::User => "user",
            UserRole::Admin { .. } => "admin",
        }
    }
    #[must_use]
    pub const fn admin_level(&self) -> u32 {
        match self.principal.role {
            UserRole::User => 0,
            UserRole::Admin { level } => level,
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/model.rs"]
mod tests;
