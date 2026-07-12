use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};

use crate::{TenantContext, UserId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityModelError {
    EmptyId,
    InvalidAuthenticationTime,
    FutureAuthenticationTime,
    EmptyAuthenticationMethods,
    EmptyOidcSid,
}

impl fmt::Display for IdentityModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyId => "identity ID must not be nil",
            Self::InvalidAuthenticationTime => "authentication time must be positive",
            Self::FutureAuthenticationTime => "authentication time exceeds allowed clock skew",
            Self::EmptyAuthenticationMethods => "authentication methods must not be empty",
            Self::EmptyOidcSid => "OIDC session ID must not be blank",
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AuthMethod {
    Password,
    Passkey,
    Totp,
    BackupCode,
    RememberedMfa,
    Federated(String),
}

impl AuthMethod {
    fn append_amr(&self, values: &mut Vec<String>) {
        match self {
            Self::Password => push_unique(values, "password"),
            Self::Passkey => push_unique(values, "passkey"),
            Self::Totp => push_unique(values, "otp"),
            Self::BackupCode => push_unique(values, "recovery_code"),
            Self::RememberedMfa => {
                push_unique(values, "remembered_mfa");
                push_unique(values, "mfa");
            }
            Self::Federated(provider) => {
                push_unique(values, provider);
                push_unique(values, "federated");
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuthenticationContext {
    pub auth_time: i64,
    pub methods: Vec<AuthMethod>,
    pub oidc_sid: String,
    amr: Vec<String>,
}

impl AuthenticationContext {
    pub fn new(
        auth_time: i64,
        methods: impl IntoIterator<Item = AuthMethod>,
    ) -> Result<Self, IdentityModelError> {
        let methods = deduplicate_methods(methods);
        if auth_time <= 0 {
            return Err(IdentityModelError::InvalidAuthenticationTime);
        }
        if methods.is_empty() {
            return Err(IdentityModelError::EmptyAuthenticationMethods);
        }
        let mut amr = Vec::new();
        for method in &methods {
            method.append_amr(&mut amr);
        }
        Ok(Self {
            auth_time,
            methods,
            oidc_sid: uuid::Uuid::now_v7().to_string(),
            amr,
        })
    }

    pub fn from_amr<'a>(
        auth_time: i64,
        amr: impl IntoIterator<Item = &'a str>,
        oidc_sid: &str,
        now: i64,
    ) -> Result<Self, IdentityModelError> {
        if auth_time <= 0 {
            return Err(IdentityModelError::InvalidAuthenticationTime);
        }
        if auth_time > now.saturating_add(30) {
            return Err(IdentityModelError::FutureAuthenticationTime);
        }
        let mut normalized_amr = Vec::new();
        for value in amr {
            push_unique(&mut normalized_amr, value);
        }
        if normalized_amr.is_empty() {
            return Err(IdentityModelError::EmptyAuthenticationMethods);
        }
        let oidc_sid = oidc_sid.trim();
        if oidc_sid.is_empty() {
            return Err(IdentityModelError::EmptyOidcSid);
        }
        let methods = normalized_amr
            .iter()
            .map(|value| method_from_amr(value))
            .collect();
        Ok(Self {
            auth_time,
            methods,
            oidc_sid: oidc_sid.to_owned(),
            amr: normalized_amr,
        })
    }

    #[must_use]
    pub fn has_mfa(&self) -> bool {
        self.amr.iter().any(|value| {
            matches!(
                value.as_str(),
                "mfa" | "otp" | "recovery_code" | "remembered_mfa"
            )
        })
    }

    #[must_use]
    pub fn amr(&self) -> &[String] {
        &self.amr
    }
}

fn deduplicate_methods(methods: impl IntoIterator<Item = AuthMethod>) -> Vec<AuthMethod> {
    let mut result = Vec::new();
    for method in methods {
        if !result.contains(&method) {
            result.push(method);
        }
    }
    result
}

fn push_unique(values: &mut Vec<String>, value: &str) {
    if !value.trim().is_empty() && !values.iter().any(|existing| existing == value) {
        values.push(value.to_owned());
    }
}

fn method_from_amr(value: &str) -> AuthMethod {
    match value {
        "password" | "pwd" => AuthMethod::Password,
        "passkey" => AuthMethod::Passkey,
        "otp" => AuthMethod::Totp,
        "recovery_code" => AuthMethod::BackupCode,
        "remembered_mfa" => AuthMethod::RememberedMfa,
        other => AuthMethod::Federated(other.to_owned()),
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
