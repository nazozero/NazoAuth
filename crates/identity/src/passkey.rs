use std::{error::Error, fmt};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::{TenantId, UserId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PasskeyPolicyError {
    LabelTooLong,
    InvalidCeremonyId,
    InvalidCredentialId,
}

impl fmt::Display for PasskeyPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::LabelTooLong => "passkey label is too long",
            Self::InvalidCeremonyId => "invalid ceremony ID",
            Self::InvalidCredentialId => "invalid passkey credential ID",
        })
    }
}

impl Error for PasskeyPolicyError {}

#[must_use]
pub fn passkey_user_handle(tenant_id: TenantId, user_id: UserId) -> Vec<u8> {
    let mut handle = Vec::with_capacity(32);
    handle.extend_from_slice(tenant_id.as_uuid().as_bytes());
    handle.extend_from_slice(user_id.as_uuid().as_bytes());
    handle
}

pub fn normalize_passkey_label(value: Option<&str>) -> Result<String, PasskeyPolicyError> {
    let label = value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("Passkey");
    if label.len() > 120 {
        return Err(PasskeyPolicyError::LabelTooLong);
    }
    Ok(label.to_owned())
}

pub fn normalize_ceremony_id(value: &str) -> Result<String, PasskeyPolicyError> {
    let value = value.trim();
    if value.len() < 32
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(PasskeyPolicyError::InvalidCeremonyId);
    }
    Ok(value.to_owned())
}

pub fn credential_id_from_response(id: &str) -> Result<Vec<u8>, PasskeyPolicyError> {
    URL_SAFE_NO_PAD
        .decode(id)
        .map_err(|_| PasskeyPolicyError::InvalidCredentialId)
}
