use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CredentialIdentifier(pub String);

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Proofs(pub BTreeMap<String, Vec<Value>>);

impl Proofs {
    #[must_use]
    pub fn count(&self) -> usize {
        self.0.values().map(Vec::len).sum()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialResponseEncryption {
    pub jwk: Value,
    pub enc: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zip: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CredentialRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_identifier: Option<CredentialIdentifier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_configuration_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proofs: Option<Proofs>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_response_encryption: Option<CredentialResponseEncryption>,
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl CredentialRequest {
    pub fn validate_identifier(&self) -> Result<(), CredentialError> {
        match (
            self.credential_identifier.as_ref(),
            self.credential_configuration_id.as_ref(),
        ) {
            (Some(_), None) | (None, Some(_)) => Ok(()),
            _ => Err(CredentialError::InvalidCredentialRequest),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeferredCredentialRequest {
    pub transaction_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_response_encryption: Option<CredentialResponseEncryption>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationEvent {
    CredentialAccepted,
    CredentialFailure,
    CredentialDeleted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationRequest {
    pub notification_id: String,
    pub event: NotificationEvent,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_description: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuedCredential {
    pub credential: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<Vec<IssuedCredential>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notification_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,
}

impl CredentialResponse {
    pub fn validate(&self) -> Result<(), CredentialError> {
        match (&self.credentials, &self.transaction_id) {
            (Some(credentials), None) if !credentials.is_empty() => Ok(()),
            (None, Some(transaction_id)) if !transaction_id.is_empty() => Ok(()),
            _ => Err(CredentialError::InvalidCredentialRequest),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CredentialError {
    #[error("invalid credential request")]
    InvalidCredentialRequest,
    #[error("unknown credential configuration")]
    UnknownCredentialConfiguration,
    #[error("unknown credential identifier")]
    UnknownCredentialIdentifier,
    #[error("invalid proof")]
    InvalidProof,
    #[error("invalid nonce")]
    InvalidNonce,
    #[error("invalid encryption parameters")]
    InvalidEncryptionParameters,
    #[error("invalid transaction identifier")]
    InvalidTransactionId,
}
