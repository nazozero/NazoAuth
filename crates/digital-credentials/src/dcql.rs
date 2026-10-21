use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::CredentialFormat;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ClaimPathSegment {
    Name(String),
    Index(u64),
    Wildcard(Option<()>),
}

pub type ClaimPath = Vec<ClaimPathSegment>;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ClaimsQuery {
    pub path: ClaimPath,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent_to_retain: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TrustedAuthority {
    #[serde(rename = "type")]
    pub authority_type: String,
    pub values: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CredentialQuery {
    pub id: String,
    pub format: CredentialFormat,
    #[serde(default, skip_serializing_if = "is_false")]
    pub multiple: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<ClaimsQuery>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_sets: Option<Vec<Vec<String>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_authorities: Option<Vec<TrustedAuthority>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_cryptographic_holder_binding: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CredentialSetOption {
    pub options: Vec<Vec<String>>,
    #[serde(default = "required_by_default")]
    pub required: bool,
}

const fn is_false(value: &bool) -> bool {
    !*value
}

const fn required_by_default() -> bool {
    true
}

pub type CredentialSetQuery = CredentialSetOption;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DcqlQuery {
    pub credentials: Vec<CredentialQuery>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_sets: Option<Vec<CredentialSetQuery>>,
}

impl DcqlQuery {
    pub fn validate(&self) -> Result<(), DcqlError> {
        if self.credentials.is_empty() {
            return Err(DcqlError::MissingCredentials);
        }
        if self.credential_sets.as_ref().is_some_and(Vec::is_empty) {
            return Err(DcqlError::InvalidCredentialSet);
        }
        let mut ids = std::collections::BTreeSet::new();
        for credential in &self.credentials {
            if !valid_identifier(&credential.id) || !ids.insert(credential.id.as_str()) {
                return Err(DcqlError::InvalidCredentialId);
            }
            if credential.claims.as_ref().is_some_and(Vec::is_empty)
                || credential.claim_sets.as_ref().is_some_and(Vec::is_empty)
            {
                return Err(DcqlError::EmptySelection);
            }
            let mut claim_ids = std::collections::BTreeSet::new();
            if let Some(claims) = &credential.claims {
                for claim in claims {
                    if claim.path.is_empty() {
                        return Err(DcqlError::EmptyClaimPath);
                    }
                    if credential.format == CredentialFormat::MsoMdoc
                        && (claim.path.len() != 2
                            || !claim
                                .path
                                .iter()
                                .all(|segment| matches!(segment, ClaimPathSegment::Name(_))))
                    {
                        return Err(DcqlError::InvalidClaimPath);
                    }
                    if claim.values.as_ref().is_some_and(|values| {
                        values.is_empty()
                            || values.iter().any(|value| {
                                !matches!(value, Value::String(_) | Value::Bool(_))
                                    && !value.is_i64()
                                    && !value.is_u64()
                            })
                    }) {
                        return Err(DcqlError::InvalidClaimValues);
                    }
                    if credential.claim_sets.is_some() && claim.id.is_none() {
                        return Err(DcqlError::InvalidClaimId);
                    }
                    if let Some(id) = claim.id.as_deref()
                        && (!valid_identifier(id) || !claim_ids.insert(id))
                    {
                        return Err(DcqlError::InvalidClaimId);
                    }
                }
            }
            if let Some(claim_sets) = &credential.claim_sets
                && claim_sets.iter().any(|set| {
                    set.is_empty()
                        || set
                            .iter()
                            .any(|id| id.is_empty() || !claim_ids.contains(id.as_str()))
                })
            {
                return Err(DcqlError::InvalidClaimSet);
            }
            let meta = credential
                .meta
                .as_ref()
                .and_then(Value::as_object)
                .ok_or(DcqlError::InvalidMetadata)?;
            // Unknown extensions are ignored, but each supported format's
            // required type constraint must be present and well formed.
            match credential.format {
                CredentialFormat::SdJwtVc => {
                    if meta.get("vct_values").is_none_or(|value| {
                        value.as_array().is_none_or(|values| {
                            values.is_empty()
                                || values
                                    .iter()
                                    .any(|value| value.as_str().is_none_or(str::is_empty))
                        })
                    }) {
                        return Err(DcqlError::InvalidMetadata);
                    }
                }
                CredentialFormat::MsoMdoc => {
                    if meta
                        .get("doctype_value")
                        .is_none_or(|value| value.as_str().is_none_or(str::is_empty))
                    {
                        return Err(DcqlError::InvalidMetadata);
                    }
                }
            }
        }
        if let Some(sets) = &self.credential_sets {
            for set in sets {
                if set.options.is_empty()
                    || set.options.iter().any(Vec::is_empty)
                    || set
                        .options
                        .iter()
                        .flatten()
                        .any(|id| !ids.contains(id.as_str()))
                {
                    return Err(DcqlError::InvalidCredentialSet);
                }
            }
        }
        Ok(())
    }
}

fn valid_identifier(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DcqlError {
    #[error("DCQL credentials must not be empty")]
    MissingCredentials,
    #[error("DCQL credential identifiers must be unique and non-empty")]
    InvalidCredentialId,
    #[error("DCQL claim selections must not be empty")]
    EmptySelection,
    #[error("DCQL claim paths must not be empty")]
    EmptyClaimPath,
    #[error("mdoc claim paths must contain a namespace and data element name")]
    InvalidClaimPath,
    #[error("DCQL values must be non-empty strings, integers or booleans")]
    InvalidClaimValues,
    #[error("DCQL claim identifiers must be unique and non-empty")]
    InvalidClaimId,
    #[error("DCQL claim set references are invalid")]
    InvalidClaimSet,
    #[error("DCQL credential set references are invalid")]
    InvalidCredentialSet,
    #[error("DCQL metadata must be an object with correctly typed known constraints")]
    InvalidMetadata,
}
