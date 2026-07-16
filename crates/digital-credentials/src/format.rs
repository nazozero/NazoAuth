use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{MDOC_MEDIA_TYPE, SD_JWT_VC_MEDIA_TYPE};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialFormat {
    #[serde(rename = "dc+sd-jwt")]
    SdJwtVc,
    #[serde(rename = "mso_mdoc")]
    MsoMdoc,
}

impl CredentialFormat {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SdJwtVc => SD_JWT_VC_MEDIA_TYPE,
            Self::MsoMdoc => MDOC_MEDIA_TYPE,
        }
    }
}

impl FromStr for CredentialFormat {
    type Err = CredentialFormatError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            SD_JWT_VC_MEDIA_TYPE => Ok(Self::SdJwtVc),
            MDOC_MEDIA_TYPE => Ok(Self::MsoMdoc),
            _ => Err(CredentialFormatError::Unsupported),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CredentialFormatError {
    #[error("credential format is not supported")]
    Unsupported,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HolderBinding {
    Jwk { jwk: Value },
}

#[derive(Clone, Debug, PartialEq)]
pub struct CredentialPayload {
    pub issuer: String,
    pub format: CredentialFormat,
    pub configuration_id: String,
    pub credential_type: String,
    pub subject_claims: Value,
    pub holder_binding: Option<HolderBinding>,
    pub selectively_disclosable_claims: Vec<String>,
}
