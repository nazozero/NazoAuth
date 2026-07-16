use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::PRE_AUTHORIZED_CODE_GRANT;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TxCodeDescription {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationCodeGrant {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_server: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreAuthorizedCodeGrant {
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_code: Option<TxCodeDescription>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_server: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CredentialOfferGrants(pub BTreeMap<String, serde_json::Value>);

impl CredentialOfferGrants {
    pub fn new(
        authorization_code: Option<AuthorizationCodeGrant>,
        pre_authorized: Option<PreAuthorizedCodeGrant>,
    ) -> Self {
        let mut grants = BTreeMap::new();
        if let Some(grant) = authorization_code {
            grants.insert(
                "authorization_code".to_owned(),
                serde_json::to_value(grant).unwrap(),
            );
        }
        if let Some(grant) = pre_authorized {
            grants.insert(
                PRE_AUTHORIZED_CODE_GRANT.to_owned(),
                serde_json::to_value(grant).unwrap(),
            );
        }
        Self(grants)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialOffer {
    pub credential_issuer: String,
    pub credential_configuration_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<CredentialOfferGrants>,
}

impl CredentialOffer {
    pub fn validate(&self) -> Result<(), OfferError> {
        if self.credential_configuration_ids.is_empty()
            || self
                .credential_configuration_ids
                .iter()
                .any(String::is_empty)
        {
            return Err(OfferError::MissingCredentialConfiguration);
        }
        let url =
            url::Url::parse(&self.credential_issuer).map_err(|_| OfferError::InvalidIssuer)?;
        if url.scheme() != "https" || url.query().is_some() || url.fragment().is_some() {
            return Err(OfferError::InvalidIssuer);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OfferError {
    #[error("credential offer issuer is invalid")]
    InvalidIssuer,
    #[error("credential offer must identify at least one configuration")]
    MissingCredentialConfiguration,
}
