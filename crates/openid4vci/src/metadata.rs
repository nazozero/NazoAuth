use std::collections::BTreeMap;

use nazo_digital_credentials::CredentialFormat;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Logo {
    pub uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alt_text: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialDisplay {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo: Option<Logo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub background_color: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub background_image: Option<Logo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text_color: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialMetadata {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub display: Vec<CredentialDisplay>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofTypeMetadata {
    pub proof_signing_alg_values_supported: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_attestations_required: Option<BTreeMap<String, Vec<String>>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialConfiguration {
    pub format: CredentialFormat,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cryptographic_binding_methods_supported: Vec<String>,
    pub credential_signing_alg_values_supported: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub proof_types_supported: BTreeMap<String, ProofTypeMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vct: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doctype: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_metadata: Option<CredentialMetadata>,
}

impl CredentialConfiguration {
    pub fn validate(&self) -> Result<(), MetadataError> {
        let binding_declared = !self.cryptographic_binding_methods_supported.is_empty();
        let proofs_declared = !self.proof_types_supported.is_empty();
        if self.credential_signing_alg_values_supported.is_empty()
            || self.credential_signing_alg_values_supported != ["ES256"]
            || binding_declared != proofs_declared
            || self
                .cryptographic_binding_methods_supported
                .iter()
                .any(|method| method != "jwk")
            || self
                .proof_types_supported
                .iter()
                .any(|(proof_type, proof)| {
                    !matches!(proof_type.as_str(), "jwt" | "attestation")
                        || proof.proof_signing_alg_values_supported.is_empty()
                        || proof
                            .proof_signing_alg_values_supported
                            .iter()
                            .any(|alg| !matches!(alg.as_str(), "ES256" | "EdDSA"))
                })
        {
            return Err(MetadataError::EmptyAlgorithmSet);
        }
        match self.format {
            CredentialFormat::SdJwtVc if self.vct.as_deref().unwrap_or_default().is_empty() => {
                Err(MetadataError::MissingFormatType)
            }
            CredentialFormat::MsoMdoc if self.doctype.as_deref().unwrap_or_default().is_empty() => {
                Err(MetadataError::MissingFormatType)
            }
            CredentialFormat::MsoMdoc if !binding_declared => Err(MetadataError::MissingBinding),
            _ if self.scope.as_deref().is_some_and(|scope| {
                scope.is_empty()
                    || scope
                        .bytes()
                        .any(|byte| byte <= b' ' || byte == b'"' || byte == b'\\')
            }) =>
            {
                Err(MetadataError::InvalidScope)
            }
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptionMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alg_values_supported: Vec<String>,
    pub enc_values_supported: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub zip_values_supported: Vec<String>,
    pub encryption_required: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchCredentialIssuance {
    pub batch_size: u16,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialIssuerMetadata {
    pub credential_issuer: String,
    pub authorization_servers: Vec<String>,
    pub credential_endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deferred_credential_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notification_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_request_encryption: Option<EncryptionMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_response_encryption: Option<EncryptionMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch_credential_issuance: Option<BatchCredentialIssuance>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub display: Vec<CredentialDisplay>,
    pub credential_configurations_supported: BTreeMap<String, CredentialConfiguration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_metadata: Option<String>,
}

impl CredentialIssuerMetadata {
    pub fn validate(&self) -> Result<(), MetadataError> {
        let issuer = url::Url::parse(&self.credential_issuer)
            .map_err(|_| MetadataError::InvalidHttpsEndpoint)?;
        if issuer.scheme() != "https"
            || issuer.query().is_some()
            || issuer.fragment().is_some()
            || !issuer.username().is_empty()
            || issuer.password().is_some()
            || self.credential_configurations_supported.is_empty()
        {
            return Err(MetadataError::InvalidHttpsEndpoint);
        }
        for endpoint in self
            .authorization_servers
            .iter()
            .chain(std::iter::once(&self.credential_endpoint))
            .chain(self.nonce_endpoint.iter())
            .chain(self.deferred_credential_endpoint.iter())
            .chain(self.notification_endpoint.iter())
        {
            let parsed =
                url::Url::parse(endpoint).map_err(|_| MetadataError::InvalidHttpsEndpoint)?;
            if parsed.scheme() != "https"
                || parsed.fragment().is_some()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
            {
                return Err(MetadataError::InvalidHttpsEndpoint);
            }
        }
        for encryption in [
            self.credential_request_encryption.as_ref(),
            self.credential_response_encryption.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            if encryption.alg_values_supported != ["ECDH-ES"]
                || encryption.enc_values_supported != ["A256GCM"]
                || encryption
                    .zip_values_supported
                    .iter()
                    .any(|zip| zip != "DEF")
            {
                return Err(MetadataError::EmptyAlgorithmSet);
            }
        }
        if self
            .batch_credential_issuance
            .is_some_and(|batch| batch.batch_size < 2)
        {
            return Err(MetadataError::InvalidBatchSize);
        }
        for configuration in self.credential_configurations_supported.values() {
            configuration.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MetadataError {
    #[error("credential issuer endpoints must use canonical HTTPS URLs")]
    InvalidHttpsEndpoint,
    #[error("credential configuration requires its format-specific type")]
    MissingFormatType,
    #[error("credential configuration algorithm sets must not be empty")]
    EmptyAlgorithmSet,
    #[error("credential configuration scope is invalid")]
    InvalidScope,
    #[error("credential binding and proof metadata must be declared together")]
    MissingBinding,
    #[error("batch credential issuance requires a batch size of at least two")]
    InvalidBatchSize,
}
