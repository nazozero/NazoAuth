//! Atomic tenant-resource persistence contract.
//!
//! An adapter must commit idempotency, resource mutations, revision fencing,
//! security audit append, and the replayable typed outcome as one atomic unit.

use std::{collections::BTreeMap, fmt};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use futures_util::future::BoxFuture;
use nazo_auth::{CreateClientRequest, OAuthClient};
use nazo_identity::TenantContext;
use nazo_operator_protocol::{
    ControlResultData, Openid4vcTrustPolicy, TenantResourceIdentity, TenantResourceKind,
    TenantResourceSelector, canonical_tenant_resource_manifest_sha256,
    validate_openid4vc_trust_policy,
};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const APPLY_MANIFEST_SCHEMA: u32 = 1;
const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_RESOURCE_PAYLOAD_BYTES: usize = 512 * 1024;
const MAX_USERNAME_BYTES: usize = 150;
const MAX_EMAIL_BYTES: usize = 254;
const MAX_PASSWORD_BYTES: usize = 512;
const MAX_CLIENT_SECRET_BYTES: usize = 512;
const MAX_CONFIGURATION_ID_BYTES: usize = 255;
const MAX_DATASET_CLAIMS_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TenantResourceAction {
    Apply,
    Enumerate,
    Revoke,
}

#[derive(Clone)]
pub enum TenantResourcePayload {
    User(Box<UserResourcePayload>),
    OauthClient(Box<OauthClientResourcePayload>),
    MtlsTrustAnchor(MtlsTrustAnchorResourcePayload),
    Openid4vcDataset(Openid4vcDatasetResourcePayload),
    Openid4vcTrustPolicy(Box<Openid4vcTrustPolicyResourcePayload>),
}

#[derive(Clone)]
pub struct UserResourcePayload {
    pub username: String,
    pub email: String,
    pub password: String,
    pub email_verified: bool,
    pub profile: UserProfileFields,
}

#[derive(Clone, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct UserProfileFields {
    pub display_name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub middle_name: Option<String>,
    pub nickname: Option<String>,
    pub profile_url: Option<String>,
    pub avatar_url: Option<String>,
    pub website_url: Option<String>,
    pub gender: Option<String>,
    pub birthdate: Option<String>,
    pub zoneinfo: Option<String>,
    pub locale: Option<String>,
    pub address_formatted: Option<String>,
    pub address_street_address: Option<String>,
    pub address_locality: Option<String>,
    pub address_region: Option<String>,
    pub address_postal_code: Option<String>,
    pub address_country: Option<String>,
    pub phone_number: Option<String>,
    pub phone_number_verified: bool,
}

#[derive(Clone)]
pub struct OauthClientResourcePayload {
    pub request: CreateClientRequest,
    pub supplied_secret: Option<String>,
    pub trust_policy_resource_id: Option<String>,
}

#[derive(Clone)]
pub struct MtlsTrustAnchorResourcePayload {
    pub client_resource_id: String,
    pub certificate_pem: String,
}

#[derive(Clone)]
pub struct Openid4vcDatasetResourcePayload {
    pub user_resource_id: String,
    pub configuration_id: String,
    pub claims: Value,
}

#[derive(Clone)]
pub struct Openid4vcTrustPolicyResourcePayload {
    pub public_material: Openid4vcTrustPolicy,
}

#[derive(Clone)]
pub struct PreparedTenantResource {
    pub identity: TenantResourceIdentity,
    /// Apply carries one payload; Revoke and Enumerate do not.
    pub payload: Option<TenantResourcePayload>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TenantResourceExecutorError {
    Conflict,
    Unavailable,
    Rejected,
    InvalidPayload(&'static str),
    TooLarge,
}

impl fmt::Display for TenantResourceExecutorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Conflict => "tenant-resource consistency conflict",
            Self::Unavailable => "tenant-resource persistence unavailable",
            Self::Rejected => "tenant-resource operation rejected",
            Self::InvalidPayload(message) => message,
            Self::TooLarge => "tenant-resource payload too large",
        })
    }
}

impl std::error::Error for TenantResourceExecutorError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplyManifest {
    schema: u32,
    resources: Vec<ManifestResource>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestResource {
    kind: TenantResourceKind,
    resource_id: String,
    payload_base64url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UserManifestPayload {
    username: String,
    email: String,
    password: String,
    email_verified: bool,
    #[serde(default)]
    profile: Option<serde_json::Map<String, Value>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OauthClientManifestPayload {
    request: CreateClientRequest,
    #[serde(default)]
    supplied_secret: Option<String>,
    #[serde(default)]
    trust_policy_resource_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MtlsTrustAnchorManifestPayload {
    client_resource_id: String,
    certificate_pem: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Openid4vcDatasetManifestPayload {
    user_resource_id: String,
    configuration_id: String,
    claims: Value,
}

/// Decode an Apply manifest and bind every payload to the exact signed
/// identity set. This validation is backend independent.
pub fn decode_change_set_payloads(
    raw_manifest: &[u8],
    identities: &[TenantResourceIdentity],
) -> Result<Vec<PreparedTenantResource>, TenantResourceExecutorError> {
    if raw_manifest.len() > MAX_MANIFEST_BYTES {
        return Err(TenantResourceExecutorError::TooLarge);
    }
    let manifest: ApplyManifest = serde_json::from_slice(raw_manifest)
        .map_err(|_| TenantResourceExecutorError::InvalidPayload("invalid resource manifest"))?;
    if manifest.schema != APPLY_MANIFEST_SCHEMA
        || manifest.resources.is_empty()
        || manifest.resources.len() > nazo_operator_protocol::MAX_TENANT_RESOURCE_IDENTITIES
    {
        return Err(TenantResourceExecutorError::InvalidPayload(
            "unsupported resource manifest",
        ));
    }
    let mut authorized = identities
        .iter()
        .map(|identity| ((identity.kind, identity.resource_id.as_str()), identity))
        .collect::<BTreeMap<_, _>>();
    let mut prepared = Vec::with_capacity(manifest.resources.len());
    for resource in &manifest.resources {
        let identity = authorized
            .remove(&(resource.kind, resource.resource_id.as_str()))
            .ok_or(TenantResourceExecutorError::InvalidPayload(
                "manifest resource is not authorized by task or is duplicated",
            ))?;
        let payload = URL_SAFE_NO_PAD
            .decode(&resource.payload_base64url)
            .map_err(|_| {
                TenantResourceExecutorError::InvalidPayload(
                    "resource payload is not valid base64url",
                )
            })?;
        if payload.len() > MAX_RESOURCE_PAYLOAD_BYTES {
            return Err(TenantResourceExecutorError::TooLarge);
        }
        if sha256_hex(&payload) != identity.digest {
            return Err(TenantResourceExecutorError::InvalidPayload(
                "resource payload digest does not match task",
            ));
        }
        let typed = decode_payload(resource.kind, &payload)?;
        prepared.push(PreparedTenantResource {
            identity: identity.clone(),
            payload: Some(typed),
        });
    }
    if prepared.len() != identities.len() {
        return Err(TenantResourceExecutorError::InvalidPayload(
            "manifest resources do not match task",
        ));
    }
    Ok(prepared)
}

fn decode_payload(
    kind: TenantResourceKind,
    payload: &[u8],
) -> Result<TenantResourcePayload, TenantResourceExecutorError> {
    match kind {
        TenantResourceKind::User => {
            let value: UserManifestPayload = serde_json::from_slice(payload)
                .map_err(|_| TenantResourceExecutorError::InvalidPayload("invalid user payload"))?;
            validate_text(&value.username, MAX_USERNAME_BYTES)?;
            validate_text(&value.email, MAX_EMAIL_BYTES)?;
            validate_text(&value.password, MAX_PASSWORD_BYTES)?;
            let profile = normalize_user_profile(value.profile)?;
            Ok(TenantResourcePayload::User(Box::new(UserResourcePayload {
                username: value.username,
                email: value.email,
                password: value.password,
                email_verified: value.email_verified,
                profile,
            })))
        }
        TenantResourceKind::OauthClient => {
            let value: OauthClientManifestPayload =
                serde_json::from_slice(payload).map_err(|_| {
                    TenantResourceExecutorError::InvalidPayload("invalid oauth client payload")
                })?;
            if let Some(secret) = &value.supplied_secret {
                validate_text(secret, MAX_CLIENT_SECRET_BYTES)?;
            }
            Ok(TenantResourcePayload::OauthClient(Box::new(
                OauthClientResourcePayload {
                    request: value.request,
                    supplied_secret: value.supplied_secret,
                    trust_policy_resource_id: value
                        .trust_policy_resource_id
                        .map(|resource_id| validate_resource_id(&resource_id).map(|()| resource_id))
                        .transpose()?,
                },
            )))
        }
        TenantResourceKind::MtlsTrustAnchor => {
            let value: MtlsTrustAnchorManifestPayload =
                serde_json::from_slice(payload).map_err(|_| {
                    TenantResourceExecutorError::InvalidPayload("invalid mTLS trust anchor payload")
                })?;
            validate_resource_id(&value.client_resource_id)?;
            Ok(TenantResourcePayload::MtlsTrustAnchor(
                MtlsTrustAnchorResourcePayload {
                    client_resource_id: value.client_resource_id,
                    certificate_pem: value.certificate_pem,
                },
            ))
        }
        TenantResourceKind::Openid4vcDataset => {
            let value: Openid4vcDatasetManifestPayload =
                serde_json::from_slice(payload).map_err(|_| {
                    TenantResourceExecutorError::InvalidPayload("invalid OpenID4VC dataset payload")
                })?;
            validate_resource_id(&value.user_resource_id)?;
            validate_text(&value.configuration_id, MAX_CONFIGURATION_ID_BYTES)?;
            if !value.claims.is_object() {
                return Err(TenantResourceExecutorError::InvalidPayload(
                    "OpenID4VC dataset claims must be an object",
                ));
            }
            let size =
                nazo_operator_protocol::serialized_json_size(&value.claims).map_err(|_| {
                    TenantResourceExecutorError::InvalidPayload("invalid dataset claims")
                })?;
            if size > MAX_DATASET_CLAIMS_BYTES {
                return Err(TenantResourceExecutorError::TooLarge);
            }
            Ok(TenantResourcePayload::Openid4vcDataset(
                Openid4vcDatasetResourcePayload {
                    user_resource_id: value.user_resource_id,
                    configuration_id: value.configuration_id,
                    claims: value.claims,
                },
            ))
        }
        TenantResourceKind::Openid4vcTrustPolicy => {
            let public_material: Openid4vcTrustPolicy =
                serde_json::from_slice(payload).map_err(|_| {
                    TenantResourceExecutorError::InvalidPayload(
                        "invalid OpenID4VC trust policy payload",
                    )
                })?;
            validate_openid4vc_trust_policy(&public_material).map_err(|_| {
                TenantResourceExecutorError::InvalidPayload("invalid OpenID4VC trust policy")
            })?;
            Ok(TenantResourcePayload::Openid4vcTrustPolicy(Box::new(
                Openid4vcTrustPolicyResourcePayload { public_material },
            )))
        }
    }
}

fn validate_resource_id(value: &str) -> Result<(), TenantResourceExecutorError> {
    nazo_operator_protocol::validate_file_identifier_value(value)
        .map_err(|_| TenantResourceExecutorError::InvalidPayload("invalid resource identifier"))
}

fn validate_text(value: &str, max_bytes: usize) -> Result<(), TenantResourceExecutorError> {
    if value.trim().is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(TenantResourceExecutorError::InvalidPayload(
            "invalid resource text",
        ));
    }
    Ok(())
}

fn normalize_user_profile(
    value: Option<serde_json::Map<String, Value>>,
) -> Result<UserProfileFields, TenantResourceExecutorError> {
    let fields: UserProfileFields = value
        .map(|object| serde_json::from_value(Value::Object(object)))
        .transpose()
        .map_err(|_| TenantResourceExecutorError::InvalidPayload("invalid user profile"))?
        .unwrap_or_default();
    macro_rules! text {
        ($name:ident, $max:expr) => {
            if let Some(text) = &fields.$name {
                validate_profile_text(text, $max)?;
            }
        };
    }
    text!(display_name, 80);
    text!(given_name, 80);
    text!(family_name, 80);
    text!(middle_name, 80);
    text!(nickname, 80);
    text!(profile_url, 512);
    text!(avatar_url, 512);
    text!(website_url, 512);
    text!(gender, 40);
    text!(birthdate, 10);
    text!(zoneinfo, 64);
    text!(locale, 35);
    text!(address_formatted, 512);
    text!(address_street_address, 256);
    text!(address_locality, 128);
    text!(address_region, 128);
    text!(address_postal_code, 64);
    text!(address_country, 64);
    text!(phone_number, 32);
    Ok(fields)
}

fn validate_profile_text(text: &str, max_bytes: usize) -> Result<(), TenantResourceExecutorError> {
    if text.is_empty() || text.len() > max_bytes || text.chars().any(char::is_control) {
        return Err(TenantResourceExecutorError::InvalidPayload(
            "invalid user profile",
        ));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Result of application policy preparation consumed by a persistence adapter.
pub struct PreparedOAuthClient {
    pub client: OAuthClient,
    pub client_secret_hash: Option<String>,
}

/// Certificate material validated by the application policy layer before the
/// adapter opens its mutation transaction.
pub struct PreparedMtlsTrustAnchor {
    pub certificate_pem: String,
    pub certificate_sha256: String,
    pub subject_dn: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

impl fmt::Debug for PreparedOAuthClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedOAuthClient")
            .field("client_id", &self.client.client_id)
            .field("client_secret_hash", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TenantResourcePreparationError {
    Rejected,
    Unavailable,
}

/// Application policy bridge used before entering the database transaction.
pub trait TenantResourcePreparation: Send + Sync {
    fn hash_user_password<'a>(
        &'a self,
        password: String,
    ) -> BoxFuture<'a, Result<String, TenantResourcePreparationError>>;

    fn prepare_oauth_client<'a>(
        &'a self,
        request: CreateClientRequest,
        supplied_secret: Option<String>,
        tenant: TenantContext,
    ) -> BoxFuture<'a, Result<PreparedOAuthClient, TenantResourcePreparationError>>;

    fn prepare_mtls_trust_anchor<'a>(
        &'a self,
        certificate_pem: String,
    ) -> BoxFuture<'a, Result<PreparedMtlsTrustAnchor, TenantResourcePreparationError>>;
}

pub struct ControlTenantResourceFrame<'a> {
    pub deployment_id: &'a str,
    pub jti: &'a str,
    pub request_sha256: &'a str,
    pub actor: &'a Value,
    pub operation: TenantResourceAction,
    pub tenant_id: &'a str,
    pub resources: Vec<PreparedTenantResource>,
    pub selectors: &'a [TenantResourceSelector],
}

/// Atomic execution boundary implemented by each database adapter.
pub trait TenantResourceExecutorPort: Send + Sync {
    fn execute_control_operation<'a>(
        &'a self,
        frame: ControlTenantResourceFrame<'a>,
    ) -> BoxFuture<'a, Result<ControlResultData, TenantResourceExecutorError>>;
}

#[must_use]
pub fn empty_manifest_sha256() -> String {
    canonical_tenant_resource_manifest_sha256(&[])
        .expect("the empty tenant-resource identity set is valid")
}

#[must_use]
pub const fn operation_name(operation: TenantResourceAction) -> &'static str {
    match operation {
        TenantResourceAction::Apply => "apply",
        TenantResourceAction::Enumerate => "enumerate",
        TenantResourceAction::Revoke => "revoke",
    }
}

#[cfg(test)]
#[path = "../tests/unit/tenant_resources.rs"]
mod tests;
