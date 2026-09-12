use std::sync::Arc;

use nazo_auth::{CibaMetadataProfile, MetadataAuthorizationServerProfile, MetadataSubjectType};
use nazo_runtime_modules::ActiveModuleSnapshot;
use serde_json::Value;

/// Owned, transport-facing configuration used to render standard metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataEndpointConfig {
    pub issuer: String,
    pub mtls_endpoint_base_url: String,
    pub mtls_enabled: bool,
    pub authorization_server_profile: MetadataAuthorizationServerProfile,
    pub ciba_profile: CibaMetadataProfile,
    pub subject_type: MetadataSubjectType,
    pub pairwise_subject_enabled: bool,
    pub protected_resource_identifier: String,
    pub require_pushed_authorization_requests: bool,
}

/// One request's immutable view of module admission and public signing data.
#[derive(Clone, Debug)]
pub struct MetadataSnapshot {
    pub active_modules: Arc<ActiveModuleSnapshot>,
    pub active_signing_algorithms: Vec<&'static str>,
    pub id_token_signing_algorithms: Vec<&'static str>,
    pub response_signing_algorithms: Vec<&'static str>,
    pub jwks: Value,
}

/// Supplies public, request-facing snapshots without exposing key lifecycle or storage details.
pub trait MetadataSnapshotSource: Send + Sync {
    fn snapshot(&self) -> MetadataSnapshot;
}
