use crate::http::Response;
use std::sync::Arc;

use nazo_auth::{
    AuthorizationServerMetadataInput, MetadataSigningAlgorithms, ProtectedResourceMetadataInput,
    authorization_server_metadata, protected_resource_metadata,
};
use nazo_oauth_server::contracts::metadata::{
    MetadataEndpointConfig, MetadataSnapshot, MetadataSnapshotSource,
};
use nazo_runtime_modules::ActiveModuleSnapshot;
use serde::Serialize;

/// Focused HTTP services for discovery, RFC 8414/RFC 9728 metadata, and JWKS.
#[derive(Clone)]
pub struct MetadataHandles {
    config: MetadataEndpointConfig,
    snapshots: Arc<dyn MetadataSnapshotSource>,
}

impl MetadataHandles {
    #[must_use]
    pub fn new(config: MetadataEndpointConfig, snapshots: Arc<dyn MetadataSnapshotSource>) -> Self {
        Self { config, snapshots }
    }

    fn authorization_server_metadata<'a>(
        &'a self,
        snapshot: &'a MetadataSnapshot,
    ) -> impl Serialize + 'a {
        authorization_server_metadata(
            AuthorizationServerMetadataInput {
                deployment_profile: self.config.deployment_profile,
                issuer: &self.config.issuer,
                mtls_endpoint_base_url: &self.config.mtls_endpoint_base_url,
                mtls_enabled: self.config.mtls_enabled,
                backchannel_logout_supported: self.config.backchannel_logout_supported,
                profile: self.config.authorization_server_profile,
                ciba_profile: self.config.ciba_profile,
                pairwise_subject_enabled: self.config.pairwise_subject_enabled,
                protected_resource_identifier: &self.config.protected_resource_identifier,
                additional_scopes_supported: &self.config.additional_scopes_supported,
                credential_scopes: &self.config.credential_scopes,
                require_pushed_authorization_requests: self
                    .config
                    .require_pushed_authorization_requests,
                signing_algorithms: MetadataSigningAlgorithms {
                    active: &snapshot.active_signing_algorithms,
                    id_token: &snapshot.id_token_signing_algorithms,
                    response: &snapshot.response_signing_algorithms,
                },
            },
            &snapshot.active_modules,
        )
    }

    fn protected_resource_metadata<'a>(
        &'a self,
        modules: &'a ActiveModuleSnapshot,
    ) -> impl Serialize + 'a {
        protected_resource_metadata(
            ProtectedResourceMetadataInput {
                issuer: &self.config.issuer,
                protected_resource_identifier: &self.config.protected_resource_identifier,
                mtls_enabled: self.config.mtls_enabled,
            },
            modules,
        )
    }
}

/// OIDC Discovery metadata. A single immutable snapshot is used for the whole document.
pub fn discovery(handles: &MetadataHandles) -> Response {
    let snapshot = handles.snapshots.snapshot();
    crate::http::json_response(handles.authorization_server_metadata(&snapshot))
}

/// RFC 8414 Authorization Server metadata.
pub fn oauth_authorization_server_metadata(handles: &MetadataHandles) -> Response {
    let snapshot = handles.snapshots.snapshot();
    crate::http::json_response(handles.authorization_server_metadata(&snapshot))
}

/// RFC 9728 Protected Resource metadata.
pub fn oauth_protected_resource_metadata(handles: &MetadataHandles) -> Response {
    let snapshot = handles.snapshots.active_modules();
    crate::http::json_response(handles.protected_resource_metadata(&snapshot))
}

/// Public JSON Web Key Set derived from the current key snapshot.
pub fn jwks(handles: &MetadataHandles) -> Response {
    crate::http::json_response(handles.snapshots.jwks())
}

#[cfg(test)]
#[path = "../../tests/unit/http/metadata.rs"]
mod tests;
