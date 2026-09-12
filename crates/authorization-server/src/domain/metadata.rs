use std::sync::Arc;

use crate::contracts::metadata::{
    MetadataEndpointConfig, MetadataSnapshot, MetadataSnapshotSource,
};
use nazo_auth::{CibaMetadataProfile, MetadataAuthorizationServerProfile, MetadataSubjectType};
use nazo_key_management::{KeyManager, signing_algorithm_name};
use nazo_runtime_modules::SnapshotStore;

#[derive(Clone)]
pub struct MetadataConfig {
    pub issuer: String,
    pub mtls_endpoint_base_url: String,
    pub mtls_enabled: bool,
    pub authorization_server_profile: MetadataAuthorizationServerProfile,
    pub ciba_security_profile: CibaMetadataProfile,
    pub subject_type: MetadataSubjectType,
    pub pairwise_subject_enabled: bool,
    pub protected_resource_identifier: String,
    pub require_pushed_authorization_requests: bool,
}

impl MetadataConfig {
    pub fn endpoint_config(&self) -> MetadataEndpointConfig {
        MetadataEndpointConfig {
            issuer: self.issuer.clone(),
            mtls_endpoint_base_url: self.mtls_endpoint_base_url.clone(),
            mtls_enabled: self.mtls_enabled,
            authorization_server_profile: self.authorization_server_profile,
            ciba_profile: self.ciba_security_profile,
            subject_type: self.subject_type,
            pairwise_subject_enabled: self.pairwise_subject_enabled,
            protected_resource_identifier: self.protected_resource_identifier.clone(),
            require_pushed_authorization_requests: self.require_pushed_authorization_requests,
        }
    }
}

/// Exposes public signing material and the currently published module snapshot.
pub struct ApplicationMetadataSnapshotSource {
    keyset: KeyManager,
    snapshots: Arc<SnapshotStore>,
}

impl ApplicationMetadataSnapshotSource {
    pub fn new(keyset: KeyManager, snapshots: Arc<SnapshotStore>) -> Self {
        Self { keyset, snapshots }
    }
}

impl MetadataSnapshotSource for ApplicationMetadataSnapshotSource {
    fn snapshot(&self) -> MetadataSnapshot {
        let keys = self.keyset.snapshot();
        MetadataSnapshot {
            active_modules: self.snapshots.load_full(),
            active_signing_algorithms: signing_algorithm_name(keys.active_alg)
                .into_iter()
                .collect(),
            id_token_signing_algorithms: keys.id_token_signing_alg_values_supported(),
            response_signing_algorithms: keys.response_signing_alg_values_supported(),
            jwks: keys.jwks(),
        }
    }
}
