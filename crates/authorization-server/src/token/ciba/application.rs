use super::{
    request::apply_ciba_request_object_client_id_hint,
    state::{CibaTokenHandles, ciba_module_admissible},
};
use crate::{
    contracts::{
        ciba::{BackchannelAuthenticationForm, PreparedCibaCreation},
        dynamic_client_registration::RemoteJwksResolverPort,
        oauth_error::OAuthEndpointError,
    },
    ports::audit::SecurityAudit,
    services::ServerAuthorizationService,
};
use std::sync::Arc;

pub struct CibaApplication {
    pub(super) authorization: Arc<ServerAuthorizationService>,
    pub(super) handles: Arc<CibaTokenHandles>,
    pub(super) remote_jwks: Arc<dyn RemoteJwksResolverPort>,
    pub(super) snapshots: Arc<nazo_runtime_modules::SnapshotStore>,
    pub(super) security_audit: Arc<dyn SecurityAudit>,
}
impl CibaApplication {
    pub fn new(
        authorization: Arc<ServerAuthorizationService>,
        handles: Arc<CibaTokenHandles>,
        remote_jwks: Arc<dyn RemoteJwksResolverPort>,
        snapshots: Arc<nazo_runtime_modules::SnapshotStore>,
        security_audit: Arc<dyn SecurityAudit>,
    ) -> Self {
        Self {
            authorization,
            handles,
            remote_jwks,
            snapshots,
            security_audit,
        }
    }
    pub fn check_admission(&self, admission: nazo_auth::CapabilityAdmission) -> bool {
        ciba_module_admissible(&self.snapshots, admission)
    }
}
pub fn prepare_ciba_creation(
    mut form: BackchannelAuthenticationForm,
    has_basic: bool,
) -> Result<PreparedCibaCreation, OAuthEndpointError> {
    let has_assertion = form.client_assertion_type.is_some() || form.client_assertion.is_some();
    if has_basic && (form.client_id.is_some() || form.client_secret.is_some() || has_assertion)
        || has_assertion && form.client_secret.is_some()
    {
        return Err(OAuthEndpointError::json(
            http::StatusCode::BAD_REQUEST,
            "invalid_request",
            "CIBA request cannot mix client authentication methods.",
        ));
    }
    apply_ciba_request_object_client_id_hint(&mut form, has_basic, has_assertion);
    Ok(PreparedCibaCreation::new(form))
}
