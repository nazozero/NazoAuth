//! Authorization protocol orchestration and typed outcomes.
pub mod config;
mod consent;
mod jar;
pub mod par;
pub mod presentation;
mod request;
use crate::{
    contracts::{
        authorization_decision::AuthorizationDecisionResponse,
        dynamic_client_registration::RemoteJwksResolverPort, oauth_error::OAuthEndpointError,
    },
    ports::{audit::SecurityAudit, remote_request_object::RemoteRequestObjectResolverPort},
    services::ServerAuthorizationService,
    sessions::SessionResolver,
};
use config::AuthorizationConfig;
use nazo_identity::SessionId;
use nazo_openid4vci::AuthorizationOfferPort;
use nazo_runtime_modules::{ActiveModuleSnapshot, ModuleId, SnapshotStore};
use std::{collections::HashMap, sync::Arc};
use uuid::Uuid;
pub type AuthorizationOutcome = AuthorizationDecisionResponse;
pub struct AuthorizationRequestFacts<'a> {
    pub source_ip: &'a str,
    pub session_id: Option<&'a SessionId>,
    pub user_agent: Option<&'a str>,
}
pub struct AuthorizationApplication {
    service: Arc<ServerAuthorizationService>,
    security_audit: Arc<dyn SecurityAudit>,
    config: Arc<AuthorizationConfig>,
    sessions: Arc<SessionResolver>,
    snapshots: Arc<SnapshotStore>,
    remote_client_documents: Arc<dyn RemoteJwksResolverPort>,
    request_object_resolver: Arc<dyn RemoteRequestObjectResolverPort>,
    request_object_keys: nazo_key_management::KeyManager,
    tenant_id: Uuid,
    credential_authorization_offers: Option<Arc<dyn AuthorizationOfferPort>>,
}
impl AuthorizationApplication {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        service: Arc<ServerAuthorizationService>,
        security_audit: Arc<dyn SecurityAudit>,
        config: Arc<AuthorizationConfig>,
        sessions: Arc<SessionResolver>,
        snapshots: Arc<SnapshotStore>,
        remote_client_documents: Arc<dyn RemoteJwksResolverPort>,
        request_object_resolver: Arc<dyn RemoteRequestObjectResolverPort>,
        request_object_keys: nazo_key_management::KeyManager,
        tenant_id: Uuid,
        credential_authorization_offers: Option<Arc<dyn AuthorizationOfferPort>>,
    ) -> Self {
        Self {
            service,
            security_audit,
            config,
            sessions,
            snapshots,
            remote_client_documents,
            request_object_resolver,
            request_object_keys,
            tenant_id,
            credential_authorization_offers,
        }
    }
    pub fn duplicate_parameters() -> Vec<&'static str> {
        request::authorization_duplicate_parameters()
    }
    pub async fn authorize(
        &self,
        facts: &AuthorizationRequestFacts<'_>,
        parameters: &mut HashMap<String, String>,
    ) -> Result<AuthorizationOutcome, OAuthEndpointError> {
        request::flow::authorize_request_with_context(&self.context(), facts, parameters).await
    }
    pub async fn consent(
        &self,
        session_id: Option<&SessionId>,
        request_id: Option<&str>,
    ) -> Result<crate::domain::oauth::ConsentPayload, OAuthEndpointError> {
        consent::consent_with_context(&self.context(), session_id, request_id).await
    }
    pub async fn client_presentation(
        &self,
        client_id: &str,
    ) -> Result<presentation::ClientPresentation, presentation::ClientPresentationError> {
        presentation::client_presentation_with_context(&self.context(), client_id).await
    }
    pub(crate) fn context(&self) -> AuthorizationRequestContext<'_> {
        AuthorizationRequestContext {
            service: &self.service,
            security_audit: self.security_audit.as_ref(),
            config: &self.config,
            sessions: &self.sessions,
            modules: self.snapshots.load_full().as_ref().clone(),
            remote_client_documents: self.remote_client_documents.as_ref(),
            request_object_resolver: self.request_object_resolver.as_ref(),
            request_object_keys: &self.request_object_keys,
            tenant_id: self.tenant_id,
            credential_authorization_offers: self.credential_authorization_offers.as_deref(),
        }
    }
}
pub(crate) struct AuthorizationRequestContext<'a> {
    pub(crate) service: &'a ServerAuthorizationService,
    pub(crate) security_audit: &'a dyn SecurityAudit,
    pub(crate) config: &'a AuthorizationConfig,
    pub(crate) sessions: &'a SessionResolver,
    pub(crate) modules: ActiveModuleSnapshot,
    pub(crate) remote_client_documents: &'a dyn RemoteJwksResolverPort,
    pub(crate) request_object_resolver: &'a dyn RemoteRequestObjectResolverPort,
    pub(crate) request_object_keys: &'a nazo_key_management::KeyManager,
    pub(crate) tenant_id: Uuid,
    pub(crate) credential_authorization_offers: Option<&'a dyn AuthorizationOfferPort>,
}
pub(crate) fn accepts_module(
    context: &AuthorizationRequestContext<'_>,
    module_id: ModuleId,
) -> bool {
    nazo_auth::module_admissible(
        &context.modules,
        module_id,
        nazo_auth::CapabilityAdmission::NewRequest,
    )
}
pub(crate) fn permits_existing_module_transaction(
    context: &AuthorizationRequestContext<'_>,
    module_id: ModuleId,
) -> bool {
    nazo_auth::module_admissible(
        &context.modules,
        module_id,
        nazo_auth::CapabilityAdmission::ExistingTransaction,
    )
}
use jar::{apply_request_object_with_context, unverified_request_object_client_id};
use par::is_pushed_authorization_request_uri;
