//! Semantic I/O capabilities supplied by an embedding host.
//!
//! These are storage, outbound delivery and expensive-work boundaries. The
//! facade constructs application services and endpoint handles itself.

use std::sync::Arc;

pub use crate::endpoints::auth::federation::FederationHttpClient;
pub use crate::endpoints::mtls::CertificateChainVerifier;
pub use nazo_identity::ports::{
    AvatarDirectUploadPort, AvatarStoragePort, MfaSecretHashPort, SecretHashPort, SecretVerifyPort,
    VerificationEmailDeliveryPort,
};
pub use nazo_key_management::KeyManager;
pub use nazo_oauth_server::ports::{
    audit::SecurityAudit, mdoc::MdocDocumentSigner, persistence::ServerPersistenceBindings,
    transient_state::ServerTransientStateBindings,
};
pub use nazo_runtime_modules::ModuleLifecycle;
pub use nazo_scim_events::EventPollerPort;

/// One outbound document client can supply the existing semantic document ports.
pub trait RemoteDocuments:
    nazo_oauth_server::contracts::dynamic_client_registration::RemoteJwksResolverPort
    + nazo_auth::SectorIdentifierResolverPort
    + nazo_oauth_server::ports::remote_request_object::RemoteRequestObjectResolverPort
    + nazo_oauth_server::ports::credential_status::CredentialStatusResolver
{
}

impl<T> RemoteDocuments for T where
    T: nazo_oauth_server::contracts::dynamic_client_registration::RemoteJwksResolverPort
        + nazo_auth::SectorIdentifierResolverPort
        + nazo_oauth_server::ports::remote_request_object::RemoteRequestObjectResolverPort
        + nazo_oauth_server::ports::credential_status::CredentialStatusResolver
{
}

/// Host-controlled execution of memory-hard password work.
pub struct PasswordServices {
    pub verifier: Arc<dyn SecretVerifyPort>,
    pub hasher: Arc<dyn SecretHashPort>,
    pub mfa: Arc<dyn MfaSecretHashPort>,
    /// Prepared hash of an unknown random secret, shared by nonexistent-account
    /// verification and accounts provisioned without a password.
    pub dummy_hash: String,
}

/// The dependencies that a host must actually provide; no application graph is exposed.
pub struct Capabilities {
    pub persistence: ServerPersistenceBindings,
    pub transient_state: ServerTransientStateBindings,
    pub keys: KeyManager,
    pub audit: Arc<dyn SecurityAudit>,
    pub passwords: PasswordServices,
    pub documents: Arc<dyn RemoteDocuments>,
    pub email: Arc<dyn VerificationEmailDeliveryPort>,
    pub federation_http: Arc<dyn FederationHttpClient>,
    pub module_lifecycle: Arc<dyn ModuleLifecycle>,
    pub scim_events: Arc<dyn EventPollerPort>,
    pub mdoc_signer: Option<Arc<dyn MdocDocumentSigner>>,
    pub certificate_verifier: Option<Arc<dyn CertificateChainVerifier>>,
}

pub use crate::control_discovery::DeploymentIdentity;

/// Current membership in the host's atomically published tenant index.
pub trait TenantAvailability: Send + Sync {
    fn contains_tenant(&self, tenant: nazo_identity::TenantId) -> bool;
}

/// Optional deployment-wide controls, admitted only through the configured control tenant.
pub struct DeploymentCapabilities {
    pub identity: DeploymentIdentity,
    pub control_tenant: nazo_identity::TenantId,
    pub tenants: Arc<dyn TenantAvailability>,
}

/// Supplies signed CRL bytes; native key provisioning remains in the host.
pub trait MdocCrlProvider: Send + Sync {
    fn signed_crl<'a>(
        &'a self,
        issuer_id: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<Option<bytes::Bytes>>> + Send + 'a>,
    >;
}
