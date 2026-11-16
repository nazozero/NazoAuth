use crate::capabilities::Capabilities;
use crate::config::Configuration as Settings;
use crate::endpoints::{
    admin::{
        access_requests::AdminAccessRequestConfig,
        clients::{
            AdminClientConfig, ServerAdminClientCrypto, ServerAdminClientService,
            admin_client_policy,
        },
        federation::AdminFederationConfig,
    },
    auth::{
        MFA_REMEMBERED_COOKIE_NAME, MFA_REMEMBERED_TTL_SECONDS,
        csrf::CsrfHttpConfig,
        federation::{FEDERATION_STATE_TTL_SECONDS, FederationHttpConfig, SAML_REPLAY_TTL_SECONDS},
    },
    authorization::{AuthorizationEndpoint, authorization_config},
    mtls::{MtlsCertificateSource, ServerMtlsThumbprintExtractor},
    profile::avatar::AvatarProfileService,
    sessions::{AdminSessionHandles, SessionHttpConfig, SessionProfileHandles},
    token::{
        ServerTokenManagementRequestFactsExtractor, ciba::ciba_config,
        device_config::DeviceHttpConfig, issue::token_issuance_config,
    },
};
use crate::http::{
    AuthorizationDecisionEndpoint, ClientIpConfig, LocalRegistrationEndpoint, MfaProfileConfig,
    MfaProfileEndpoint, OidcLogoutConfig as OidcLogoutHttpConfig, OidcLogoutEndpoint,
    PasskeyLoginConfig, PasskeyLoginEndpoint, PasskeyProfileConfig, PasskeyProfileEndpoint,
    PasswordLoginConfig, PasswordLoginEndpoint, ProfileAccountEndpoint, RuntimeModuleAdminEndpoint,
    SessionCookieConfig, SessionLogoutEndpoint, SessionManagementConfig, SessionManagementEndpoint,
};
use crate::runtime_modules::{RuntimeModules, ServerRuntimeModuleRegistry};
use audit::{TracingAuthenticationAudit, TracingFederationAudit, TracingPasskeyAudit};
use std::sync::Arc;

pub(crate) mod audit;
mod core;
mod dispatch;
mod identity;
mod openid4vc;

use crate::openid4vc::{CredentialIssuerEndpoint, PresentationEndpoint};
use nazo_oauth_server::authorization::config::AuthorizationConfig;
use nazo_oauth_server::domain::authorization_decision::ServerAuthorizationDecisionOperations;
use nazo_oauth_server::domain::dynamic_registration::DynamicRegistrationConfig;
use nazo_oauth_server::domain::local_registration::ServerAuthenticationRateLimit;
use nazo_oauth_server::domain::local_registration::ServerLocalRegistrationOperations;
use nazo_oauth_server::domain::metadata::MetadataConfig;
use nazo_oauth_server::domain::mfa_profile::ServerMfaProfileOperations;
use nazo_oauth_server::domain::oidc_logout::OidcLogoutConfig;
use nazo_oauth_server::domain::oidc_logout::OidcLogoutHandles;
use nazo_oauth_server::domain::openid4vc::Openid4vcCredentialCrypto;
use nazo_oauth_server::domain::openid4vc::Openid4vcProofValidator;
use nazo_oauth_server::domain::openid4vc_endpoints::CredentialDatasetAdminService;
use nazo_oauth_server::domain::openid4vc_endpoints::PresentationVerifierConfig;
use nazo_oauth_server::domain::openid4vc_endpoints::ServerCredentialIssuerOperations;
use nazo_oauth_server::domain::openid4vc_endpoints::ServerPresentationOperations;
use nazo_oauth_server::domain::passkey::PasskeyOperationsProvider;
use nazo_oauth_server::domain::password_login::ServerPasswordLoginOperations;
use nazo_oauth_server::domain::profile_account::ServerProfileAccountOperations;
use nazo_oauth_server::domain::resource_server::{
    ResourceServerConfig, ServerFapiHttpMessageSignatures, ServerFapiResourceAuthorizer,
};
use nazo_oauth_server::domain::scim::ServerScimCursorProtector;
use nazo_oauth_server::domain::scim::ServerScimRequestAuthorizer;
use nazo_oauth_server::domain::session_management::ServerSessionManagementOperations;
use nazo_oauth_server::domain::token_management::ServerTokenManagementOperations;
use nazo_oauth_server::domain::token_management::ServerTokenManagementRequestGuard;
use nazo_oauth_server::domain::userinfo::ServerUserinfoOperations;
use nazo_oauth_server::domain::userinfo::UserinfoConfig;
use nazo_oauth_server::domain::userinfo::UserinfoHandles;
use nazo_oauth_server::rate_limit::{AuthRequestLimiter, TokenManagementRequestLimiter};
use nazo_oauth_server::token::ciba::state::CibaTokenHandles;
use nazo_oauth_server::token::device::DeviceDecisionHandles;
use nazo_oauth_server::token::dispatch::{
    Openid4vcTokenHandles, TokenCoreHandles, TokenEndpointHandles,
};

/// A fully assembled tenant. Request dispatch borrows focused services from this
/// immutable graph; it never constructs services or looks up dependencies by type.
pub struct NazoAuth {
    pub(crate) settings: Arc<Settings>,
    core: core::CoreServices,
    identity: identity::IdentityServices,
    runtime_modules: Arc<RuntimeModules>,
    mtls: Arc<MtlsCertificateSource>,
    readiness: crate::well_known::ReadinessDependencies,
    deployment: Option<DeploymentServices>,
    mdoc_crls: Option<Arc<dyn crate::capabilities::MdocCrlProvider>>,
    password_hasher: Arc<dyn crate::capabilities::SecretHashPort>,
}

/// Builds a tenant once from configuration and actual host I/O capabilities.
pub struct NazoAuthBuilder {
    settings: Settings,
    capabilities: Capabilities,
    instance_id: String,
    avatar: AvatarProfileService,
    deployment: Option<Arc<crate::capabilities::DeploymentCapabilities>>,
    mdoc_crls: Option<Arc<dyn crate::capabilities::MdocCrlProvider>>,
}

impl NazoAuthBuilder {
    pub fn new(
        settings: Settings,
        capabilities: Capabilities,
        instance_id: impl Into<String>,
    ) -> Self {
        Self {
            settings,
            capabilities,
            instance_id: instance_id.into(),
            avatar: AvatarProfileService::Disabled,
            deployment: None,
            mdoc_crls: None,
        }
    }

    pub fn with_avatar_storage<S: nazo_identity::ports::AvatarStoragePort + 'static>(
        mut self,
        storage: S,
    ) -> Self {
        let persistence = self.capabilities.persistence.provider();
        self.avatar = AvatarProfileService::local(nazo_identity::AvatarService::from_ports(
            persistence.avatars(),
            persistence.grant_summaries(),
            storage,
            self.settings.storage.avatar_max_bytes,
        ));
        self
    }

    pub fn with_direct_avatar_storage(
        mut self,
        storage: Arc<dyn nazo_identity::ports::AvatarDirectUploadPort>,
    ) -> Self {
        let persistence = self.capabilities.persistence.provider();
        self.avatar =
            AvatarProfileService::Direct(nazo_identity::AvatarDirectUploadService::from_ports(
                persistence.avatars(),
                persistence.grant_summaries(),
                storage,
                self.capabilities
                    .transient_state
                    .provider()
                    .avatar_upload_state(),
                self.settings.storage.avatar_max_bytes,
                300,
                30,
            ));
        self
    }

    pub fn with_deployment(
        mut self,
        deployment: Arc<crate::capabilities::DeploymentCapabilities>,
    ) -> Self {
        self.deployment = Some(deployment);
        self
    }

    pub fn with_mdoc_crls(
        mut self,
        provider: Arc<dyn crate::capabilities::MdocCrlProvider>,
    ) -> Self {
        self.mdoc_crls = Some(provider);
        self
    }

    pub async fn build(self) -> anyhow::Result<NazoAuth> {
        let Self {
            settings,
            capabilities,
            instance_id,
            avatar,
            deployment,
            mdoc_crls,
        } = self;
        settings.validate()?;
        let password_hasher = capabilities.passwords.hasher.clone();
        let readiness = crate::well_known::ReadinessDependencies::new(
            capabilities.persistence.provider().database_health(),
            capabilities.transient_state.provider().health(),
            capabilities.keys.clone(),
        );
        let persistence = capabilities.persistence.provider();
        let deployment = deployment.map(|capabilities| {
            let deployment_id = capabilities.identity.deployment_id();
            DeploymentServices {
                controller_registry:
                    crate::control::controller_registry::ControllerRegistryService::new(
                        persistence.controller_registry(),
                        deployment_id,
                    ),
                recovery_root: crate::control::recovery_root::RecoveryRootService::new(
                    persistence.recovery_root(),
                    deployment_id,
                ),
                capabilities,
            }
        });
        let runtime_modules = Arc::new(
            RuntimeModules::initialize(
                capabilities
                    .persistence
                    .provider()
                    .runtime_modules(settings.tenant.context.tenant_id.as_uuid()),
                capabilities.module_lifecycle.clone(),
                &settings,
                &instance_id,
            )
            .await?,
        );
        let mtls = Arc::new(MtlsCertificateSource::new(
            settings.endpoint.mtls_certificate_source,
            &settings.endpoint.trusted_proxy_cidrs,
            capabilities.certificate_verifier.clone(),
        ));
        let startup = StartupConfiguration {
            settings: Arc::new(settings),
            capabilities,
            runtime_modules,
            avatar: Arc::new(avatar),
        };
        let core = core::build(&startup).await?;
        let identity = identity::build(&startup, &core).await?;
        Ok(NazoAuth {
            settings: startup.settings,
            core,
            identity,
            runtime_modules: startup.runtime_modules,
            mtls,
            readiness,
            deployment,
            mdoc_crls,
            password_hasher,
        })
    }
}

struct DeploymentServices {
    capabilities: Arc<crate::capabilities::DeploymentCapabilities>,
    controller_registry: crate::control::controller_registry::ControllerRegistryService,
    recovery_root: crate::control::recovery_root::RecoveryRootService,
}

struct StartupConfiguration {
    settings: Arc<Settings>,
    capabilities: Capabilities,
    runtime_modules: Arc<RuntimeModules>,
    avatar: Arc<AvatarProfileService>,
}

impl NazoAuth {
    pub async fn plan_reconciliation(
        &self,
    ) -> Result<
        Vec<nazo_runtime_modules::ModuleId>,
        nazo_runtime_modules::RegistryError<nazo_identity::ports::RepositoryError>,
    > {
        self.runtime_modules.registry.plan_reconciliation().await
    }

    pub async fn reconcile_once(
        &self,
        module: nazo_runtime_modules::ModuleId,
    ) -> Result<
        nazo_runtime_modules::ReconcileOutcome,
        nazo_runtime_modules::RegistryError<nazo_identity::ports::RepositoryError>,
    > {
        self.runtime_modules.registry.reconcile_once(module).await
    }
}

pub struct DummyPasswordHash(pub String);

impl nazo_identity::ports::FederationPasswordHasherPort for DummyPasswordHash {
    fn hash_bootstrap_secret(
        &self,
    ) -> nazo_identity::ports::RepositoryFuture<'_, nazo_identity::ports::PasswordHashInput> {
        Box::pin(async {
            nazo_identity::ports::PasswordHashInput::new(self.0.clone()).map_err(|error| {
                nazo_identity::ports::RepositoryError::Unexpected(error.to_string())
            })
        })
    }
}

impl nazo_oauth_server::contracts::scim::ScimBootstrapPasswordProvider for DummyPasswordHash {
    fn password_hash(
        &self,
    ) -> nazo_oauth_server::contracts::scim::ScimFuture<
        '_,
        Result<
            nazo_identity::ports::PasswordHashInput,
            nazo_oauth_server::contracts::scim::ScimDependencyError,
        >,
    > {
        Box::pin(async {
            nazo_identity::ports::PasswordHashInput::new(self.0.clone())
                .map_err(|_| nazo_oauth_server::contracts::scim::ScimDependencyError::Unavailable)
        })
    }
}
