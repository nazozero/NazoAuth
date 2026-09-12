use super::super::configuration::StartupConfiguration;
use super::*;
use crate::http::mtls::MtlsCertificateSourceMode;
use nazo_auth::{CibaMetadataProfile, MetadataAuthorizationServerProfile, MetadataSubjectType};
use nazo_oauth_server::domain::dynamic_registration::{
    DynamicRegistrationApplication, ServerDynamicRegistrationRequestGuard,
    ServerDynamicRegistrationTokens,
};
use nazo_oauth_server::domain::metadata::ApplicationMetadataSnapshotSource;
use nazo_oauth_server::domain::openid4vc::client_attestation::Openid4vcClientAttestationValidator;
use nazo_oauth_server::policy::{CibaSecurityProfile, SubjectType};
use nazo_oauth_server::services::{
    ServerAuthorizationService, ServerCibaService, ServerDeviceGrantService,
};

mod openid4vc;

/// Request-facing protocol and OAuth service handles.  Each handle is built
/// once outside the Actix worker factory and cloned into worker applications.
#[derive(Clone)]
pub(super) struct CoreServices {
    pub(super) security_audit: Arc<dyn nazo_oauth_server::ports::audit::SecurityAudit>,
    pub(super) metadata_handles: web::Data<nazo_http_actix::MetadataHandles>,
    pub(super) resource_server_http_data: web::Data<nazo_http_actix::FapiResourceEndpoint>,
    pub(super) dynamic_registration_handles:
        web::Data<nazo_http_actix::DynamicRegistrationEndpoint>,
    pub(super) admin_client_config: web::Data<AdminClientConfig>,
    pub(super) admin_client_service: web::Data<ServerAdminClientService>,
    pub(super) scim_endpoint: web::Data<nazo_http_actix::ScimEndpoint>,
    pub(super) authorization_service: web::Data<ServerAuthorizationService>,
    pub(super) token_service: web::Data<nazo_oauth_server::services::ServerTokenService>,
    pub(super) ciba_application: web::Data<nazo_oauth_server::token::ciba::CibaApplication>,
    pub(super) token_issuance_config: web::Data<TokenIssuanceConfig>,
    pub(super) device_service: web::Data<ServerDeviceGrantService>,
    pub(super) device_grants: web::Data<dyn nazo_auth::DeviceGrantRepositoryPort>,
    pub(super) device_config: web::Data<DeviceHttpConfig>,
    pub(super) userinfo_endpoint: web::Data<nazo_http_actix::UserinfoEndpoint>,
    pub(super) authorization_config: web::Data<AuthorizationConfig>,
    #[cfg(not(test))]
    pub(super) token_management_endpoint: web::Data<nazo_http_actix::TokenManagementEndpoint>,
    pub(super) authorization_runtime: web::Data<ServerRuntimeModuleRegistry>,
    pub(super) credential_issuer_endpoint: Option<web::Data<CredentialIssuerEndpoint>>,
    pub(super) credential_dataset_admin: Option<web::Data<CredentialDatasetAdminService>>,
    pub(super) presentation_endpoint: Option<web::Data<PresentationEndpoint>>,
    pub(super) client_attestation_validator: Option<Arc<Openid4vcClientAttestationValidator>>,
    pub(super) token_endpoint_handles: web::Data<TokenEndpointHandles>,
}

pub(super) async fn build(startup: &StartupConfiguration) -> anyhow::Result<CoreServices> {
    let settings = startup.settings.as_ref();
    let security_audit: Arc<dyn nazo_oauth_server::ports::audit::SecurityAudit> = Arc::new(
        crate::adapters::audit::TenantSecurityAudit::new(settings.tenant.context.tenant_id),
    );
    let persistence = startup.persistence.provider();
    let transient_state = startup.transient_state.provider();
    let keyset = startup.keyset.clone();
    let runtime_registry = startup.runtime_modules.registry.clone();
    let remote_client_documents = startup.remote_client_documents.clone();

    let metadata_config = metadata_config(settings);
    let metadata_handles = web::Data::new(nazo_http_actix::MetadataHandles::new(
        metadata_config.endpoint_config(),
        Arc::new(ApplicationMetadataSnapshotSource::new(
            keyset.clone(),
            runtime_registry.snapshot_store(),
        )),
    ));
    let resource_server_config = resource_server_config(settings);
    tracing::info!(
        dpop_nonce_policy = ?settings.protocol.dpop_nonce_policy,
        fapi_resource_dpop_nonce_policy = ?settings.protocol.fapi_resource_dpop_nonce_policy,
        "loaded DPoP nonce policies"
    );
    let resource_server_http_data = {
        let authorizer = Arc::new(ServerFapiResourceAuthorizer::from_port(
            resource_server_config.clone(),
            keyset.clone(),
            persistence.access_token_revocations(),
            transient_state.protected_resource_dpop_state(),
        ));
        let mtls = Arc::new(ServerMtlsThumbprintExtractor::new(
            settings.endpoint.trusted_proxy_cidrs.clone(),
        ));
        let signatures = Arc::new(ServerFapiHttpMessageSignatures::from_port(
            persistence.admin_clients(),
            transient_state.fapi_http_signature_replay(),
            keyset.clone(),
            runtime_registry.snapshot_store(),
            resource_server_config.fapi_http_signature_max_age_seconds,
        ));
        web::Data::new(nazo_http_actix::FapiResourceEndpoint::new(
            resource_server_config.issuer.clone(),
            resource_server_config.mtls_endpoint_base_url.clone(),
            resource_server_config.fapi_http_signature_max_age_seconds,
            authorizer,
            mtls,
            signatures,
        ))
    };
    let dynamic_registration_config = dynamic_registration_config(settings, &keyset);
    let registration_crypto = Arc::new(nazo_key_management::ClientRegistrationCrypto::new(
        keyset.clone(),
    ));
    let registration_guard = Arc::new(ServerDynamicRegistrationRequestGuard::new(
        transient_state.request_rate_limits(),
        &dynamic_registration_config,
        runtime_registry.snapshot_store(),
        security_audit.clone(),
    ));
    let registration_application = Arc::new(DynamicRegistrationApplication::new(
        dynamic_registration_config, persistence.dynamic_registration_clients(),
        remote_client_documents.clone(),
        nazo_oauth_server::contracts::dynamic_client_registration::DynamicRegistrationSecurityServices::new(
            remote_client_documents.clone(), registration_crypto.clone(), registration_crypto,
            Arc::new(ServerDynamicRegistrationTokens),
        ), registration_guard,
    ));
    let dynamic_registration_handles =
        web::Data::new(nazo_http_actix::DynamicRegistrationEndpoint::new(
            registration_application,
            ClientIpConfig::new(
                &settings.endpoint.trusted_proxy_cidrs,
                settings.endpoint.client_ip_header_mode,
            ),
        ));
    let admin_client_config = web::Data::new(AdminClientConfig::from_settings(&startup.settings));
    let admin_client_service = web::Data::new(ServerAdminClientService::new(
        persistence.admin_clients(),
        remote_client_documents.as_ref().clone(),
        ServerAdminClientCrypto::new(keyset.clone()),
        admin_client_policy(&startup.settings),
    ));
    let scim_endpoint_settings = &startup.settings.endpoint;
    let scim_protocol = &startup.settings.protocol;
    let scim_storage = &startup.settings.storage;
    let scim_service = nazo_identity::scim::ScimService::new(
        persistence.scim_repository(scim_storage.scim_event_retention_seconds),
        persistence.scim_credential_audit(),
    );
    let scim_client_ip = ClientIpConfig::new(
        &scim_endpoint_settings.trusted_proxy_cidrs,
        scim_endpoint_settings.client_ip_header_mode,
    );
    let scim_endpoint = web::Data::new(
        nazo_http_actix::ScimEndpoint::new(
            scim_service.clone(),
            Arc::new(ServerScimRequestAuthorizer::new(
                scim_service,
                settings.tenant.context,
                runtime_registry.snapshot_store(),
                security_audit.clone(),
            )),
            Arc::new(ServerScimCursorProtector::new(
                &scim_protocol.client_secret_pepper,
            )?),
            Arc::new(ServerScimBootstrapPasswordProvider),
            scim_client_ip,
        )
        .with_security_events(Arc::new(nazo_scim_events::EventPublisher::from_port(
            persistence.scim_event_store(),
            ServerScimEventSigner::new(keyset.clone()),
            startup.settings.endpoint.issuer.clone(),
        ))),
    );
    let authorization_service = web::Data::new(ServerAuthorizationService::from_port(
        persistence.authorization_repository(settings.tenant.context.tenant_id.as_uuid()),
        transient_state.authorization_state(),
        keyset.clone(),
    ));
    let token_issuance_repository =
        persistence.token_repository(startup.token_issuance_response_keys.clone());
    token_issuance_repository
        .validate_response_key_ring()
        .await
        .map_err(|error| {
            anyhow::anyhow!("token issuance response key-ring preflight failed: {error}")
        })?;
    let token_service = web::Data::new(nazo_oauth_server::services::ServerTokenService::from_port(
        token_issuance_repository,
        transient_state.token_state(),
        keyset.clone(),
    ));
    let ciba_handles = CibaTokenHandles::new(
        Arc::new(ServerCibaService::new(transient_state.ciba_state())),
        persistence.ciba_accounts(),
        Arc::new(ciba_config(settings)),
    );
    let ciba_application = web::Data::new(nazo_oauth_server::token::ciba::CibaApplication::new(
        authorization_service.clone().into_inner(),
        Arc::new(ciba_handles.clone()),
        remote_client_documents.clone(),
        runtime_registry.snapshot_store(),
        security_audit.clone(),
    ));
    let token_issuance_config = web::Data::new(token_issuance_config(settings));
    let device_service = web::Data::new(ServerDeviceGrantService::new(
        transient_state.device_state(),
    ));
    let device_grants: web::Data<dyn nazo_auth::DeviceGrantRepositoryPort> = web::Data::from(
        persistence.device_grant_repository(settings.tenant.context.tenant_id.as_uuid()),
    );
    let device_config = web::Data::new(DeviceHttpConfig::from(settings));
    let userinfo_handles = UserinfoHandles::new(
        transient_state.dpop_state(),
        security_audit.clone(),
        keyset.clone(),
        UserinfoConfig::new(
            settings.endpoint.issuer.as_str(),
            settings.protocol.default_audience.as_str(),
            settings.endpoint.mtls_endpoint_base_url.as_str(),
            settings.protocol.dpop_nonce_policy,
        ),
        remote_client_documents.clone(),
    );
    let userinfo_endpoint = web::Data::new(nazo_http_actix::UserinfoEndpoint::new(
        Arc::new(ServerUserinfoOperations::new(
            token_service.clone().into_inner(),
            userinfo_handles,
        )),
        Arc::new(ServerMtlsThumbprintExtractor::new(
            settings.endpoint.trusted_proxy_cidrs.clone(),
        )),
    ));
    let authorization_config = web::Data::new(authorization_config(settings));
    #[cfg(not(test))]
    let token_management_endpoint = web::Data::new(nazo_http_actix::TokenManagementEndpoint::new(
        Arc::new(ServerTokenManagementRequestFactsExtractor::new(
            ClientIpConfig::new(
                &settings.endpoint.trusted_proxy_cidrs,
                settings.endpoint.client_ip_header_mode,
            ),
        )),
        Arc::new(ServerTokenManagementRequestGuard::new(
            token_service.clone().into_inner(),
            authorization_config.clone().into_inner(),
        )),
        Arc::new(ServerTokenManagementOperations::new(
            token_service.clone().into_inner(),
            authorization_service.clone().into_inner(),
            authorization_config.clone().into_inner(),
            remote_client_documents.clone(),
            security_audit.clone(),
        )),
    ));
    let authorization_runtime: web::Data<ServerRuntimeModuleRegistry> =
        web::Data::from(runtime_registry.clone());

    let openid4vc = openid4vc::build(
        startup,
        &token_service,
        &authorization_service,
        runtime_registry,
        &keyset,
    )
    .await?;
    let openid4vc::Openid4vcServices {
        credential_issuer_operations,
        credential_issuer_endpoint,
        credential_dataset_admin,
        presentation_endpoint,
        client_attestation_validator,
    } = openid4vc;
    let token_endpoint_handles = web::Data::new(TokenEndpointHandles::new(
        TokenCoreHandles {
            security_audit: security_audit.clone(),
            token_service: token_service.clone().into_inner(),
            authorization_service: authorization_service.clone().into_inner(),
            device_service: device_service.clone().into_inner(),
        },
        ciba_handles,
        token_issuance_config.clone().into_inner(),
        authorization_runtime.snapshot_store(),
        remote_client_documents,
        Openid4vcTokenHandles {
            credential_issuer: credential_issuer_operations,
            client_attestation: client_attestation_validator.clone(),
        },
    ));

    Ok(CoreServices {
        security_audit,
        metadata_handles,
        resource_server_http_data,
        dynamic_registration_handles,
        admin_client_config,
        admin_client_service,
        scim_endpoint,
        authorization_service,
        token_service,
        ciba_application,
        token_issuance_config,
        device_service,
        device_grants,
        device_config,
        userinfo_endpoint,
        authorization_config,
        #[cfg(not(test))]
        token_management_endpoint,
        authorization_runtime,
        credential_issuer_endpoint,
        credential_dataset_admin,
        presentation_endpoint,
        client_attestation_validator,
        token_endpoint_handles,
    })
}

fn metadata_config(settings: &Settings) -> MetadataConfig {
    let endpoint = &settings.endpoint;
    let protocol = &settings.protocol;
    MetadataConfig {
        issuer: endpoint.issuer.clone(),
        mtls_endpoint_base_url: endpoint.mtls_endpoint_base_url.clone(),
        mtls_enabled: endpoint.mtls_certificate_source != MtlsCertificateSourceMode::Disabled,
        authorization_server_profile: MetadataAuthorizationServerProfile::Composable,
        ciba_security_profile: match protocol.ciba_security_profile {
            CibaSecurityProfile::FapiCibaId1 => CibaMetadataProfile::FapiCiba,
            CibaSecurityProfile::Fapi2Ciba => CibaMetadataProfile::Fapi2Ciba,
        },
        subject_type: match protocol.subject_type {
            SubjectType::Public => MetadataSubjectType::Public,
            SubjectType::Pairwise => MetadataSubjectType::Pairwise,
        },
        pairwise_subject_enabled: protocol.pairwise_subject_secret.is_some(),
        protected_resource_identifier: protocol.protected_resource_identifier.to_owned(),
        require_pushed_authorization_requests: protocol.require_pushed_authorization_requests,
    }
}

fn dynamic_registration_config(
    settings: &Settings,
    keyset: &nazo_key_management::KeyManager,
) -> DynamicRegistrationConfig {
    let keys = keyset.snapshot();
    DynamicRegistrationConfig {
        tenant: settings.tenant.context,
        issuer: settings.endpoint.issuer.clone(),
        default_audience: settings.protocol.default_audience.clone(),
        pairwise_subject_secret: settings.protocol.pairwise_subject_secret.clone(),
        client_secret_pepper: settings.protocol.client_secret_pepper.clone(),
        initial_access_token: settings
            .modules
            .dynamic_client_registration_initial_access_token
            .clone(),
        rate_limit_window_seconds: settings.identity.rate_limit.window_seconds,
        rate_limit_max_requests: settings.identity.rate_limit.token_management_max_requests,
        id_token_signing_algs: keys.id_token_signing_alg_values_supported(),
        response_signing_algs: keys.response_signing_alg_values_supported(),
        request_object_encryption_algs: vec!["RSA-OAEP-256"],
        request_object_encryption_encs: vec!["A256GCM"],
    }
}

#[cfg(test)]
#[path = "../../../../tests/unit/domain/metadata.rs"]
mod metadata_config_tests;

fn resource_server_config(settings: &Settings) -> ResourceServerConfig {
    ResourceServerConfig {
        issuer: settings.endpoint.issuer.clone(),
        mtls_endpoint_base_url: settings.endpoint.mtls_endpoint_base_url.clone(),
        default_audience: settings.protocol.default_audience.clone(),
        protected_resource_identifier: settings.protocol.protected_resource_identifier.clone(),
        dpop_nonce_policy: settings.protocol.fapi_resource_dpop_nonce_policy,
        fapi_http_signature_max_age_seconds: settings.protocol.fapi_http_signature_max_age_seconds,
    }
}

#[cfg(test)]
#[path = "../../../../tests/unit/domain/dynamic_registration.rs"]
mod dynamic_registration_config_tests;
