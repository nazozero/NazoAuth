use super::StartupConfiguration;
use super::*;
use crate::config::MtlsCertificateSourceMode;
use nazo_auth::{CibaMetadataProfile, MetadataAuthorizationServerProfile};
use nazo_oauth_server::domain::dynamic_registration::{
    DynamicRegistrationApplication, ServerDynamicRegistrationRequestGuard,
    ServerDynamicRegistrationTokens,
};
use nazo_oauth_server::domain::metadata::ApplicationMetadataSnapshotSource;
use nazo_oauth_server::domain::openid4vc::client_attestation::Openid4vcClientAttestationValidator;
use nazo_oauth_server::policy::CibaSecurityProfile;
use nazo_oauth_server::services::{
    ServerAuthorizationService, ServerCibaService, ServerDeviceGrantService,
};

use super::openid4vc;

/// Immutable protocol services built once for the selected tenant.
pub(super) struct CoreServices {
    pub(super) security_audit: Arc<dyn nazo_oauth_server::ports::audit::SecurityAudit>,
    pub(super) metadata_handles: Arc<crate::http::MetadataHandles>,
    pub(super) resource_server_http_data: Arc<crate::http::FapiResourceEndpoint>,
    pub(super) dynamic_registration_handles: Arc<crate::http::DynamicRegistrationEndpoint>,
    pub(super) admin_client_config: Arc<AdminClientConfig>,
    pub(super) admin_client_service: Arc<ServerAdminClientService>,
    pub(super) scim_endpoint: Arc<crate::http::ScimEndpoint>,
    pub(super) authorization_service: Arc<ServerAuthorizationService>,
    pub(super) ciba_application: Arc<nazo_oauth_server::token::ciba::CibaApplication>,
    pub(super) device_service: Arc<ServerDeviceGrantService>,
    pub(super) device_grants: Arc<dyn nazo_auth::DeviceGrantRepositoryPort>,
    pub(super) device_config: Arc<DeviceHttpConfig>,
    pub(super) userinfo_endpoint: Arc<crate::http::UserinfoEndpoint>,
    pub(super) authorization_config: Arc<AuthorizationConfig>,
    pub(super) token_management_endpoint: Arc<crate::http::TokenManagementEndpoint>,
    pub(super) credential_issuer_endpoint: Option<Arc<CredentialIssuerEndpoint>>,
    pub(super) credential_dataset_admin: Option<Arc<CredentialDatasetAdminService>>,
    pub(super) presentation_endpoint: Option<Arc<PresentationEndpoint>>,
    pub(super) client_attestation_validator: Option<Arc<Openid4vcClientAttestationValidator>>,
    pub(super) token_endpoint_handles: Arc<TokenEndpointHandles>,
}

pub(super) async fn build(startup: &StartupConfiguration) -> anyhow::Result<CoreServices> {
    let settings = startup.settings.as_ref();
    let security_audit = startup.capabilities.audit.clone();
    let persistence = startup.capabilities.persistence.provider();
    let transient_state = startup.capabilities.transient_state.provider();
    let keyset = startup.capabilities.keys.clone();
    let runtime_registry = startup.runtime_modules.registry.clone();
    let remote_client_documents = startup.capabilities.documents.clone();

    let metadata_config = metadata_config(settings);
    let metadata_handles = Arc::new(crate::http::MetadataHandles::new(
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
        let mtls = Arc::new(ServerMtlsThumbprintExtractor);
        let signatures = Arc::new(ServerFapiHttpMessageSignatures::from_port(
            persistence.admin_clients(),
            transient_state.fapi_http_signature_replay(),
            keyset.clone(),
            runtime_registry.snapshot_store(),
            resource_server_config.fapi_http_signature_max_age_seconds,
        ));
        Arc::new(crate::http::FapiResourceEndpoint::new(
            resource_server_config.issuer.clone(),
            resource_server_config.mtls_endpoint_base_url.clone(),
            resource_server_config.fapi_http_signature_max_age_seconds,
            Arc::new(ServerFapiResourceAuthorizer::from_port(
                resource_server_config,
                keyset.clone(),
                persistence.access_token_revocations(),
                transient_state.protected_resource_dpop_state(),
            )),
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
    let dynamic_registration_handles = Arc::new(crate::http::DynamicRegistrationEndpoint::new(
        registration_application,
        ClientIpConfig::new(
            &settings.endpoint.trusted_proxy_cidrs,
            settings.endpoint.client_ip_header_mode,
        ),
    ));
    let admin_client_config = Arc::new(AdminClientConfig::from_settings(&startup.settings));
    let admin_client_service = Arc::new(ServerAdminClientService::new(
        persistence.admin_clients(),
        remote_client_documents.clone() as Arc<dyn nazo_auth::SectorIdentifierResolverPort>,
        ServerAdminClientCrypto::new(keyset.clone()),
        admin_client_policy(&startup.settings),
    ));
    let scim_endpoint_settings = &startup.settings.endpoint;
    let scim_protocol = &startup.settings.protocol;
    let scim_storage = &startup.settings.storage;
    let scim_service = nazo_identity::scim::ScimService::new(
        persistence.scim_repository(scim_storage.scim_event_retention_seconds),
        persistence.scim_credentials(),
    );
    let scim_client_ip = ClientIpConfig::new(
        &scim_endpoint_settings.trusted_proxy_cidrs,
        scim_endpoint_settings.client_ip_header_mode,
    );
    let scim_endpoint = Arc::new(
        crate::http::ScimEndpoint::new(
            scim_service.clone(),
            Arc::new(ServerScimRequestAuthorizer::new(
                scim_service,
                settings.tenant.context,
                runtime_registry.snapshot_store(),
                security_audit.clone(),
                transient_state.request_rate_limits(),
                settings.identity.rate_limit.window_seconds,
                settings.identity.rate_limit.scim_denial_max_requests,
            )),
            Arc::new(ServerScimCursorProtector::new(
                &scim_protocol.client_secret_pepper,
            )?),
            Arc::new(DummyPasswordHash(
                startup.capabilities.passwords.dummy_hash.clone(),
            )),
            scim_client_ip,
        )
        .with_security_events(startup.capabilities.scim_events.clone()),
    );
    let authorization_service = Arc::new(ServerAuthorizationService::from_port(
        persistence.authorization_repository(settings.tenant.context.tenant_id.as_uuid()),
        transient_state.authorization_state(),
        keyset.clone(),
    ));
    let token_issuance_repository = persistence.token_repository();
    let token_service = Arc::new(nazo_oauth_server::services::ServerTokenService::from_port(
        token_issuance_repository,
        transient_state.token_state(),
        keyset.clone(),
    ));
    let ciba_handles = CibaTokenHandles::new(
        Arc::new(ServerCibaService::new(transient_state.ciba_state())),
        persistence.ciba_accounts(),
        Arc::new(ciba_config(settings)),
    );
    let ciba_application = Arc::new(nazo_oauth_server::token::ciba::CibaApplication::new(
        authorization_service.clone(),
        Arc::new(ciba_handles.clone()),
        remote_client_documents.clone(),
        runtime_registry.snapshot_store(),
        security_audit.clone(),
    ));
    let token_issuance_config = Arc::new(token_issuance_config(settings));
    let device_service = Arc::new(ServerDeviceGrantService::new(
        transient_state.device_state(),
    ));
    let device_grants: Arc<dyn nazo_auth::DeviceGrantRepositoryPort> =
        persistence.device_grant_repository(settings.tenant.context.tenant_id.as_uuid());
    let device_config = Arc::new(DeviceHttpConfig::from(settings));
    let userinfo_handles = UserinfoHandles::new(
        transient_state.dpop_state(),
        security_audit.clone(),
        keyset.clone(),
        UserinfoConfig::new(
            settings.endpoint.issuer.as_str(),
            settings.protocol.default_audience.as_str(),
            settings.endpoint.mtls_endpoint_base_url.as_str(),
            settings.protocol.dpop_nonce_policy,
            settings
                .protocol
                .authorization_server_profile
                .requires_fapi2_security(),
        ),
        remote_client_documents.clone(),
    );
    let userinfo_endpoint = Arc::new(crate::http::UserinfoEndpoint::new(
        Arc::new(ServerUserinfoOperations::new(
            token_service.clone(),
            userinfo_handles,
        )),
        Arc::new(ServerMtlsThumbprintExtractor),
    ));
    let authorization_config = Arc::new(authorization_config(settings));
    let token_management_endpoint = Arc::new(crate::http::TokenManagementEndpoint::new(
        Arc::new(ServerTokenManagementRequestFactsExtractor::new(
            ClientIpConfig::new(
                &settings.endpoint.trusted_proxy_cidrs,
                settings.endpoint.client_ip_header_mode,
            ),
        )),
        Arc::new(ServerTokenManagementRequestGuard::new(
            token_service.clone(),
            authorization_config.clone(),
        )),
        Arc::new(ServerTokenManagementOperations::new(
            token_service.clone(),
            authorization_service.clone(),
            authorization_config.clone(),
            remote_client_documents.clone(),
            security_audit.clone(),
        )),
    ));
    let authorization_runtime: Arc<ServerRuntimeModuleRegistry> = runtime_registry.clone();

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
    let token_endpoint_handles = Arc::new(TokenEndpointHandles::new(
        TokenCoreHandles {
            security_audit: security_audit.clone(),
            token_service: token_service.clone(),
            authorization_service: authorization_service.clone(),
            device_service: device_service.clone(),
        },
        ciba_handles,
        token_issuance_config.clone(),
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
        ciba_application,
        device_service,
        device_grants,
        device_config,
        userinfo_endpoint,
        authorization_config,
        token_management_endpoint,
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
        backchannel_logout_supported: settings.protocol.backchannel_logout_supported,
        issuer: endpoint.issuer.clone(),
        mtls_endpoint_base_url: endpoint.mtls_endpoint_base_url.clone(),
        mtls_enabled: endpoint.mtls_certificate_source != MtlsCertificateSourceMode::Disabled,
        authorization_server_profile: MetadataAuthorizationServerProfile::Composable,
        ciba_security_profile: match protocol.ciba_security_profile {
            CibaSecurityProfile::FapiCibaId1 => CibaMetadataProfile::FapiCiba,
            CibaSecurityProfile::Fapi2Ciba => CibaMetadataProfile::Fapi2Ciba,
        },
        pairwise_subject_enabled: protocol.pairwise_subject_secret.is_some(),
        protected_resource_identifier: protocol.protected_resource_identifier.to_owned(),
        additional_scopes_supported: protocol.additional_scopes_supported.clone(),
        credential_scopes: settings
            .openid4vc
            .credential_configurations
            .values()
            .filter_map(|configuration| configuration.scope.clone())
            .collect(),
        require_pushed_authorization_requests: protocol.require_pushed_authorization_requests,
    }
}

fn dynamic_registration_config(
    settings: &Settings,
    keyset: &nazo_key_management::KeyManager,
) -> DynamicRegistrationConfig {
    let keys = keyset.snapshot();
    DynamicRegistrationConfig {
        capabilities: settings
            .modules
            .dynamic_client_registration_capabilities
            .clone(),
        require_fapi2: settings
            .protocol
            .authorization_server_profile
            .requires_fapi2_security(),
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
#[path = "../../tests/unit/composition/metadata.rs"]
mod metadata_tests;

#[cfg(test)]
#[path = "../../tests/unit/composition/dynamic_registration.rs"]
mod dynamic_registration_tests;
