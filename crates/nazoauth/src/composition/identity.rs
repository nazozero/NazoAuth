use super::StartupConfiguration;
use super::core::CoreServices;
use super::*;
use nazo_oauth_server::services::{
    AccountProfileService, ClientAccessProfileService, FederationProfileService,
    LocalAuthenticationService, LocalFederationService, LocalPasskeyService,
    LocalRegistrationService, MtlsTrustAnchorService, PASSKEY_CEREMONY_TTL_SECONDS,
};

/// Identity, session, administration, and local-login endpoints.  These
/// adapters share session/cookie policy and are kept together so that the
/// factory only has to register the already-composed handles.
pub(super) struct IdentityServices {
    pub(super) profile_logout_endpoint: Arc<SessionLogoutEndpoint>,
    pub(super) runtime_module_admin_endpoint: Arc<RuntimeModuleAdminEndpoint>,
    pub(super) admin_sessions: Arc<AdminSessionHandles>,
    pub(super) authorization_endpoint: Arc<AuthorizationEndpoint>,
    pub(super) admin_federation: Arc<AdminFederationConfig>,
    pub(super) session_profiles: Arc<SessionProfileHandles>,
    pub(super) session_management_endpoint: Arc<SessionManagementEndpoint>,
    pub(super) device_decision_handles: Arc<DeviceDecisionHandles>,
    pub(super) authorization_decision_endpoint: Arc<AuthorizationDecisionEndpoint>,
    pub(super) oidc_logout: Arc<OidcLogoutEndpoint>,
    pub(super) csrf_http_config: Arc<CsrfHttpConfig>,
    pub(super) profile_account_endpoint: Arc<ProfileAccountEndpoint>,
    pub(super) avatar_profiles: Arc<AvatarProfileService>,
    pub(super) profile_access_requests: Arc<ClientAccessProfileService>,
    pub(super) profile_federation: Arc<FederationProfileService>,
    pub(super) admin_users: Arc<dyn nazo_identity::ports::AdminUserRepositoryPort>,
    pub(super) admin_user_registration:
        Arc<dyn nazo_identity::ports::RegistrationAccountRepositoryPort>,
    pub(super) admin_grants: Arc<dyn nazo_auth::AdminGrantRepositoryPort>,
    pub(super) admin_access_requests: Arc<dyn nazo_persistence::AdminAccessRequestStore>,
    pub(super) mtls_trust_anchors: Arc<MtlsTrustAnchorService>,
    pub(super) admin_access_delivery: Arc<dyn nazo_identity::ports::DeliveryStorePort>,
    pub(super) admin_access_request_config: Arc<AdminAccessRequestConfig>,
    pub(super) client_ip_config: Arc<ClientIpConfig>,
    pub(super) mfa_profiles: Arc<MfaProfileEndpoint>,
    pub(super) auth_request_limiter: Arc<AuthRequestLimiter>,
    pub(super) local_registration_endpoint: Arc<LocalRegistrationEndpoint>,
    pub(super) password_login_endpoint: Arc<PasswordLoginEndpoint>,
    pub(super) passkey_login_endpoint: Arc<PasskeyLoginEndpoint>,
    pub(super) passkey_profile_endpoint: Arc<PasskeyProfileEndpoint>,
    pub(super) federation: Arc<LocalFederationService>,
    pub(super) federation_http_config: Arc<FederationHttpConfig>,
    pub(super) federation_sessions: nazo_identity::SessionService,
}

pub(super) async fn build(
    startup: &StartupConfiguration,
    core: &CoreServices,
) -> anyhow::Result<IdentityServices> {
    let settings = startup.settings.as_ref();
    let persistence = startup.capabilities.persistence.provider();
    let transient_state = startup.capabilities.transient_state.provider();
    let runtime_registry = startup.runtime_modules.registry.clone();
    let keyset = startup.capabilities.keys.clone();

    let session = &settings.session;
    let session_http_config = SessionHttpConfig::new(
        &session.session_cookie_name,
        &session.csrf_cookie_name,
        session.cookie_secure,
    );
    let session_cookie_config = SessionCookieConfig::new(
        &session.session_cookie_name,
        &session.csrf_cookie_name,
        session.cookie_secure,
    );
    let identity_session_service = nazo_identity::SessionService::new(
        transient_state.sessions(),
        persistence.session_accounts(),
        settings.tenant.context.tenant_id,
    );
    let profile_logout_endpoint = Arc::new(SessionLogoutEndpoint::new(
        identity_session_service.clone(),
        session_cookie_config.clone(),
        |error| tracing::warn!(%error, "failed to delete session during logout"),
    ));
    let runtime_module_admin_endpoint = Arc::new(RuntimeModuleAdminEndpoint::new(
        identity_session_service.clone(),
        session_cookie_config.clone(),
        startup.runtime_modules.administration(),
    ));
    let session_resolver = Arc::new(nazo_oauth_server::sessions::SessionResolver::new(
        transient_state.sessions(),
        persistence.session_accounts(),
        settings.tenant.context.tenant_id,
    ));
    let admin_sessions = Arc::new(AdminSessionHandles::new(
        session_resolver.clone(),
        session_http_config.clone(),
    ));
    let authorization_application = Arc::new(
        nazo_oauth_server::authorization::AuthorizationApplication::new(
            core.authorization_service.clone(),
            core.security_audit.clone(),
            core.authorization_config.clone(),
            session_resolver.clone(),
            runtime_registry.snapshot_store(),
            startup.capabilities.documents.clone(),
            startup.capabilities.documents.clone(),
            keyset.clone(),
            settings.tenant.context.tenant_id.as_uuid(),
            if settings.modules.enable_openid4vci_issuer {
                Some(
                    persistence.openid4vci_authorization_offers(
                        settings
                            .openid4vc
                            .data_encryption_key
                            .expect("enabled OpenID4VCI requires a data encryption key"),
                        startup.capabilities.passwords.verifier.clone(),
                    ),
                )
            } else {
                None
            },
        ),
    );
    let authorization_endpoint = Arc::new(
        AuthorizationEndpoint::new(
            authorization_application,
            ClientIpConfig::new(
                &settings.endpoint.trusted_proxy_cidrs,
                settings.endpoint.client_ip_header_mode,
            ),
            session_http_config.clone(),
        )
        .with_client_attestation(core.client_attestation_validator.clone()),
    );
    let admin_federation = Arc::new(AdminFederationConfig::from_settings(&startup.settings));
    let session_profiles = Arc::new(SessionProfileHandles::new(
        session_resolver.clone(),
        session_http_config,
    ));
    let session_management_endpoint = Arc::new(SessionManagementEndpoint::new(
        Arc::new(ServerSessionManagementOperations::new(
            session_resolver.clone(),
            persistence.admin_clients(),
            runtime_registry.snapshot_store(),
        )),
        SessionManagementConfig::new(
            settings.endpoint.issuer.as_str(),
            session.session_cookie_name.as_str(),
        ),
    ));
    let oidc_logout_operations = OidcLogoutHandles::new(
        session_resolver,
        persistence.logout_clients(),
        persistence.logout_outbox(),
        keyset,
        OidcLogoutConfig {
            require_fapi2: settings
                .protocol
                .authorization_server_profile
                .requires_fapi2_security(),
            issuer: settings.endpoint.issuer.as_str().into(),
            pairwise_subject_secret: settings
                .protocol
                .pairwise_subject_secret
                .as_deref()
                .map(Into::into),
        },
        runtime_registry.snapshot_store(),
        core.security_audit.clone(),
    );
    let oidc_logout = Arc::new(OidcLogoutEndpoint::new(
        Arc::new(oidc_logout_operations),
        OidcLogoutHttpConfig::new(
            session.session_cookie_name.as_str(),
            session.csrf_cookie_name.as_str(),
            session.cookie_secure,
        ),
    ));
    let csrf_http_config = Arc::new(CsrfHttpConfig::new(
        session.csrf_cookie_name.as_str(),
        session.session_ttl_seconds,
        session.cookie_secure,
    ));
    let account_profile_service = AccountProfileService::from_ports(
        persistence.profiles(),
        persistence.grant_summaries(),
        persistence.authorized_applications(),
    );
    let profile_account_endpoint = Arc::new(ProfileAccountEndpoint::new(
        Arc::new(ServerProfileAccountOperations::new(
            identity_session_service.clone(),
            account_profile_service,
        )),
        session_cookie_config.clone(),
    ));
    let avatar_profiles = startup.avatar.clone();
    let profile_delivery_store = transient_state.delivery();
    let profile_access_requests = Arc::new(ClientAccessProfileService::from_port(
        persistence.access_requests(),
        profile_delivery_store,
        &settings.protocol.client_secret_pepper,
    ));
    let profile_federation = Arc::new(FederationProfileService::from_port(
        persistence.federation_links(),
    ));
    let admin_users: Arc<dyn nazo_identity::ports::AdminUserRepositoryPort> =
        persistence.admin_users();
    let admin_user_registration: Arc<dyn nazo_identity::ports::RegistrationAccountRepositoryPort> =
        persistence.registration_accounts();
    let admin_grants: Arc<dyn nazo_auth::AdminGrantRepositoryPort> = persistence.admin_grants();
    let admin_access_requests: Arc<dyn nazo_persistence::AdminAccessRequestStore> =
        persistence.admin_access_requests();
    let mtls_trust_anchors: Arc<MtlsTrustAnchorService> = persistence.mtls_trust_anchors();
    let admin_access_delivery: Arc<dyn nazo_identity::ports::DeliveryStorePort> =
        transient_state.delivery();
    let protocol = &settings.protocol;
    let storage = &settings.storage;
    let admin_access_request_config = Arc::new(AdminAccessRequestConfig::new(
        &protocol.client_secret_pepper,
        storage.client_delivery_ttl_seconds,
    ));
    let endpoint = &settings.endpoint;
    let client_ip_config = Arc::new(ClientIpConfig::new(
        &endpoint.trusted_proxy_cidrs,
        endpoint.client_ip_header_mode,
    ));
    let authorization_decision_endpoint = Arc::new(AuthorizationDecisionEndpoint::new(
        Arc::new(ServerAuthorizationDecisionOperations::new(
            core.authorization_service.clone(),
            identity_session_service.clone(),
            settings.tenant.context.tenant_id,
            core.authorization_config.clone(),
            runtime_registry.snapshot_store(),
            startup.capabilities.documents.clone(),
            core.security_audit.clone(),
        )),
        session_cookie_config,
        client_ip_config.as_ref().clone(),
    ));
    let identity_settings = &settings.identity;
    let auth_request_limiter = Arc::new(AuthRequestLimiter::new(
        transient_state.request_rate_limits(),
        identity_settings.rate_limit.window_seconds,
        identity_settings.rate_limit.auth_max_requests,
    ));
    let token_management_limiter = Arc::new(TokenManagementRequestLimiter::new(
        transient_state.request_rate_limits(),
        identity_settings.rate_limit.window_seconds,
        identity_settings.rate_limit.token_management_max_requests,
    ));
    let device_decision_handles = Arc::new(DeviceDecisionHandles::new(
        core.authorization_service.clone(),
        core.device_service.clone(),
        core.device_grants.clone(),
        Arc::new(crate::endpoints::token::device_config::device_config_from_settings(settings)),
        runtime_registry.snapshot_store(),
        startup.capabilities.documents.clone(),
        token_management_limiter,
        core.security_audit.clone(),
    ));
    let registration = LocalRegistrationService::from_port(
        persistence.registration_accounts(),
        transient_state.email_verification(),
        startup.capabilities.passwords.hasher.clone(),
        startup.capabilities.email.clone(),
        settings.tenant.context,
        nazo_identity::RegistrationServiceConfig {
            delivery_enabled: identity_settings.email.delivery_enabled,
            send_peer_cooldown_seconds: identity_settings.email.send_peer_cooldown_seconds,
            send_cooldown_seconds: identity_settings.email.send_cooldown_seconds,
            code_ttl_seconds: identity_settings.email.code_ttl_seconds,
        },
    );
    let authentication_rate_limit = Arc::new(ServerAuthenticationRateLimit::new(
        transient_state.request_rate_limits(),
        identity_settings.rate_limit.window_seconds,
        identity_settings.rate_limit.auth_max_requests,
    ));
    let mfa_attempt_throttle: Arc<dyn nazo_identity::ports::MfaAttemptThrottlePort> =
        transient_state.mfa_attempt_throttle();
    let mfa_repository = persistence.mfa_repository();
    let mfa_profiles = Arc::new(MfaProfileEndpoint::new(
        Arc::new(ServerMfaProfileOperations::new(
            nazo_identity::MfaService::new(
                mfa_repository.clone(),
                startup.capabilities.passwords.mfa.clone(),
            ),
            identity_session_service.clone(),
            authentication_rate_limit.clone(),
            mfa_attempt_throttle,
            core.security_audit.clone(),
            identity_settings.rate_limit.mfa_failure_window_seconds,
            identity_settings.rate_limit.mfa_failure_max_attempts,
            settings.endpoint.issuer.as_str(),
            session.session_ttl_seconds,
            MFA_REMEMBERED_TTL_SECONDS,
        )),
        client_ip_config.as_ref().clone(),
        MfaProfileConfig::new(
            session.session_cookie_name.as_str(),
            session.csrf_cookie_name.as_str(),
            MFA_REMEMBERED_COOKIE_NAME,
            session.session_ttl_seconds,
            MFA_REMEMBERED_TTL_SECONDS,
            session.cookie_secure,
        ),
    ));
    let local_registration_endpoint = Arc::new(LocalRegistrationEndpoint::new(
        Arc::new(ServerLocalRegistrationOperations::new(registration)),
        authentication_rate_limit.clone(),
        client_ip_config.as_ref().clone(),
        identity_settings.email_code_dev_response_enabled,
    ));
    let authentication = LocalAuthenticationService::from_ports(
        persistence.login_accounts(),
        transient_state.login_throttle(),
        startup.capabilities.passwords.verifier.clone(),
        persistence.remembered_mfa_devices(),
        transient_state.login_sessions(),
        Arc::new(TracingAuthenticationAudit::new(core.security_audit.clone())),
        nazo_identity::AuthenticationServiceConfig {
            tenant_id: settings.tenant.context.tenant_id,
            dummy_password_hash: nazo_identity::PasswordHash::new(
                startup.capabilities.passwords.dummy_hash.clone(),
            )?,
            failure_window_seconds: identity_settings.rate_limit.login_failure_window_seconds,
            failure_ip_email_max_attempts: identity_settings
                .rate_limit
                .login_failure_ip_email_max_attempts,
            session_ttl_seconds: session.session_ttl_seconds,
            pending_mfa_session_ttl_seconds: session.pending_mfa_session_ttl_seconds,
        },
    );
    let password_login_endpoint = Arc::new(PasswordLoginEndpoint::new(
        Arc::new(ServerPasswordLoginOperations::new(authentication)),
        authentication_rate_limit.clone(),
        client_ip_config.as_ref().clone(),
        PasswordLoginConfig::new(
            settings.endpoint.issuer.as_str(),
            settings.endpoint.frontend_base_url.as_str(),
            session.session_cookie_name.as_str(),
            session.csrf_cookie_name.as_str(),
            MFA_REMEMBERED_COOKIE_NAME,
            session.session_ttl_seconds,
            session.cookie_secure,
        ),
    ));
    let passkey = &identity_settings.passkey;
    let passkey_operations = Arc::new(PasskeyOperationsProvider::new(
        LocalPasskeyService::from_ports(
            persistence.passkey_accounts(),
            persistence.passkeys(),
            transient_state.passkey_ceremonies(),
            persistence.remembered_mfa_devices(),
            transient_state.login_sessions(),
            Arc::new(TracingPasskeyAudit::new(core.security_audit.clone())),
            nazo_identity::PasskeyServiceConfig {
                tenant_id: settings.tenant.context.tenant_id,
                rp_id: passkey.rp_id.to_owned(),
                rp_name: passkey.rp_name.to_owned(),
                origin: passkey.origin.to_owned(),
                require_user_verification: passkey.require_user_verification,
                require_user_handle: passkey.require_user_handle,
                ceremony_ttl_seconds: PASSKEY_CEREMONY_TTL_SECONDS,
                session_ttl_seconds: session.session_ttl_seconds,
                pending_mfa_session_ttl_seconds: session.pending_mfa_session_ttl_seconds,
            },
        ),
        identity_session_service.clone(),
    ));
    let passkey_login_endpoint = Arc::new(PasskeyLoginEndpoint::new(
        passkey_operations.clone(),
        authentication_rate_limit,
        client_ip_config.as_ref().clone(),
        PasskeyLoginConfig::new(
            session.session_cookie_name.as_str(),
            session.csrf_cookie_name.as_str(),
            MFA_REMEMBERED_COOKIE_NAME,
            session.session_ttl_seconds,
            session.cookie_secure,
        ),
    ));
    let passkey_profile_endpoint = Arc::new(PasskeyProfileEndpoint::new(
        passkey_operations,
        PasskeyProfileConfig::new(
            session.session_cookie_name.as_str(),
            session.csrf_cookie_name.as_str(),
            session.cookie_secure,
        ),
    ));
    let federation = Arc::new(LocalFederationService::from_port(
        persistence.federation_logins(),
        transient_state.federation_state(),
        Arc::new(DummyPasswordHash(
            startup.capabilities.passwords.dummy_hash.clone(),
        )),
        transient_state.login_sessions(),
        Arc::new(TracingFederationAudit::new(core.security_audit.clone())),
        nazo_identity::FederationServiceConfig {
            tenant: settings.tenant.context,
            state_ttl_seconds: FEDERATION_STATE_TTL_SECONDS,
            saml_replay_ttl_seconds: SAML_REPLAY_TTL_SECONDS,
            session_ttl_seconds: session.session_ttl_seconds,
            pending_mfa_session_ttl_seconds: session.pending_mfa_session_ttl_seconds,
        },
    ));
    let federation_http_config = Arc::new(FederationHttpConfig::new(
        &identity_settings.federation,
        startup.capabilities.federation_http.clone(),
        session,
    ));

    Ok(IdentityServices {
        profile_logout_endpoint,
        runtime_module_admin_endpoint,
        admin_sessions,
        authorization_endpoint,
        admin_federation,
        session_profiles,
        session_management_endpoint,
        device_decision_handles,
        authorization_decision_endpoint,
        oidc_logout,
        csrf_http_config,
        profile_account_endpoint,
        avatar_profiles,
        profile_access_requests,
        profile_federation,
        admin_users,
        admin_user_registration,
        admin_grants,
        admin_access_requests,
        mtls_trust_anchors,
        admin_access_delivery,
        admin_access_request_config,
        client_ip_config,
        mfa_profiles,
        auth_request_limiter,
        local_registration_endpoint,
        password_login_endpoint,
        passkey_login_endpoint,
        passkey_profile_endpoint,
        federation,
        federation_http_config,
        federation_sessions: identity_session_service,
    })
}
