//! 应用启动入口。
// 负责组装配置、外部连接、共享状态和 Actix HTTP server。

mod authentication_services;
mod cors;
mod federation_services;
mod observability;
mod passkey_services;
mod profile_services;
mod registration_services;
pub(crate) mod routes;
pub(crate) use authentication_services::{
    LocalAuthenticationService, LoginPasswordVerifier, TracingAuthenticationAudit,
};
pub(crate) use federation_services::{
    FederationBootstrapPasswordHasher, LocalFederationService, TracingFederationAudit,
};
pub(crate) use passkey_services::{
    LocalPasskeyService, PASSKEY_CEREMONY_TTL_SECONDS, TracingPasskeyAudit,
};
pub(crate) use profile_services::{
    AccountProfileService, AvatarProfileService, ClientAccessProfileService,
    FederationProfileService,
};
pub(crate) use registration_services::{LocalRegistrationService, RegistrationSecretHasher};

use std::{net::SocketAddr, sync::Arc, time::Duration};

use actix_web::{App, HttpServer, dev::Service, middleware::from_fn, web};

use crate::config::{ConfigSource, database_max_connections, database_url};
use crate::domain::{
    DynamicRegistrationConfig, DynamicRegistrationHandles, MetadataConfig, MetadataHandles,
    MfaProfileConfig, MfaProfileHandles, OidcLogoutConfig, OidcLogoutHandles, ResourceServerConfig,
    ResourceServerHandles, UserinfoConfig, UserinfoHandles,
};
use crate::http::admin::access_requests::AdminAccessRequestConfig;
use crate::http::admin::clients::{
    AdminClientConfig, ServerAdminClientCrypto, ServerAdminClientService,
    ServerSectorIdentifierResolver, admin_client_policy,
};
use crate::http::admin::federation::AdminFederationConfig;
use crate::http::auth::csrf::CsrfHttpConfig;
use crate::http::auth::email_code::EmailCodeHttpConfig;
use crate::http::auth::federation::{
    FEDERATION_STATE_TTL_SECONDS, FederationHttpConfig, SAML_REPLAY_TTL_SECONDS,
};
use crate::http::auth::login::LoginHttpConfig;
use crate::http::auth::passkey::PasskeyHttpConfig;
use crate::http::authorization::{AuthorizationHttpConfig, ServerAuthorizationService};
#[cfg(not(test))]
use crate::http::profile::oidc_logout::spawn_backchannel_logout_delivery_worker;
use crate::http::scim::{ScimConfig, ScimEndpoint, ScimRuntimeAdmission};
use crate::http::token::ciba::{CibaHttpConfig, CibaTokenHandles, ServerCibaService};
use crate::http::token::device::{DeviceDecisionHandles, ServerDeviceGrantService};
use crate::http::token::device_config::DeviceHttpConfig;
use crate::http::token::dispatch::TokenEndpointHandles;
use crate::http::token::issue::TokenIssuanceConfig;
use crate::runtime_modules::{RuntimeModules, ServerRuntimeModuleRegistry};
use crate::settings::Settings;
use crate::support::client_ip::ClientIpConfig;
use crate::support::sessions::{AdminSessionHandles, SessionHttpConfig, SessionProfileHandles};
use crate::support::{
    AuthRequestLimiter, SmtpVerificationEmailDelivery, TokenManagementRequestLimiter,
    configure_password_hash_limits, default_password_hash_max_concurrency,
    default_password_hash_queue_timeout_ms, default_tenant_context, dummy_password_hash,
    email_delivery_configured, initialize_dummy_password_hash,
};
#[cfg(test)]
use actix_web::http::header;
use nazo_http_actix::security_headers;
use nazo_postgres::create_pool;
use tracing::Instrument;

pub async fn run() -> anyhow::Result<()> {
    let config = ConfigSource::load()?;
    let _observability = observability::init(&config)?;
    let perf_metrics_enabled = config.bool("PERF_METRICS_ENABLED", false)?;
    let password_hash_max_concurrency = config.parse::<usize>(
        "PASSWORD_HASH_MAX_CONCURRENCY",
        default_password_hash_max_concurrency(),
    )?;
    let password_hash_queue_timeout_ms = config.parse::<u64>(
        "PASSWORD_HASH_QUEUE_TIMEOUT_MS",
        default_password_hash_queue_timeout_ms(),
    )?;
    configure_password_hash_limits(
        password_hash_max_concurrency,
        password_hash_queue_timeout_ms,
    )?;
    initialize_dummy_password_hash()?;

    // 配置只在启动阶段读取；运行期只向 handler 注入其所需的 focused handles。
    let database_url = database_url(&config);
    let valkey_url = config.string("VALKEY_URL", "redis://127.0.0.1:6379/0");
    let valkey_command_timeout_ms = config.parse::<u64>("VALKEY_COMMAND_TIMEOUT_MS", 1_000)?;
    if valkey_command_timeout_ms == 0 {
        anyhow::bail!("VALKEY_COMMAND_TIMEOUT_MS must be greater than zero");
    }
    let valkey_command_timeout = Duration::from_millis(valkey_command_timeout_ms);

    // 数据库和 Valkey 客户端在 server factory 外创建，避免每个 worker 重复初始化。
    let diesel_db = create_pool(database_url.clone(), database_max_connections(&config)?)?;
    #[cfg(not(test))]
    let valkey =
        nazo_valkey::ValkeyConnection::connect(&valkey_url, valkey_command_timeout).await?;
    #[cfg(test)]
    let valkey = nazo_valkey::test_support::connect(&valkey_url, valkey_command_timeout).await?;

    let settings = Arc::new(Settings::from_config(&config)?);
    let runtime_modules =
        web::Data::new(RuntimeModules::initialize(diesel_db.clone(), &settings).await?);
    RuntimeModules::spawn_reconciler(runtime_modules.clone());
    tokio::fs::create_dir_all(&settings.storage.avatar_storage_dir).await?;
    let keyset = nazo_key_management::KeyManager::load_or_create(settings.key_settings()).await?;
    tokio::spawn(keyset.clone().run_lifecycle());
    let metadata_handles = web::Data::new(MetadataHandles {
        config: MetadataConfig::from(settings.as_ref()),
        keyset: keyset.clone(),
        runtime_modules: runtime_modules.registry.clone(),
    });
    #[cfg(not(test))]
    let resource_replay_connection = valkey.clone();
    #[cfg(test)]
    let resource_replay_connection =
        nazo_valkey::ValkeyConnection::from_existing_client(valkey.clone());
    let resource_server_handles = web::Data::new(ResourceServerHandles {
        config: ResourceServerConfig::from(settings.as_ref()),
        keyset: keyset.clone(),
        tokens: nazo_postgres::TokenRepository::new(diesel_db.clone()),
        clients: nazo_postgres::OAuthClientRepository::new(diesel_db.clone()),
        replay: nazo_valkey::ReplayStore::new(&resource_replay_connection),
        #[cfg(not(test))]
        runtime_modules: runtime_modules.registry.clone(),
        #[cfg(test)]
        http_message_signatures_enabled: settings.modules.enable_fapi_http_signatures,
    });
    #[cfg(not(test))]
    let dynamic_registration_rate_limit_connection = valkey.clone();
    #[cfg(test)]
    let dynamic_registration_rate_limit_connection =
        nazo_valkey::ValkeyConnection::from_existing_client(valkey.clone());
    let dynamic_registration_handles = web::Data::new(DynamicRegistrationHandles {
        config: DynamicRegistrationConfig::from(settings.as_ref()),
        clients: nazo_postgres::OAuthClientRepository::new(diesel_db.clone()),
        rate_limits: nazo_valkey::RateLimitStore::new(&dynamic_registration_rate_limit_connection),
        keyset: keyset.clone(),
        #[cfg(not(test))]
        runtime_modules: runtime_modules.registry.clone(),
        #[cfg(test)]
        enabled: settings.modules.enable_dynamic_client_registration,
    });
    let admin_client_config = web::Data::new(AdminClientConfig::from_settings(&settings));
    let admin_client_service = web::Data::new(ServerAdminClientService::new(
        nazo_postgres::OAuthClientRepository::new(diesel_db.clone()),
        ServerSectorIdentifierResolver,
        ServerAdminClientCrypto::new(keyset.clone()),
        admin_client_policy(&settings),
    ));
    let scim_endpoint = &settings.endpoint;
    let scim_protocol = &settings.protocol;
    let scim_storage = &settings.storage;
    let scim_service = nazo_identity::scim::ScimService::new(
        Arc::new(nazo_postgres::ScimRepository::new(diesel_db.clone())),
        Arc::new(nazo_postgres::AuditRepository::new(diesel_db.clone())),
    );
    let scim_endpoint = web::Data::new(ScimEndpoint::new(
        scim_service,
        ScimConfig::new(
            scim_storage.scim_bearer_token.as_deref(),
            &scim_protocol.client_secret_pepper,
            ClientIpConfig::new(
                &scim_endpoint.trusted_proxy_cidrs,
                scim_endpoint.client_ip_header_mode,
            ),
        )?,
        ScimRuntimeAdmission::new(runtime_modules.registry.clone()),
    ));
    #[cfg(not(test))]
    let valkey_connection = valkey.clone();
    #[cfg(test)]
    let valkey_connection = nazo_valkey::ValkeyConnection::from_existing_client(valkey.clone());
    let authorization_service = web::Data::new(ServerAuthorizationService::new(
        nazo_postgres::AuthorizationFlowRepository::new(
            diesel_db.clone(),
            crate::support::DEFAULT_TENANT_ID,
        ),
        nazo_valkey::AuthorizationStateAdapter::new(&valkey_connection),
        keyset.clone(),
    ));
    let token_service = web::Data::new(crate::http::token::ServerTokenService::new(
        nazo_postgres::TokenIssuanceRepository::new(diesel_db.clone()),
        nazo_valkey::TokenIssuanceStateAdapter::new(&valkey_connection),
        keyset.clone(),
    ));
    let ciba_service = web::Data::new(ServerCibaService::new(nazo_valkey::CibaStore::new(
        &valkey_connection,
    )));
    let ciba_users = web::Data::new(nazo_postgres::UserRepository::new(diesel_db.clone()));
    let ciba_config = web::Data::new(CibaHttpConfig::from(settings.as_ref()));
    let token_issuance_config = web::Data::new(TokenIssuanceConfig::from(settings.as_ref()));
    let device_service = web::Data::new(ServerDeviceGrantService::new(
        nazo_valkey::DeviceStore::new(&valkey_connection),
    ));
    let device_grants = web::Data::new(nazo_postgres::AuthorizationFlowRepository::new(
        diesel_db.clone(),
        crate::support::DEFAULT_TENANT_ID,
    ));
    let device_config = web::Data::new(DeviceHttpConfig::from(settings.as_ref()));
    let userinfo_handles = web::Data::new(UserinfoHandles::new(
        nazo_valkey::ReplayStore::new(&valkey_connection),
        keyset.clone(),
        UserinfoConfig::from(settings.as_ref()),
    ));
    let authorization_config = web::Data::new(AuthorizationHttpConfig::from(settings.as_ref()));
    let authorization_runtime: web::Data<ServerRuntimeModuleRegistry> =
        web::Data::from(runtime_modules.registry.clone());
    let token_endpoint_handles = web::Data::new(TokenEndpointHandles::new(
        token_service.clone(),
        authorization_service.clone(),
        CibaTokenHandles::new(
            ciba_service.clone(),
            ciba_users.clone(),
            ciba_config.clone(),
        ),
        token_issuance_config.clone(),
        device_service.clone(),
        authorization_runtime.clone(),
    ));

    let session = &settings.session;
    let session_http_config = SessionHttpConfig::new(
        &session.session_cookie_name,
        &session.csrf_cookie_name,
        session.cookie_secure,
    );
    let admin_sessions = web::Data::new(AdminSessionHandles::new(
        nazo_valkey::SessionStore::new(&valkey_connection),
        nazo_postgres::UserRepository::new(diesel_db.clone()),
        session_http_config.clone(),
    ));
    let admin_federation = web::Data::new(AdminFederationConfig::from_settings(&settings));
    #[cfg(not(test))]
    let session_profiles = web::Data::new(SessionProfileHandles::new(
        nazo_valkey::SessionStore::new(&valkey_connection),
        nazo_postgres::UserRepository::new(diesel_db.clone()),
        session_http_config,
        &settings.endpoint.issuer,
        runtime_modules.registry.clone(),
    ));
    #[cfg(test)]
    let session_profiles = web::Data::new(SessionProfileHandles::new(
        nazo_valkey::SessionStore::new(&valkey_connection),
        nazo_postgres::UserRepository::new(diesel_db.clone()),
        session_http_config,
        &settings.endpoint.issuer,
        settings.modules.enable_session_management,
    ));
    let device_decision_handles = web::Data::new(DeviceDecisionHandles::new(
        authorization_service.clone(),
        device_service.clone(),
        device_grants.clone(),
        session_profiles.clone(),
        device_config.clone(),
        authorization_runtime.clone(),
    ));
    #[cfg(not(test))]
    let oidc_logout = web::Data::new(OidcLogoutHandles::new(
        session_profiles.get_ref().clone(),
        nazo_postgres::OAuthClientRepository::new(diesel_db.clone()),
        nazo_postgres::AuditRepository::new(diesel_db.clone()),
        keyset.clone(),
        OidcLogoutConfig::from(settings.as_ref()),
        runtime_modules.registry.clone(),
    ));
    #[cfg(test)]
    let oidc_logout = web::Data::new(OidcLogoutHandles::new(
        session_profiles.get_ref().clone(),
        nazo_postgres::OAuthClientRepository::new(diesel_db.clone()),
        nazo_postgres::AuditRepository::new(diesel_db.clone()),
        keyset.clone(),
        OidcLogoutConfig::from(settings.as_ref()),
        settings.modules.enable_frontchannel_logout,
    ));
    let mfa_rate_limit_connection = valkey_connection.clone();
    let csrf_http_config = web::Data::new(CsrfHttpConfig::new(
        session.csrf_cookie_name.as_str(),
        session.session_ttl_seconds,
        session.cookie_secure,
    ));
    let mfa_profiles = web::Data::new(MfaProfileHandles {
        config: MfaProfileConfig::from(settings.as_ref()),
        sessions: session_profiles.get_ref().clone(),
        mfa: nazo_postgres::MfaRepository::new(diesel_db.clone()),
        rate_limits: nazo_valkey::RateLimitStore::new(&mfa_rate_limit_connection),
    });
    let account_profiles = web::Data::new(AccountProfileService::new(
        nazo_postgres::UserRepository::new(diesel_db.clone()),
        nazo_postgres::GrantRepository::new(diesel_db.clone()),
        nazo_postgres::OAuthClientRepository::new(diesel_db.clone()),
    ));
    let avatar_profiles = web::Data::new(AvatarProfileService::new(
        nazo_postgres::UserRepository::new(diesel_db.clone()),
        nazo_postgres::GrantRepository::new(diesel_db.clone()),
        crate::adapters::avatar_files::LocalAvatarStorage::new(
            settings.storage.avatar_storage_dir.clone(),
        ),
        settings.storage.avatar_max_bytes,
    ));
    let profile_delivery_store = nazo_valkey::DeliveryStore::new(&valkey_connection);
    let profile_access_requests = web::Data::new(ClientAccessProfileService::new(
        nazo_postgres::AccessRequestRepository::new(diesel_db.clone()),
        profile_delivery_store,
        &settings.protocol.client_secret_pepper,
        &settings.endpoint.frontend_base_url,
    ));
    let profile_federation = web::Data::new(FederationProfileService::new(
        nazo_postgres::FederationRepository::new(diesel_db.clone()),
    ));
    let admin_users: web::Data<dyn nazo_identity::ports::AdminUserRepositoryPort> = web::Data::from(
        Arc::new(nazo_postgres::UserRepository::new(diesel_db.clone()))
            as Arc<dyn nazo_identity::ports::AdminUserRepositoryPort>,
    );
    let admin_grants: web::Data<dyn nazo_auth::AdminGrantRepositoryPort> = web::Data::from(
        Arc::new(nazo_postgres::GrantRepository::new(diesel_db.clone()))
            as Arc<dyn nazo_auth::AdminGrantRepositoryPort>,
    );
    let admin_access_requests = web::Data::new(nazo_postgres::AccessRequestRepository::new(
        diesel_db.clone(),
    ));
    let admin_access_delivery = web::Data::new(nazo_valkey::DeliveryStore::new(&valkey_connection));
    let protocol = &settings.protocol;
    let storage = &settings.storage;
    let admin_access_request_config = web::Data::new(AdminAccessRequestConfig::new(
        &protocol.client_secret_pepper,
        storage.client_delivery_ttl_seconds,
    ));
    let endpoint = &settings.endpoint;
    let client_ip_config = web::Data::new(ClientIpConfig::new(
        &endpoint.trusted_proxy_cidrs,
        endpoint.client_ip_header_mode,
    ));
    let identity = &settings.identity;
    let auth_request_limiter = web::Data::new(AuthRequestLimiter::new(
        nazo_valkey::RateLimitStore::new(&valkey_connection),
        identity.rate_limit.window_seconds,
        identity.rate_limit.auth_max_requests,
        client_ip_config.get_ref().clone(),
    ));
    let token_management_limiter = web::Data::new(TokenManagementRequestLimiter::new(
        nazo_valkey::RateLimitStore::new(&valkey_connection),
        identity.rate_limit.window_seconds,
        identity.rate_limit.token_management_max_requests,
        client_ip_config.get_ref().clone(),
    ));
    let email_code_http_config = web::Data::new(EmailCodeHttpConfig::new(
        identity.email_code_dev_response_enabled,
    ));
    let registration = web::Data::new(LocalRegistrationService::new(
        nazo_postgres::UserRepository::new(diesel_db.clone()),
        nazo_valkey::AuthenticationStore::new(&valkey_connection),
        RegistrationSecretHasher,
        SmtpVerificationEmailDelivery::new(settings.clone()),
        default_tenant_context()
            .as_identity_context()
            .expect("default tenant identifiers are valid"),
        nazo_identity::RegistrationServiceConfig {
            delivery_enabled: email_delivery_configured(&settings),
            send_peer_cooldown_seconds: identity.email.send_peer_cooldown_seconds,
            send_cooldown_seconds: identity.email.send_cooldown_seconds,
            code_ttl_seconds: identity.email.code_ttl_seconds,
        },
    ));
    let authentication = web::Data::new(LocalAuthenticationService::new(
        nazo_postgres::UserRepository::new(diesel_db.clone()),
        nazo_valkey::RateLimitStore::new(&valkey_connection),
        LoginPasswordVerifier,
        nazo_postgres::MfaRepository::new(diesel_db.clone()),
        nazo_valkey::SessionStore::new(&valkey_connection),
        TracingAuthenticationAudit,
        nazo_identity::AuthenticationServiceConfig {
            tenant_id: nazo_identity::TenantId::new(crate::support::DEFAULT_TENANT_ID)
                .expect("default tenant ID is valid"),
            dummy_password_hash: nazo_identity::PasswordHash::new(dummy_password_hash()?)?,
            failure_window_seconds: identity.rate_limit.login_failure_window_seconds,
            failure_email_max_attempts: identity.rate_limit.login_failure_email_max_attempts,
            failure_ip_email_max_attempts: identity.rate_limit.login_failure_ip_email_max_attempts,
            session_ttl_seconds: session.session_ttl_seconds,
        },
    ));
    let login_http_config = web::Data::new(LoginHttpConfig::new(
        settings.endpoint.issuer.as_str(),
        settings.endpoint.frontend_base_url.as_str(),
        session.session_cookie_name.as_str(),
        session.csrf_cookie_name.as_str(),
        session.session_ttl_seconds,
        session.cookie_secure,
    ));
    let passkey = &identity.passkey;
    let passkeys = web::Data::new(LocalPasskeyService::new(
        nazo_postgres::UserRepository::new(diesel_db.clone()),
        nazo_postgres::PasskeyRepository::new(diesel_db.clone()),
        nazo_valkey::AuthenticationStore::new(&valkey_connection),
        nazo_postgres::MfaRepository::new(diesel_db.clone()),
        nazo_valkey::SessionStore::new(&valkey_connection),
        TracingPasskeyAudit,
        nazo_identity::PasskeyServiceConfig {
            tenant_id: nazo_identity::TenantId::new(crate::support::DEFAULT_TENANT_ID)
                .expect("default tenant ID is valid"),
            rp_id: passkey.rp_id.to_owned(),
            rp_name: passkey.rp_name.to_owned(),
            origin: passkey.origin.to_owned(),
            require_user_verification: passkey.require_user_verification,
            require_user_handle: passkey.require_user_handle,
            strict_base64: passkey.strict_base64,
            ceremony_ttl_seconds: PASSKEY_CEREMONY_TTL_SECONDS,
            session_ttl_seconds: session.session_ttl_seconds,
        },
    ));
    let passkey_http_config = web::Data::new(PasskeyHttpConfig::new(
        session.session_cookie_name.as_str(),
        session.csrf_cookie_name.as_str(),
        session.session_ttl_seconds,
        session.cookie_secure,
    ));
    let federation = web::Data::new(LocalFederationService::new(
        nazo_postgres::FederationRepository::new(diesel_db.clone()),
        nazo_valkey::AuthenticationStore::new(&valkey_connection),
        FederationBootstrapPasswordHasher,
        nazo_valkey::SessionStore::new(&valkey_connection),
        TracingFederationAudit,
        nazo_identity::FederationServiceConfig {
            tenant: default_tenant_context()
                .as_identity_context()
                .expect("default tenant identifiers are valid"),
            state_ttl_seconds: FEDERATION_STATE_TTL_SECONDS,
            saml_replay_ttl_seconds: SAML_REPLAY_TTL_SECONDS,
            session_ttl_seconds: session.session_ttl_seconds,
        },
    ));
    let federation_http_config = web::Data::new(FederationHttpConfig::new(
        identity.federation.providers.clone(),
        identity.federation.saml_gateway.clone(),
        session.session_cookie_name.as_str(),
        session.csrf_cookie_name.as_str(),
        session.session_ttl_seconds,
        session.cookie_secure,
    ));
    #[cfg(not(test))]
    spawn_backchannel_logout_delivery_worker(oidc_logout.clone());

    let bind = config.string("BIND", "0.0.0.0:8000");
    let addr: SocketAddr = bind.parse()?;
    tracing::info!("nazo-oauth-server(actix-web) listening on {addr}");

    HttpServer::new(move || {
        let app = App::new()
            .wrap_fn(|req, service| {
                let method = req.method().clone();
                let path = req.path().to_owned();
                let started = std::time::Instant::now();
                let span = tracing::info_span!(
                    "http.request",
                    "otel.kind" = "server",
                    "http.request.method" = %method,
                    "url.path" = %path
                );
                let future = service.call(req);
                async move {
                    let result = future.await;
                    if let Ok(response) = &result {
                        let status = response.status().as_u16();
                        let elapsed_ms = started.elapsed().as_secs_f64() * 1_000.0;
                        tracing::info!(
                            monotonic_counter.http_server_requests = 1_u64,
                            histogram.http_server_request_duration_ms = elapsed_ms,
                            "http.request.method" = %method,
                            "http.response.status_code" = status as i64,
                            "url.path" = %path,
                            "HTTP request completed"
                        );
                    }
                    result
                }
                .instrument(span)
            })
            .wrap(from_fn(security_headers))
            .app_data(runtime_modules.clone())
            .app_data(authorization_service.clone())
            .app_data(token_service.clone())
            .app_data(token_endpoint_handles.clone())
            .app_data(ciba_service.clone())
            .app_data(ciba_users.clone())
            .app_data(ciba_config.clone())
            .app_data(token_issuance_config.clone())
            .app_data(device_service.clone())
            .app_data(device_grants.clone())
            .app_data(device_decision_handles.clone())
            .app_data(device_config.clone())
            .app_data(userinfo_handles.clone())
            .app_data(authorization_config.clone())
            .app_data(authorization_runtime.clone())
            .app_data(metadata_handles.clone())
            .app_data(admin_sessions.clone())
            .app_data(admin_federation.clone())
            .app_data(session_profiles.clone())
            .app_data(oidc_logout.clone())
            .app_data(csrf_http_config.clone())
            .app_data(mfa_profiles.clone())
            .app_data(account_profiles.clone())
            .app_data(avatar_profiles.clone())
            .app_data(profile_access_requests.clone())
            .app_data(profile_federation.clone())
            .app_data(resource_server_handles.clone())
            .app_data(admin_users.clone())
            .app_data(admin_grants.clone())
            .app_data(admin_access_requests.clone())
            .app_data(admin_access_delivery.clone())
            .app_data(admin_access_request_config.clone())
            .app_data(admin_client_service.clone())
            .app_data(admin_client_config.clone())
            .app_data(client_ip_config.clone())
            .app_data(auth_request_limiter.clone())
            .app_data(token_management_limiter.clone())
            .app_data(email_code_http_config.clone())
            .app_data(registration.clone())
            .app_data(authentication.clone())
            .app_data(login_http_config.clone())
            .app_data(passkeys.clone())
            .app_data(passkey_http_config.clone())
            .app_data(federation.clone())
            .app_data(federation_http_config.clone())
            .app_data(dynamic_registration_handles.clone())
            .app_data(scim_endpoint.clone());
        app.configure(|cfg| routes::configure(cfg, &settings, perf_metrics_enabled))
    })
    .bind(addr)?
    .run()
    .await?;
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/in_source/src/bootstrap/tests/bootstrap.rs"]
mod tests;
