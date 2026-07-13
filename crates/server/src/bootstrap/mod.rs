//! 应用启动入口。
// 负责组装配置、外部连接、共享状态和 Actix HTTP server。

mod authentication_services;
mod cors;
mod observability;
mod profile_services;
mod registration_services;
pub(crate) mod routes;
pub(crate) use authentication_services::{
    LocalAuthenticationService, LoginPasswordVerifier, TracingAuthenticationAudit,
};
pub(crate) use profile_services::{
    AccountProfileService, ClientAccessProfileService, FederationProfileService,
};
pub(crate) use registration_services::{LocalRegistrationService, RegistrationSecretHasher};

use std::{net::SocketAddr, sync::Arc, time::Duration};

use actix_web::{App, HttpServer, dev::Service, middleware::from_fn, web};

use crate::config::{ConfigSource, database_max_connections, database_url};
use crate::domain::{
    AppState, DynamicRegistrationConfig, DynamicRegistrationHandles, MetadataConfig,
    MetadataHandles, MfaProfileConfig, MfaProfileHandles, ResourceServerConfig,
    ResourceServerHandles,
};
use crate::http::admin::access_requests::AdminAccessRequestConfig;
use crate::http::admin::clients::AdminClientConfig;
use crate::http::auth::email_code::EmailCodeHttpConfig;
use crate::http::auth::login::LoginHttpConfig;
use crate::http::authorization::{AuthorizationHttpConfig, ServerAuthorizationService};
use crate::http::profile::oidc_logout::spawn_backchannel_logout_delivery_worker;
use crate::http::scim::{ScimConfig, ScimEndpoint, ScimRuntimeAdmission};
use crate::runtime_modules::{RuntimeModules, ServerRuntimeModuleRegistry};
use crate::settings::Settings;
use crate::support::client_ip::ClientIpConfig;
use crate::support::sessions::{AdminSessionHandles, SessionHttpConfig, SessionProfileHandles};
use crate::support::{
    AuthRateLimitConfig, SmtpVerificationEmailDelivery, configure_password_hash_limits,
    default_password_hash_max_concurrency, default_password_hash_queue_timeout_ms,
    default_tenant_context, dummy_password_hash, email_delivery_configured,
    initialize_dummy_password_hash,
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

    // 配置只在启动阶段读取，运行期通过 AppState 共享不可变配置。
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
    tokio::fs::create_dir_all(&settings.storage.avatar_storage_dir)
        .await
        .ok();
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
    let admin_client_keyset = web::Data::new(keyset.clone());
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
    let authorization_state_connection = valkey.clone();
    #[cfg(test)]
    let authorization_state_connection =
        nazo_valkey::ValkeyConnection::from_existing_client(valkey.clone());
    let authorization_service = web::Data::new(ServerAuthorizationService::new(
        nazo_postgres::AuthorizationFlowRepository::new(
            diesel_db.clone(),
            crate::support::DEFAULT_TENANT_ID,
        ),
        nazo_valkey::AuthorizationStateAdapter::new(&authorization_state_connection),
        keyset.clone(),
    ));
    let authorization_config = web::Data::new(AuthorizationHttpConfig::from(settings.as_ref()));
    let authorization_runtime: web::Data<ServerRuntimeModuleRegistry> =
        web::Data::from(runtime_modules.registry.clone());

    let state = web::Data::new(AppState {
        diesel_db,
        valkey,
        settings,
        keyset,
        #[cfg(not(test))]
        runtime_modules: runtime_modules.registry.clone(),
    });
    let session = &state.settings.session;
    let session_http_config = SessionHttpConfig::new(
        &session.session_cookie_name,
        &session.csrf_cookie_name,
        session.cookie_secure,
    );
    let admin_sessions = web::Data::new(AdminSessionHandles::new(
        nazo_valkey::SessionStore::new(&state.valkey_connection()),
        nazo_postgres::UserRepository::new(state.diesel_db.clone()),
        session_http_config.clone(),
    ));
    #[cfg(not(test))]
    let session_profiles = web::Data::new(SessionProfileHandles::new(
        nazo_valkey::SessionStore::new(&state.valkey_connection()),
        nazo_postgres::UserRepository::new(state.diesel_db.clone()),
        session_http_config,
        &state.settings.endpoint.issuer,
        runtime_modules.registry.clone(),
    ));
    #[cfg(test)]
    let session_profiles = web::Data::new(SessionProfileHandles::new(
        nazo_valkey::SessionStore::new(&state.valkey_connection()),
        nazo_postgres::UserRepository::new(state.diesel_db.clone()),
        session_http_config,
        &state.settings.endpoint.issuer,
        state.settings.modules.enable_session_management,
    ));
    let mfa_rate_limit_connection = state.valkey_connection();
    let mfa_profiles = web::Data::new(MfaProfileHandles {
        config: MfaProfileConfig::from(state.settings.as_ref()),
        sessions: session_profiles.get_ref().clone(),
        mfa: nazo_postgres::MfaRepository::new(state.diesel_db.clone()),
        rate_limits: nazo_valkey::RateLimitStore::new(&mfa_rate_limit_connection),
    });
    let account_profiles = web::Data::new(AccountProfileService::new(
        nazo_postgres::UserRepository::new(state.diesel_db.clone()),
        nazo_postgres::GrantRepository::new(state.diesel_db.clone()),
        nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone()),
    ));
    let profile_delivery_store = nazo_valkey::DeliveryStore::new(&state.valkey_connection());
    let profile_access_requests = web::Data::new(ClientAccessProfileService::new(
        nazo_postgres::AccessRequestRepository::new(state.diesel_db.clone()),
        profile_delivery_store,
        &state.settings.protocol.client_secret_pepper,
        &state.settings.endpoint.frontend_base_url,
    ));
    let profile_federation = web::Data::new(FederationProfileService::new(
        nazo_postgres::FederationRepository::new(state.diesel_db.clone()),
    ));
    let admin_users: web::Data<dyn nazo_identity::ports::AdminUserRepositoryPort> = web::Data::from(
        Arc::new(nazo_postgres::UserRepository::new(state.diesel_db.clone()))
            as Arc<dyn nazo_identity::ports::AdminUserRepositoryPort>,
    );
    let admin_grants = web::Data::new(nazo_postgres::GrantRepository::new(state.diesel_db.clone()));
    let oauth_clients = web::Data::new(nazo_postgres::OAuthClientRepository::new(
        state.diesel_db.clone(),
    ));
    let admin_access_requests = web::Data::new(nazo_postgres::AccessRequestRepository::new(
        state.diesel_db.clone(),
    ));
    let admin_access_delivery =
        web::Data::new(nazo_valkey::DeliveryStore::new(&state.valkey_connection()));
    let admin_access_keys = web::Data::new(state.keyset.clone());
    let protocol = &state.settings.protocol;
    let storage = &state.settings.storage;
    let admin_access_request_config = web::Data::new(AdminAccessRequestConfig::new(
        protocol.pairwise_subject_secret.as_deref(),
        &protocol.client_secret_pepper,
        &state.settings.endpoint.issuer,
        storage.client_delivery_ttl_seconds,
    ));
    let endpoint = &state.settings.endpoint;
    let client_ip_config = web::Data::new(ClientIpConfig::new(
        &endpoint.trusted_proxy_cidrs,
        endpoint.client_ip_header_mode,
    ));
    let identity = &state.settings.identity;
    let registration_rate_limits =
        web::Data::new(nazo_valkey::RateLimitStore::new(&state.valkey_connection()));
    let auth_rate_limit_config = web::Data::new(AuthRateLimitConfig::new(
        identity.rate_limit.window_seconds,
        identity.rate_limit.auth_max_requests,
    ));
    let email_code_http_config = web::Data::new(EmailCodeHttpConfig::new(
        identity.email_code_dev_response_enabled,
    ));
    let registration = web::Data::new(LocalRegistrationService::new(
        nazo_postgres::UserRepository::new(state.diesel_db.clone()),
        nazo_valkey::AuthenticationStore::new(&state.valkey_connection()),
        RegistrationSecretHasher,
        SmtpVerificationEmailDelivery::new(state.settings.clone()),
        default_tenant_context()
            .as_identity_context()
            .expect("default tenant identifiers are valid"),
        nazo_identity::RegistrationServiceConfig {
            delivery_enabled: email_delivery_configured(&state.settings),
            send_peer_cooldown_seconds: identity.email.send_peer_cooldown_seconds,
            send_cooldown_seconds: identity.email.send_cooldown_seconds,
            code_ttl_seconds: identity.email.code_ttl_seconds,
        },
    ));
    let authentication = web::Data::new(LocalAuthenticationService::new(
        nazo_postgres::UserRepository::new(state.diesel_db.clone()),
        nazo_valkey::RateLimitStore::new(&state.valkey_connection()),
        LoginPasswordVerifier,
        nazo_postgres::MfaRepository::new(state.diesel_db.clone()),
        nazo_valkey::SessionStore::new(&state.valkey_connection()),
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
        state.settings.endpoint.issuer.as_str(),
        state.settings.endpoint.frontend_base_url.as_str(),
        session.session_cookie_name.as_str(),
        session.csrf_cookie_name.as_str(),
        session.session_ttl_seconds,
        session.cookie_secure,
    ));
    spawn_backchannel_logout_delivery_worker(state.clone());

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
            .app_data(state.clone())
            .app_data(runtime_modules.clone())
            .app_data(authorization_service.clone())
            .app_data(authorization_config.clone())
            .app_data(authorization_runtime.clone())
            .app_data(metadata_handles.clone())
            .app_data(admin_sessions.clone())
            .app_data(session_profiles.clone())
            .app_data(mfa_profiles.clone())
            .app_data(account_profiles.clone())
            .app_data(profile_access_requests.clone())
            .app_data(profile_federation.clone())
            .app_data(resource_server_handles.clone())
            .app_data(admin_users.clone())
            .app_data(admin_grants.clone())
            .app_data(admin_access_requests.clone())
            .app_data(admin_access_delivery.clone())
            .app_data(admin_access_keys.clone())
            .app_data(admin_access_request_config.clone())
            .app_data(oauth_clients.clone())
            .app_data(admin_client_config.clone())
            .app_data(admin_client_keyset.clone())
            .app_data(client_ip_config.clone())
            .app_data(registration_rate_limits.clone())
            .app_data(auth_rate_limit_config.clone())
            .app_data(email_code_http_config.clone())
            .app_data(registration.clone())
            .app_data(authentication.clone())
            .app_data(login_http_config.clone())
            .app_data(dynamic_registration_handles.clone())
            .app_data(scim_endpoint.clone());
        app.configure(|cfg| routes::configure(cfg, &state.settings, perf_metrics_enabled))
    })
    .bind(addr)?
    .run()
    .await?;
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/in_source/src/bootstrap/tests/bootstrap.rs"]
mod tests;
