use crate::adapters::security::blake3_hex;

use crate::{domain::TestInfrastructure, settings::RateLimitSettings, settings::Settings};

use nazo_http_actix::{ClientIpHeaderMode, IpCidr, client_ip_with_context};

#[derive(Clone, Copy)]
pub(crate) enum RateLimitPolicy {
    Auth,
        Token,
        TokenManagement,
}

impl RateLimitPolicy {
        fn name(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Token => "token",
            Self::TokenManagement => "token_management",
        }
    }

    fn dimension(self) -> nazo_valkey::RateDimension {
        match self {
            Self::Auth => nazo_valkey::RateDimension::Auth,
                        Self::Token => nazo_valkey::RateDimension::Token,
                        Self::TokenManagement => nazo_valkey::RateDimension::TokenManagement,
        }
    }

        fn max_requests(self, settings: &RateLimitSettings) -> u64 {
        match self {
            Self::Auth => settings.auth_max_requests,
            Self::Token => settings.token_max_requests,
            Self::TokenManagement => settings.token_management_max_requests,
        }
    }
}

pub(crate) async fn enforce_rate_limit(
    state: &TestInfrastructure,
    req: &HttpRequest,
    policy: RateLimitPolicy,
) -> Result<(), HttpResponse> {
    let settings = &state.settings.identity.rate_limit;
    let endpoint = &state.settings.endpoint;
    enforce_rate_limit_with_store(
        &nazo_valkey::RateLimitStore::new(&state.valkey_connection()),
        req,
        policy,
        settings.window_seconds,
        policy.max_requests(settings),
        endpoint.client_ip_header_mode,
        &endpoint.trusted_proxy_cidrs,
    )
    .await
}

pub(crate) async fn enforce_rate_limit_with_store(
    store: &nazo_valkey::RateLimitStore,
    req: &HttpRequest,
    policy: RateLimitPolicy,
    window_seconds: u64,
    max_requests: u64,
    client_ip_header_mode: ClientIpHeaderMode,
    trusted_proxy_cidrs: &[IpCidr],
) -> Result<(), HttpResponse> {
    let count = store
        .increment(
            policy.dimension(),
            &client_ip_with_context(req, client_ip_header_mode, trusted_proxy_cidrs),
            window_seconds,
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "rate limit increment failed");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "请求频率校验失败.",
            )
        })?;

    if count > max_requests {
        return Err(rate_limited_response(window_seconds));
    }
    Ok(())
}

fn rate_limit_subject(req: &HttpRequest, settings: &Settings) -> String {
    client_ip_with_context(
        req,
        settings.endpoint.client_ip_header_mode,
        &settings.endpoint.trusted_proxy_cidrs,
    )
}

fn rate_limit_key(policy: RateLimitPolicy, subject: &str) -> String {
    format!(
        "oauth:rate:{}:{}",
        policy.name(),
        blake3_hex(subject.trim())
    )
}
