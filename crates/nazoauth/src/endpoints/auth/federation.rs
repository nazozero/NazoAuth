//! External OIDC, OAuth2-social, and trusted SAML-gateway federation.

use crate::endpoints::sessions::SessionProfileHandles;
use crate::http::Request as HttpRequest;
use crate::http::Response as HttpResponse;
use crate::http::{
    json_response, json_response_no_store, make_cookie, oauth_error, redirect_found,
    with_cookie_headers,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::StatusCode;
use jiff::Timestamp;
use nazo_identity::{FederationError, LoginSuccess, VerifiedExternalIdentity};
use serde::{Serialize, de::DeserializeOwned};

use serde_json::json;

use crate::config::{
    ExternalLoginProvider, ExternalLoginProviderAdapter, FederationProviderRegistry,
    FederationSettings, OidcFederationSettings, SamlGatewaySettings, SessionSettings,
    SocialProviderSettings,
};
use crate::http::{ClientIpConfig, client_ip_with_config};
use nazo_identity::email::normalize_email_address;
use nazo_identity::federation::oidc as rp;
use nazo_oauth_server::rate_limit::AuthRequestLimiter;
use nazo_oauth_server::services::LocalFederationService;

pub mod oidc;
pub mod saml;
pub mod social;
use oidc::*;
use saml::*;
use social::*;

pub const FEDERATION_STATE_TTL_SECONDS: u64 = 300;
pub const SAML_REPLAY_TTL_SECONDS: u64 =
    (SAML_ASSERTION_MAX_TTL_SECONDS + SAML_ASSERTION_CLOCK_SKEW_SECONDS) as u64;
pub const MAX_FEDERATION_PROVIDER_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
pub struct FederationHttpConfig {
    pub providers: FederationProviderRegistry,
    pub client: std::sync::Arc<dyn FederationHttpClient>,
    pub saml_gateway: Option<SamlGatewaySettings>,
    pub session_cookie_name: String,
    pub csrf_cookie_name: String,
    pub session_ttl_seconds: u64,
    pub pending_mfa_session_ttl_seconds: u64,
    pub cookie_secure: bool,
}

impl FederationHttpConfig {
    pub fn new(
        federation: &FederationSettings,
        client: std::sync::Arc<dyn FederationHttpClient>,
        session: &SessionSettings,
    ) -> Self {
        Self {
            providers: federation.providers.clone(),
            client,
            saml_gateway: federation.saml_gateway.clone(),
            session_cookie_name: session.session_cookie_name.clone(),
            csrf_cookie_name: session.csrf_cookie_name.clone(),
            session_ttl_seconds: session.session_ttl_seconds,
            pending_mfa_session_ttl_seconds: session.pending_mfa_session_ttl_seconds,
            cookie_secure: session.cookie_secure,
        }
    }
}

/// Outbound transport for configured federation providers. The host enforces the
/// supplied response limit while reading, disables redirects and environment
/// proxies, and applies the existing ten-second exchange timeout.
pub trait FederationHttpClient: Send + Sync {
    fn send(&self, request: HttpRequest, max_response_bytes: usize) -> FederationHttpFuture<'_>;

    /// Executes an HTTPS request whose destination was selected by issuer metadata.
    /// Hosts must enforce their network admission policy for the resolved destination.
    fn send_discovered(
        &self,
        _request: HttpRequest,
        _max_response_bytes: usize,
    ) -> FederationHttpFuture<'_> {
        Box::pin(async { anyhow::bail!("OIDC discovery transport is not configured") })
    }
}

pub type FederationHttpFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<HttpResponse>> + Send + 'a>>;

pub async fn send(
    client: &dyn FederationHttpClient,
    request: HttpRequest,
) -> anyhow::Result<HttpResponse> {
    client
        .send(request, MAX_FEDERATION_PROVIDER_RESPONSE_BYTES)
        .await
}

pub fn federation_response_bytes(response: HttpResponse) -> anyhow::Result<bytes::Bytes> {
    if response.status().is_client_error() || response.status().is_server_error() {
        anyhow::bail!("federation provider returned HTTP {}", response.status());
    }
    Ok(response.into_body())
}

pub fn federation_json_response<T: DeserializeOwned>(response: HttpResponse) -> anyhow::Result<T> {
    Ok(serde_json::from_slice(&federation_response_bytes(
        response,
    )?)?)
}

pub fn federation_text_response(response: HttpResponse) -> anyhow::Result<String> {
    Ok(std::str::from_utf8(&federation_response_bytes(response)?)?.to_owned())
}

#[derive(Serialize)]
pub struct FederationProviderView<'a> {
    pub provider_id: &'a str,
    pub display_name: &'a str,
    pub adapter_type: &'static str,
    pub icon: Option<&'a str>,
    pub display_order: i32,
    pub start_url: String,
}

pub async fn federation_provider_list(config: &FederationHttpConfig) -> HttpResponse {
    #[derive(Serialize)]
    struct ProviderList<'a> {
        providers: Vec<FederationProviderView<'a>>,
    }
    let providers = config
        .providers
        .enabled_public_providers()
        .map(provider_view)
        .collect::<Vec<_>>();
    json_response_no_store(ProviderList { providers })
}

pub async fn federation_provider_start(
    limiter: &AuthRequestLimiter,
    client_ip: &ClientIpConfig,
    service: &LocalFederationService,
    config: &FederationHttpConfig,
    req: &HttpRequest,
    path: String,
) -> HttpResponse {
    federation_provider_start_inner(limiter, client_ip, service, config, req, path, None).await
}

/// An existing local account explicitly authorizes linking this provider. The
/// session is resolved once at the authentication boundary; the callback must
/// bind to the same still-live session before committing a link.
pub async fn federation_provider_link_start(
    limiter: &AuthRequestLimiter,
    client_ip: &ClientIpConfig,
    service: &LocalFederationService,
    sessions: &SessionProfileHandles,
    config: &FederationHttpConfig,
    req: &HttpRequest,
    provider_id: String,
) -> HttpResponse {
    let current = match sessions.current_session(req).await {
        Ok(Some(session)) => session,
        Ok(None) => return sessions.login_required_response(),
        Err(error) => return crate::endpoints::sessions::session_lookup_error_response(error),
    };
    let csrf = url::form_urlencoded::parse(req.body())
        .find_map(|(name, value)| (name == "csrf_token").then_some(value));
    if !sessions.has_valid_csrf_token(req, csrf.as_deref()) {
        return crate::http::csrf_error();
    }
    if !nazo_identity::session::recent_credential_management_authentication(
        current.auth_time,
        &current.amr,
        current.user.account.mfa_enabled,
        Timestamp::now().as_second(),
    ) {
        return oauth_error(
            StatusCode::PRECONDITION_REQUIRED,
            "reauthentication_required",
            "Linking an external identity requires recent account authentication.",
        );
    }
    let Some(session_id) =
        crate::http::cookie_value(req, sessions.http_config().session_cookie_name())
    else {
        return sessions.login_required_response();
    };
    if !matches!(
        config
            .providers
            .enabled_provider(&provider_id)
            .map(|provider| &provider.adapter),
        Some(ExternalLoginProviderAdapter::Oidc(_))
    ) {
        return unknown_provider_response();
    }
    federation_provider_start_inner(
        limiter,
        client_ip,
        service,
        config,
        req,
        provider_id,
        Some((current.user.user_id(), session_id.as_str())),
    )
    .await
}

async fn federation_provider_start_inner(
    limiter: &AuthRequestLimiter,
    client_ip: &ClientIpConfig,
    service: &LocalFederationService,
    config: &FederationHttpConfig,
    req: &HttpRequest,
    path: String,
    link: Option<(nazo_identity::UserId, &str)>,
) -> HttpResponse {
    if let Err(response) =
        crate::endpoints::rate_limit::enforce_auth_request_limit(limiter, req, client_ip).await
    {
        return response;
    }
    let provider_id = path;
    let Some(provider) = config.providers.enabled_provider(&provider_id) else {
        return unknown_provider_response();
    };
    let browser_binding_seed =
        read_federation_binding_seed(req, config).unwrap_or_else(rand::random::<[u8; 32]>);
    match &provider.adapter {
        ExternalLoginProviderAdapter::Oidc(provider) => {
            let metadata = if provider.discovery {
                match discover_oidc(config.client.as_ref(), provider).await {
                    Ok(metadata) => Some(metadata),
                    Err(_) => return oidc_unavailable(),
                }
            } else {
                None
            };
            let authorization_endpoint = metadata
                .as_ref()
                .map_or(provider.authorization_endpoint.as_str(), |document| {
                    document.authorization_endpoint.as_str()
                })
                .to_owned();
            let now = Timestamp::now();
            let started = if let Some((user_id, session_id)) = link {
                service
                    .start_oidc_link_with_metadata(
                        provider.provider_id.clone(),
                        metadata,
                        &browser_binding_seed,
                        user_id,
                        session_id,
                        now,
                    )
                    .await
            } else {
                service
                    .start_oidc_with_metadata(
                        provider.provider_id.clone(),
                        metadata,
                        &browser_binding_seed,
                        now,
                    )
                    .await
            };
            match started {
                Ok(start) => federation_start_response(
                    config,
                    rp::authorization_url(
                        &authorization_endpoint,
                        &provider.client_id,
                        &provider.redirect_uri,
                        &provider.scopes,
                        &start,
                    ),
                    &browser_binding_seed,
                ),
                Err(error) => federation_state_error(error),
            }
        }
        ExternalLoginProviderAdapter::Social(provider) => {
            if link.is_some() {
                return unknown_provider_response();
            }
            match service
                .start_social(provider_id, &browser_binding_seed, Timestamp::now())
                .await
            {
                Ok(start) => federation_start_response(
                    config,
                    social_authorization_url(provider, &start.state, &start.pkce_verifier),
                    &browser_binding_seed,
                ),
                Err(error) => federation_state_error(error),
            }
        }
    }
}

fn oidc_unavailable() -> HttpResponse {
    oauth_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "OIDC federation unavailable.",
    )
}

pub fn federation_binding_cookie_name(config: &FederationHttpConfig) -> &'static str {
    if config.cookie_secure {
        "__Host-nazo_federation_binding"
    } else {
        "nazo_federation_binding"
    }
}

pub fn read_federation_binding_seed(
    req: &HttpRequest,
    config: &FederationHttpConfig,
) -> Option<[u8; 32]> {
    let cookie = crate::http::cookie_value(req, federation_binding_cookie_name(config))?;
    let value = cookie.as_str();
    if value.len() != 43 {
        return None;
    }
    let mut seed = [0; 32];
    URL_SAFE_NO_PAD.decode_slice(value, &mut seed).ok()?;
    Some(seed)
}

pub fn federation_start_response(
    config: &FederationHttpConfig,
    location: String,
    seed: &[u8; 32],
) -> HttpResponse {
    with_cookie_headers(
        redirect_found(location),
        &[make_cookie(
            federation_binding_cookie_name(config),
            &URL_SAFE_NO_PAD.encode(seed),
            true,
            FEDERATION_STATE_TTL_SECONDS,
            config.cookie_secure,
        )],
    )
}

pub async fn federation_provider_callback(
    limiter: &AuthRequestLimiter,
    client_ip: &ClientIpConfig,
    service: &LocalFederationService,
    config: &FederationHttpConfig,
    req: &HttpRequest,
    path: String,
    query: OidcCallbackQuery,
) -> HttpResponse {
    federation_provider_callback_with_sessions(
        limiter, client_ip, service, config, None, req, path, query,
    )
    .await
}

// This transport boundary combines the existing callback inputs with the
// optional already-authorized local account-linking session. A single-use
// context object would add indirection but no new invariant.
#[allow(clippy::too_many_arguments)]
pub async fn federation_provider_callback_with_sessions(
    limiter: &AuthRequestLimiter,
    client_ip: &ClientIpConfig,
    service: &LocalFederationService,
    config: &FederationHttpConfig,
    sessions: Option<&SessionProfileHandles>,
    req: &HttpRequest,
    path: String,
    query: OidcCallbackQuery,
) -> HttpResponse {
    if let Err(response) =
        crate::endpoints::rate_limit::enforce_auth_request_limit(limiter, req, client_ip).await
    {
        return response;
    }
    let provider_id = path;
    let Some(provider) = config.providers.enabled_provider(&provider_id) else {
        return unknown_provider_response();
    };
    match &provider.adapter {
        ExternalLoginProviderAdapter::Oidc(provider) => {
            oidc_callback_with_link_session(
                service, config, client_ip, sessions, req, query, provider,
            )
            .await
        }
        ExternalLoginProviderAdapter::Social(provider) => {
            social_callback_after_rate_limit(
                service,
                config,
                client_ip,
                req,
                query,
                provider_id,
                provider,
            )
            .await
        }
    }
}

pub async fn oidc_callback_after_rate_limit_for_provider(
    service: &LocalFederationService,
    config: &FederationHttpConfig,
    client_ip: &ClientIpConfig,
    req: &HttpRequest,
    query: OidcCallbackQuery,
    provider: &OidcFederationSettings,
) -> HttpResponse {
    oidc_callback_with_link_session(service, config, client_ip, None, req, query, provider).await
}

async fn oidc_callback_with_link_session(
    service: &LocalFederationService,
    config: &FederationHttpConfig,
    client_ip: &ClientIpConfig,
    sessions: Option<&SessionProfileHandles>,
    req: &HttpRequest,
    query: OidcCallbackQuery,
    provider: &OidcFederationSettings,
) -> HttpResponse {
    let input = match validate_oidc_callback_input(&query) {
        Ok(input) => input,
        Err(response) => return response,
    };
    let Some(browser_binding_seed) = read_federation_binding_seed(req, config) else {
        return federation_state_error(FederationError::InvalidState);
    };
    let stored = match service
        .consume_oidc(
            input.state_token,
            &provider.provider_id,
            &browser_binding_seed,
            Timestamp::now(),
        )
        .await
    {
        Ok(stored) => stored,
        Err(error) => return federation_state_error(error),
    };
    // Discovery was validated before storing this browser-bound, single-use state.
    // A configuration change must not reinterpret it as another issuer's login.
    let metadata = match (provider.discovery, stored.discovery.as_ref()) {
        (false, None) => None,
        (true, Some(metadata)) if metadata.issuer == provider.issuer => Some(metadata),
        _ => return federation_state_error(FederationError::InvalidState),
    };
    let token_endpoint = metadata.map_or(provider.token_endpoint.as_str(), |document| {
        document.token_endpoint.as_str()
    });
    let jwks_url = metadata.map_or(provider.jwks_url.as_str(), |document| {
        document.jwks_url.as_str()
    });
    let token = match exchange_oidc_code(
        config.client.as_ref(),
        provider,
        token_endpoint,
        input.code,
        &stored.pkce_verifier,
    )
    .await
    {
        Ok(token) => token,
        Err(error) => {
            tracing::warn!(%error, provider_id = %provider.provider_id, "OIDC token exchange failed");
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "access_denied",
                "OIDC federation failed.",
            );
        }
    };
    let jwks = match fetch_oidc_jwks(config.client.as_ref(), jwks_url, provider.discovery).await {
        Ok(jwks) => jwks,
        Err(error) => {
            tracing::warn!(%error, provider_id = %provider.provider_id, "OIDC JWKS fetch failed");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "OIDC federation unavailable.",
            );
        }
    };
    let claims = match rp::verify_id_token_with_algorithm(
        &provider.issuer,
        &provider.client_id,
        &jwks,
        &token.id_token,
        &stored.nonce,
        Some(provider.signing_algorithm()),
    ) {
        Ok(claims) => claims,
        Err(error) => {
            tracing::warn!(%error, provider_id = %provider.provider_id, "OIDC ID Token verification failed");
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "access_denied",
                "OIDC federation failed.",
            );
        }
    };
    let userinfo_endpoint = match metadata {
        // An authentication-only request uses the verified ID Token's subject.
        Some(document)
            if provider
                .scopes
                .split_whitespace()
                .any(|scope| scope != "openid") =>
        {
            document.userinfo_endpoint.as_deref()
        }
        Some(_) => None,
        None => provider.userinfo_endpoint.as_deref(),
    };
    let userinfo = if let Some(endpoint) = userinfo_endpoint {
        match fetch_oidc_userinfo(config.client.as_ref(), endpoint, &token, provider.discovery)
            .await
        {
            Ok(userinfo) => Some(userinfo),
            Err(error) => {
                tracing::warn!(%error, provider_id = %provider.provider_id, "OIDC UserInfo request failed");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "OIDC federation unavailable.",
                );
            }
        }
    } else {
        None
    };
    // Linking does not create or rotate a local session; upstream logout
    // metadata belongs only to an actual federated login session.
    let upstream = if stored.link_intent.is_none() && provider.backchannel_logout {
        match claims.upstream_login(
            service.tenant_id(),
            &provider.provider_id,
            &provider.client_id,
            stored.created_at,
        ) {
            Ok(mut upstream) => {
                if provider.post_logout_redirect_uri.is_some()
                    && let Some(endpoint) = metadata
                        .and_then(|document| document.end_session_endpoint.as_deref())
                        .and_then(rp::https_endpoint)
                {
                    let logout = UpstreamLogoutRequest {
                        endpoint: endpoint.into(),
                        id_token_hint: token.id_token,
                    };
                    let Some(hint) = logout.seal(provider, upstream.subject_key()) else {
                        return oidc_unavailable();
                    };
                    upstream.encrypted_logout = Some(hint);
                }
                Some(upstream)
            }
            Err(_) => return oidc_access_denied(),
        }
    } else {
        None
    };
    let identity = match claims.into_identity(&provider.provider_id, userinfo) {
        Ok(identity) => identity,
        Err(error) => {
            tracing::warn!(%error, provider_id = %provider.provider_id, "OIDC upstream identity rejected");
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "access_denied",
                "OIDC federation failed.",
            );
        }
    };
    if let Some(intent) = stored.link_intent.as_ref() {
        let Some(sessions) = sessions else {
            return federation_state_error(FederationError::InvalidState);
        };
        let current = match sessions.current_session(req).await {
            Ok(Some(session)) => session,
            Ok(None) => return sessions.login_required_response(),
            Err(error) => return crate::endpoints::sessions::session_lookup_error_response(error),
        };
        if !nazo_identity::session::recent_credential_management_authentication(
            current.auth_time,
            &current.amr,
            current.user.account.mfa_enabled,
            Timestamp::now().as_second(),
        ) {
            return oauth_error(
                StatusCode::PRECONDITION_REQUIRED,
                "reauthentication_required",
                "Linking an external identity requires recent account authentication.",
            );
        }
        let Some(session_id) =
            crate::http::cookie_value(req, sessions.http_config().session_cookie_name())
        else {
            return sessions.login_required_response();
        };
        return match service
            .link_oidc(identity, intent, current.user.user_id(), &session_id)
            .await
        {
            Ok(()) => json_response_no_store(json!({
                "linked": true,
                "provider_id": &provider.provider_id,
            })),
            Err(error) => federation_completion_error(error),
        };
    }
    match service
        .complete_oidc(identity, upstream, client_ip_with_config(req, client_ip))
        .await
    {
        Ok(login) => federation_session_response(config, login),
        Err(error) => federation_completion_error(error),
    }
}

fn oidc_access_denied() -> HttpResponse {
    oauth_error(
        StatusCode::UNAUTHORIZED,
        "access_denied",
        "OIDC federation failed.",
    )
}

pub async fn federation_provider_logout(
    sessions: &nazo_identity::SessionService,
    config: &FederationHttpConfig,
    req: &HttpRequest,
    provider_id: String,
) -> HttpResponse {
    use crate::http::{
        SessionCookieConfig, form_post_authorization_response, login_required_response,
    };
    use nazo_identity::session::SessionResolution;
    let Some(provider) = config.providers.enabled_provider(&provider_id) else {
        return unknown_provider_response();
    };
    let ExternalLoginProviderAdapter::Oidc(provider) = &provider.adapter else {
        return unknown_provider_response();
    };
    let Some(return_uri) = provider.post_logout_redirect_uri.as_ref() else {
        return unknown_provider_response();
    };
    let cookies = SessionCookieConfig::new(
        &config.session_cookie_name,
        &config.csrf_cookie_name,
        config.cookie_secure,
    );
    let Some(session_id) = cookies.session_id(req) else {
        return login_required_response(&cookies);
    };
    let csrf = url::form_urlencoded::parse(req.body())
        .find_map(|(name, value)| (name == "csrf_token").then_some(value));
    if !cookies.has_valid_csrf_token(req, csrf.as_deref()) {
        return crate::http::csrf_error();
    }
    let current = match sessions
        .current(&session_id, Timestamp::now().as_second())
        .await
    {
        Ok(SessionResolution::Present(current)) => current,
        Ok(_) => return login_required_response(&cookies),
        Err(_) => return oidc_unavailable(),
    };
    let logout = current.upstream.as_ref().and_then(|upstream| {
        UpstreamLogoutRequest::open(
            upstream.encrypted_logout.as_deref()?,
            provider,
            &upstream.subject_key,
        )
    });
    let Some(logout) = logout else {
        return crate::http::authorization_error_response(
            StatusCode::CONFLICT,
            "invalid_request",
            "This session has no upstream logout request.",
        );
    };
    form_post_authorization_response(
        &logout.endpoint,
        &[
            ("id_token_hint".into(), logout.id_token_hint),
            ("post_logout_redirect_uri".into(), return_uri.clone()),
        ],
        None,
        nazo_identity::SessionId::generate().as_str(),
    )
}

pub async fn federation_provider_backchannel_logout(
    limiter: &AuthRequestLimiter,
    client_ip: &ClientIpConfig,
    service: &LocalFederationService,
    config: &FederationHttpConfig,
    req: &HttpRequest,
    provider_id: String,
) -> HttpResponse {
    if let Err(response) =
        crate::endpoints::rate_limit::enforce_auth_request_limit(limiter, req, client_ip).await
    {
        return response;
    }
    let Some(provider) = config.providers.enabled_provider(&provider_id) else {
        return unknown_provider_response();
    };
    let ExternalLoginProviderAdapter::Oidc(provider) = &provider.adapter else {
        return unknown_provider_response();
    };
    if !provider.backchannel_logout {
        return unknown_provider_response();
    }

    let invalid_token = || {
        crate::http::authorization_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid OIDC Logout Token.",
        )
    };
    let logout_failed = || {
        crate::http::authorization_error_response(
            StatusCode::BAD_REQUEST,
            "server_error",
            "OIDC logout could not be completed.",
        )
    };
    if !req
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(';').next().is_some_and(|media| {
                media
                    .trim()
                    .eq_ignore_ascii_case("application/x-www-form-urlencoded")
            })
        })
    {
        return invalid_token();
    }
    let mut tokens = url::form_urlencoded::parse(req.body())
        .filter(|(name, _)| name == "logout_token")
        .map(|(_, value)| value);
    let Some(token) = tokens
        .next()
        .filter(|token| token.matches('.').count() == 2)
    else {
        return invalid_token();
    };
    if tokens.next().is_some() {
        return invalid_token();
    }

    let metadata = if provider.discovery {
        match discover_oidc(config.client.as_ref(), provider).await {
            Ok(metadata) => Some(metadata),
            Err(_) => return logout_failed(),
        }
    } else {
        None
    };
    let jwks_url = metadata
        .as_ref()
        .map_or(provider.jwks_url.as_str(), |document| {
            document.jwks_url.as_str()
        });
    let jwks = match fetch_oidc_jwks(config.client.as_ref(), jwks_url, provider.discovery).await {
        Ok(jwks) => jwks,
        Err(_) => return logout_failed(),
    };
    let now = Timestamp::now();
    let logout = match rp::verify_logout_token_with_algorithm(
        service.tenant_id(),
        &provider.provider_id,
        &provider.issuer,
        &provider.client_id,
        &jwks,
        &token,
        now,
        Some(provider.signing_algorithm()),
    ) {
        Ok(logout) => logout,
        Err(_) => return invalid_token(),
    };
    if service.revoke_oidc(logout, now).await.is_err() {
        return logout_failed();
    }
    crate::http::empty_response_no_store(StatusCode::OK)
}

pub async fn social_callback_after_rate_limit(
    service: &LocalFederationService,
    config: &FederationHttpConfig,
    client_ip: &ClientIpConfig,
    req: &HttpRequest,
    query: OidcCallbackQuery,
    provider_id: String,
    provider: &SocialProviderSettings,
) -> HttpResponse {
    let input = match validate_oidc_callback_input(&query) {
        Ok(input) => input,
        Err(response) => return response,
    };
    let Some(browser_binding_seed) = read_federation_binding_seed(req, config) else {
        return federation_state_error(FederationError::InvalidState);
    };
    let stored = match service
        .consume_social(
            input.state_token,
            &provider_id,
            &browser_binding_seed,
            Timestamp::now(),
        )
        .await
    {
        Ok(stored) => stored,
        Err(error) => return federation_state_error(error),
    };
    let identity = match resolve_social_identity(
        config.client.as_ref(),
        provider,
        input.code,
        &stored.pkce_verifier,
    )
    .await
    {
        Ok(identity) => identity,
        Err(_) => {
            tracing::warn!(%provider_id, "OAuth2 social federation failed");
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "access_denied",
                "social federation failed.",
            );
        }
    };
    let existing_only = identity.email.is_none();
    complete_federation(
        service,
        config,
        VerifiedExternalIdentity {
            provider_type: "oauth2_social".to_owned(),
            provider_id,
            subject: identity.subject,
            email: identity.email,
            display_name: identity.display_name,
            claims: identity.claims,
        },
        "oauth2_social",
        client_ip_with_config(req, client_ip),
        existing_only,
    )
    .await
}

pub async fn federation_saml_acs(
    limiter: &AuthRequestLimiter,
    client_ip: &ClientIpConfig,
    service: &LocalFederationService,
    config: &FederationHttpConfig,
    req: &HttpRequest,
    payload: SamlGatewayAssertion,
) -> HttpResponse {
    if let Err(response) =
        crate::endpoints::rate_limit::enforce_auth_request_limit(limiter, req, client_ip).await
    {
        return response;
    }
    let Some(settings) = config.saml_gateway.as_ref() else {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "SAML federation is not configured.",
        );
    };
    let email = match normalize_email_address(&payload.email) {
        Ok(email) => email,
        Err(_) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "SAML email is invalid.",
            );
        }
    };
    if !valid_saml_gateway_assertion(settings, &payload, &email) {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "access_denied",
            "SAML federation failed.",
        );
    }
    if let Err(error) = service
        .consume_saml_assertion(&payload.signature, payload.exp, Timestamp::now())
        .await
    {
        return federation_saml_replay_error(error);
    }
    complete_federation(
        service,
        config,
        VerifiedExternalIdentity {
            provider_type: "saml".to_owned(),
            provider_id: settings.issuer.clone(),
            subject: payload.subject.clone(),
            email: Some(email.clone()),
            // This gateway envelope does not authenticate name. It remains
            // explicitly untrusted link metadata, never local profile identity.
            display_name: None,
            claims: json!({
                "iss": payload.issuer,
                "aud": payload.audience,
                "sub": payload.subject,
                "email": email,
                "untrusted_display_name": payload.name,
            }),
        },
        "saml",
        client_ip_with_config(req, client_ip),
        false,
    )
    .await
}

pub async fn complete_federation(
    service: &LocalFederationService,
    config: &FederationHttpConfig,
    identity: VerifiedExternalIdentity,
    method: &str,
    source_ip: String,
    existing_only: bool,
) -> HttpResponse {
    let result = if existing_only {
        service
            .complete_existing_only(identity, method.to_owned(), source_ip)
            .await
    } else {
        service
            .complete_verified(identity, method.to_owned(), source_ip)
            .await
    };
    match result {
        Ok(success) => federation_session_response(config, success),
        Err(error) => federation_completion_error(error),
    }
}

pub fn federation_session_response(
    config: &FederationHttpConfig,
    success: LoginSuccess,
) -> HttpResponse {
    let mfa_required = success.session.pending_mfa();
    let ttl = if mfa_required {
        config.pending_mfa_session_ttl_seconds
    } else {
        config.session_ttl_seconds
    };
    with_cookie_headers(
        json_response(json!({
            "expires_in": ttl,
            "csrf_token": success.csrf_token,
            "mfa_required": mfa_required
        })),
        &[
            make_cookie(
                &config.session_cookie_name,
                &success.session_id,
                true,
                ttl,
                config.cookie_secure,
            ),
            make_cookie(
                &config.csrf_cookie_name,
                &success.csrf_token,
                false,
                ttl,
                config.cookie_secure,
            ),
        ],
    )
}

#[derive(PartialEq, Eq)]
pub struct OidcCallbackInput<'a> {
    pub state_token: &'a str,
    pub code: &'a str,
}

impl std::fmt::Debug for OidcCallbackInput<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OidcCallbackInput([REDACTED])")
    }
}

pub fn validate_oidc_callback_input(
    query: &OidcCallbackQuery,
) -> Result<OidcCallbackInput<'_>, HttpResponse> {
    if query.error.is_some() {
        return Err(oauth_error(
            StatusCode::UNAUTHORIZED,
            "access_denied",
            "OIDC federation failed.",
        ));
    }
    let state_token = query
        .state
        .as_deref()
        .and_then(nazo_identity::federation::normalize_federation_token)
        .ok_or_else(|| {
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "invalid federation state.",
            )
        })?;
    let code = query
        .code
        .as_deref()
        .filter(|value| !value.is_empty())
        .filter(|value| value.len() <= 4096)
        .ok_or_else(|| {
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "authorization code required.",
            )
        })?;
    Ok(OidcCallbackInput { state_token, code })
}

pub fn provider_view(provider: &ExternalLoginProvider) -> FederationProviderView<'_> {
    FederationProviderView {
        provider_id: &provider.provider_id,
        display_name: &provider.display_name,
        adapter_type: provider.adapter_type(),
        icon: provider.icon.as_deref(),
        display_order: provider.display_order,
        start_url: format!("/auth/federation/{}/start", provider.provider_id),
    }
}

pub fn unknown_provider_response() -> HttpResponse {
    oauth_error(
        StatusCode::NOT_FOUND,
        "invalid_request",
        "federation provider is not configured.",
    )
}

pub fn federation_state_error(error: FederationError) -> HttpResponse {
    match error {
        FederationError::InvalidState => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "invalid federation state.",
        ),
        FederationError::StateExpired | FederationError::ProviderMismatch => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "federation state expired.",
        ),
        error => {
            tracing::warn!(?error, "federation state operation failed");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "federation state failed.",
            )
        }
    }
}

pub fn federation_completion_error(error: FederationError) -> HttpResponse {
    match error {
        FederationError::LinkConflict => oauth_error(
            StatusCode::CONFLICT,
            "invalid_request",
            "This external identity is already bound to another account.",
        ),
        FederationError::VerifiedEmailRequired => oauth_error(
            StatusCode::UNAUTHORIZED,
            "access_denied",
            "verified external email or existing link required.",
        ),
        FederationError::InactiveExistingLink => {
            oauth_error(StatusCode::UNAUTHORIZED, "access_denied", "当前账号已停用.")
        }
        FederationError::LoginFailed => oauth_error(
            StatusCode::UNAUTHORIZED,
            "access_denied",
            "federation login failed.",
        ),
        FederationError::Session(_) | FederationError::SessionCollision => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "session write failed.",
        ),
        error => {
            tracing::warn!(?error, "federation identity resolution failed");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "federation login failed.",
            )
        }
    }
}

pub fn federation_saml_replay_error(error: FederationError) -> HttpResponse {
    match error {
        FederationError::SamlReplay => oauth_error(
            StatusCode::UNAUTHORIZED,
            "access_denied",
            "SAML federation failed.",
        ),
        error => federation_state_error(error),
    }
}
