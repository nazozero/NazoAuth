// Native regression module: reexports the actual neutral implementation.
pub(crate) use nazoauth::test_support::endpoints::auth::federation::*;
pub(crate) mod oidc;
pub(crate) mod saml;
pub(crate) mod social;
#[path = "../../../unit/http/auth/federation.rs"]
pub(crate) mod tests;

use crate::test_support::http::{ClientIpConfig, client_ip_with_config};
use actix_web::http::StatusCode;
use actix_web::web::{Data, Json, Path, Query};
use actix_web::{HttpRequest, HttpResponse};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use nazo_identity::{LoginSuccess, VerifiedExternalIdentity};
use nazo_oauth_server::rate_limit::AuthRequestLimiter;
use nazo_oauth_server::services::LocalFederationService;
use nazoauth::config::{OidcFederationSettings, SocialProviderSettings};
use oidc::*;
use saml::*;
use serde_json::json;
use social::*;

pub(crate) async fn federation_provider_list(config: Data<FederationHttpConfig>) -> HttpResponse {
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::auth::federation::federation_provider_list(
            config.get_ref(),
        )
        .await,
    )
}

pub(crate) async fn federation_provider_start(
    limiter: Data<AuthRequestLimiter>,
    client_ip: Data<ClientIpConfig>,
    service: Data<LocalFederationService>,
    config: Data<FederationHttpConfig>,
    req: HttpRequest,
    path: Path<String>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_with_client_ip(&req, &client_ip);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::auth::federation::federation_provider_start(
            limiter.get_ref(),
            client_ip.get_ref(),
            service.get_ref(),
            config.get_ref(),
            &request,
            path.into_inner(),
        )
        .await,
    )
}

pub(crate) fn federation_start_response(
    config: &FederationHttpConfig,
    location: String,
    seed: &[u8; 32],
) -> HttpResponse {
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::auth::federation::federation_start_response(
            config, location, seed,
        ),
    )
}

pub(crate) async fn federation_provider_callback(
    limiter: Data<AuthRequestLimiter>,
    client_ip: Data<ClientIpConfig>,
    service: Data<LocalFederationService>,
    config: Data<FederationHttpConfig>,
    req: HttpRequest,
    path: Path<String>,
    Query(query): Query<OidcCallbackQuery>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_with_client_ip(&req, &client_ip);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::auth::federation::federation_provider_callback(
            limiter.get_ref(),
            client_ip.get_ref(),
            service.get_ref(),
            config.get_ref(),
            &request,
            path.into_inner(),
            query,
        )
        .await,
    )
}

pub(crate) async fn oidc_callback_after_rate_limit_for_provider(
    service: Data<LocalFederationService>,
    config: &FederationHttpConfig,
    client_ip: Data<ClientIpConfig>,
    req: HttpRequest,
    query: OidcCallbackQuery,
    provider: &OidcFederationSettings,
) -> HttpResponse {
    let request = crate::test_support::transport::request_with_client_ip(&req, &client_ip);
    nazo_http_actix::forward_response(nazoauth::test_support::endpoints::auth::federation::oidc_callback_after_rate_limit_for_provider(service.get_ref(), config, client_ip.get_ref(), &request, query, provider).await)
}

pub(crate) async fn social_callback_after_rate_limit(
    service: Data<LocalFederationService>,
    config: &FederationHttpConfig,
    client_ip: Data<ClientIpConfig>,
    req: HttpRequest,
    query: OidcCallbackQuery,
    provider_id: String,
    provider: &SocialProviderSettings,
) -> HttpResponse {
    let request = crate::test_support::transport::request_with_client_ip(&req, &client_ip);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::auth::federation::social_callback_after_rate_limit(
            service.get_ref(),
            config,
            client_ip.get_ref(),
            &request,
            query,
            provider_id,
            provider,
        )
        .await,
    )
}

pub(crate) async fn federation_saml_acs(
    limiter: Data<AuthRequestLimiter>,
    client_ip: Data<ClientIpConfig>,
    service: Data<LocalFederationService>,
    config: Data<FederationHttpConfig>,
    req: HttpRequest,
    Json(payload): Json<SamlGatewayAssertion>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_with_client_ip(&req, &client_ip);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::auth::federation::federation_saml_acs(
            limiter.get_ref(),
            client_ip.get_ref(),
            service.get_ref(),
            config.get_ref(),
            &request,
            payload,
        )
        .await,
    )
}

pub(crate) async fn complete_federation(
    service: &LocalFederationService,
    config: &FederationHttpConfig,
    identity: VerifiedExternalIdentity,
    method: &str,
    source_ip: String,
    existing_only: bool,
) -> HttpResponse {
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::auth::federation::complete_federation(
            service,
            config,
            identity,
            method,
            source_ip,
            existing_only,
        )
        .await,
    )
}

pub(crate) fn federation_session_response(
    config: &FederationHttpConfig,
    success: LoginSuccess,
) -> HttpResponse {
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::auth::federation::federation_session_response(
            config, success,
        ),
    )
}

pub(crate) fn validate_oidc_callback_input(
    query: &OidcCallbackQuery,
) -> Result<OidcCallbackInput<'_>, HttpResponse> {
    (nazoauth::test_support::endpoints::auth::federation::validate_oidc_callback_input(query))
        .map_err(nazo_http_actix::forward_response)
}

fn federation_http_client() -> anyhow::Result<crate::adapters::federation_http::FederationClient> {
    crate::adapters::federation_http::FederationClient::new()
}

pub(crate) fn read_federation_binding_seed(
    request: &HttpRequest,
    config: &FederationHttpConfig,
) -> Option<[u8; 32]> {
    nazoauth::test_support::endpoints::auth::federation::read_federation_binding_seed(
        &crate::test_support::transport::request_head(request),
        config,
    )
}
