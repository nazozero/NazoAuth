//! /token grant_type 分发入口。
use std::sync::Arc;

use crate::adapters::security::ClientCredentials;
use crate::adapters::security::blake3_hex;
#[cfg(test)]
use crate::domain::client_policy::authorization_code_key;
#[cfg(test)]
use crate::domain::tenancy::DEFAULT_ORGANIZATION_ID;
#[cfg(test)]
use crate::domain::tenancy::DEFAULT_REALM_ID;
#[cfg(test)]
use crate::domain::tenancy::DEFAULT_TENANT_ID;
use crate::domain::{AuthorizationCodeState, ClientRow};
#[cfg(test)]
use crate::domain::{CodePayload, TestAppState};
use crate::http::client_ip::client_ip_with_context;
use crate::http::dpop::dpop_proof_present;
use crate::http::mtls::client_mtls_certificate_matches;
use crate::http::mtls::request_mtls_client_certificate_from_trusted_proxy;
use crate::http::rate_limit::rate_limited_response;
#[cfg(test)]
use crate::settings::Settings;
use actix_web::http::StatusCode;
#[cfg(test)]
use actix_web::http::header;
use actix_web::web::{Bytes, Data};
use actix_web::{HttpRequest, HttpResponse};
#[cfg(test)]
use base64::Engine;
#[cfg(test)]
use chrono::{Duration, Utc};
#[cfg(test)]
use nazo_http_actix::OAuthJsonErrorFields;
use nazo_http_actix::{TokenClientAuthForm, oauth_token_error, token_client_auth_transport_facts};
#[cfg(test)]
use serde_json::{Value, json};
#[cfg(test)]
use uuid::Uuid;
// 只负责客户端认证与 grant_type 分派，不直接签发令牌。
use super::ciba::{CibaTokenContext, CibaTokenHandles};
use super::client_auth::{
    ClientAuthConfig, TokenManagementClientAuthError, authenticate_client_with_dependencies,
    perform_dummy_client_secret_verification,
};
use super::issue::{TokenIssuanceConfig, TokenIssuanceContext};
use super::{
    CIBA_GRANT_TYPE, DEVICE_CODE_GRANT_TYPE, JWT_BEARER_GRANT_TYPE, ServerTokenService,
    TOKEN_EXCHANGE_GRANT_TYPE, TokenForm, TokenFormError, client_auth_request_facts,
    parse_token_form, token_authorization_code_with_service, token_ciba,
    token_client_credentials_with_service, token_device_code_with_service, token_exchange,
    token_jwt_bearer_with_service, token_refresh_with_service,
};
use crate::http::authorization::ServerAuthorizationService;
use crate::runtime_modules::ServerRuntimeModuleRegistry;
use nazo_auth::{
    CLIENT_ASSERTION_TYPE_JWT_BEARER, ClientAuthenticationContext, ClientProfile,
    ProtocolErrorCode, SecurityProfile, SenderConstraintPolicy,
    token_client_authentication_context, unverified_client_assertion_client_id,
    validate_token_request_profile as validate_auth_token_request_profile,
};

#[cfg(test)]
fn pending_authorization_code_payload(raw: &str) -> Result<Option<CodePayload>, serde_json::Error> {
    match serde_json::from_str::<AuthorizationCodeState>(raw)? {
        AuthorizationCodeState::Pending { payload } => Ok(Some(payload)),
        _ => Ok(None),
    }
}

fn mtls_client_credentials(client_id: String) -> ClientCredentials {
    ClientCredentials {
        client_id: Some(client_id),
        client_secret: None,
        client_assertion: None,
        method: "tls_client_auth".to_owned(),
    }
}

async fn mtls_client_credentials_without_client_id(
    service: &ServerAuthorizationService,
    trusted_proxy_cidrs: &[crate::http::client_ip::IpCidr],
    req: &HttpRequest,
) -> Result<Option<ClientCredentials>, HttpResponse> {
    let Some(certificate) =
        request_mtls_client_certificate_from_trusted_proxy(req, trusted_proxy_cidrs)
    else {
        return Ok(None);
    };
    match service.active_mtls_candidates(1000).await {
        Ok(candidates) => {
            let clients = candidates
                .into_iter()
                .filter(|client| client_mtls_certificate_matches(client, &certificate))
                .take(2)
                .collect::<Vec<_>>();
            Ok(match clients.as_slice() {
                [client] => Some(mtls_client_credentials(client.client_id.clone())),
                _ => None,
            })
        }
        Err(error) => {
            tracing::warn!(%error, "failed to query mTLS client by certificate identity");
            Err(oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端查询失败.",
                false,
            ))
        }
    }
}

fn authorization_code_holder_missing_client_error(
    dpop_bound: bool,
    mtls_bound: bool,
) -> Option<HttpResponse> {
    if mtls_bound {
        return Some(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "authorization code proof of possession validation failed.",
            false,
        ));
    }
    if dpop_bound {
        return Some(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "authorization code proof of possession validation failed.",
            false,
        ));
    }
    None
}

fn client_credentials_holder_missing_client_error(
    form: &TokenForm,
    dpop_present: bool,
) -> Option<HttpResponse> {
    if form.grant_type != "client_credentials" || dpop_present {
        return None;
    }
    Some(oauth_token_error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "client_credentials requires a holder-of-key proof.",
        false,
    ))
}

async fn missing_client_authorization_code_holder_error(
    token_service: &ServerTokenService,
    authorization_service: &ServerAuthorizationService,
    form: &TokenForm,
) -> Option<HttpResponse> {
    if form.grant_type != "authorization_code" {
        return None;
    }
    let code = form.code.as_deref()?;
    let stored = match token_service
        .load_authorization_code(&blake3_hex(code))
        .await
    {
        Ok(Some(value)) => value,
        Ok(None) => return None,
        Err(error) => {
            tracing::warn!(%error, "failed to read authorization code before client authentication");
            return Some(oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权码校验失败.",
                false,
            ));
        }
    };
    let payload = match stored {
        AuthorizationCodeState::Pending { payload } => payload,
        _ => return None,
    };
    if let Some(response) = authorization_code_holder_missing_client_error(
        payload.dpop_jkt.is_some(),
        payload.mtls_x5t_s256.is_some(),
    ) {
        return Some(response);
    }
    match authorization_service.client_by_id(&payload.client_id).await {
        Ok(Some(client))
            if client.require_dpop_bound_tokens || client.require_mtls_bound_tokens =>
        {
            authorization_code_holder_missing_client_error(
                client.require_dpop_bound_tokens,
                client.require_mtls_bound_tokens,
            )
        }
        Ok(_) => None,
        Err(error) => {
            tracing::warn!(%error, "failed to query authorization code client before client authentication");
            Some(oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端查询失败.",
                false,
            ))
        }
    }
}

async fn enforce_token_rate_limit(
    service: &ServerAuthorizationService,
    config: &TokenIssuanceConfig,
    req: &HttpRequest,
) -> Result<(), HttpResponse> {
    let subject = client_ip_with_context(
        req,
        config.client_ip_header_mode(),
        config.trusted_proxy_cidrs(),
    );
    let count = service
        .increment_token_rate(&subject, config.rate_limit_window_seconds())
        .await
        .map_err(|error| {
            tracing::warn!(%error, "token rate limit increment failed");
            oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "请求频率校验失败.",
                false,
            )
        })?;
    if count > config.token_rate_limit_max_requests() {
        return Err(rate_limited_response(config.rate_limit_window_seconds()));
    }
    Ok(())
}

pub(crate) struct TokenEndpointHandles {
    core: TokenCoreHandles,
    ciba: CibaTokenHandles,
    issuance_config: Data<TokenIssuanceConfig>,
    runtime_modules: Data<ServerRuntimeModuleRegistry>,
    remote_client_documents:
        Arc<crate::domain::remote_client_documents::RemoteClientDocumentResolver>,
    openid4vc: Openid4vcTokenHandles,
}

pub(crate) struct TokenCoreHandles {
    pub(crate) token_service: Data<ServerTokenService>,
    pub(crate) authorization_service: Data<ServerAuthorizationService>,
    pub(crate) device_service: Data<super::device::ServerDeviceGrantService>,
}

#[derive(Default)]
pub(crate) struct Openid4vcTokenHandles {
    pub(crate) credential_issuer: Option<Data<nazo_openid4vc_http_actix::CredentialIssuerEndpoint>>,
    pub(crate) client_attestation: Option<Arc<crate::domain::Openid4vcClientAttestationValidator>>,
}

impl TokenEndpointHandles {
    pub(crate) fn new(
        core: TokenCoreHandles,
        ciba: CibaTokenHandles,
        issuance_config: Data<TokenIssuanceConfig>,
        runtime_modules: Data<ServerRuntimeModuleRegistry>,
        remote_client_documents: Arc<
            crate::domain::remote_client_documents::RemoteClientDocumentResolver,
        >,
        openid4vc: Openid4vcTokenHandles,
    ) -> Self {
        Self {
            core,
            ciba,
            issuance_config,
            runtime_modules,
            remote_client_documents,
            openid4vc,
        }
    }
}

pub(crate) async fn token_with_service(
    handles: Data<TokenEndpointHandles>,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    let token_service = handles.core.token_service.get_ref();
    let authorization_service = handles.core.authorization_service.get_ref();
    let issuance_config = handles.issuance_config.get_ref();
    let device_service = handles.core.device_service.get_ref();
    let runtime_modules = handles.runtime_modules.get_ref();
    if let Err(response) =
        enforce_token_rate_limit(authorization_service, issuance_config, &req).await
    {
        return response;
    }

    let form = match parse_token_form(&req, &body) {
        Ok(form) => form,
        Err(TokenFormError::InvalidContentType) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "token 请求必须使用 application/x-www-form-urlencoded.",
                false,
            );
        }
        Err(TokenFormError::InvalidEncoding) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "token 请求体必须使用 UTF-8 编码.",
                false,
            );
        }
        Err(TokenFormError::DuplicateParameter) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "OAuth 参数不能重复.",
                false,
            );
        }
        Err(TokenFormError::InvalidResourceParameter) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_target",
                "resource must be an absolute URI without a fragment.",
                false,
            );
        }
        Err(TokenFormError::MissingGrantType) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "缺少 grant_type.",
                false,
            );
        }
    };
    if form.has_audience_param && form.grant_type != TOKEN_EXCHANGE_GRANT_TYPE {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "audience is only valid for OAuth token exchange; use RFC 8707 resource elsewhere.",
            false,
        );
    }

    if form.grant_type == nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT {
        let Some(endpoint) = handles.openid4vc.credential_issuer.as_ref() else {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                "OpenID4VCI pre-authorized issuance is not configured.",
                false,
            );
        };
        let (pre_authorized_code, tx_code) = match pre_authorized_parameters(&body) {
            Ok(parameters) => parameters,
            Err(response) => return response,
        };
        let response = endpoint
            .pre_authorized_token(nazo_openid4vc_http_actix::PreAuthorizedTokenRequest {
                pre_authorized_code,
                tx_code,
                client_id: form.client_id.clone(),
                dpop_proof: req
                    .headers()
                    .get("DPoP")
                    .and_then(|value| value.to_str().ok())
                    .map(ToOwned::to_owned),
                client_attestation: req
                    .headers()
                    .get("OAuth-Client-Attestation")
                    .and_then(|value| value.to_str().ok())
                    .map(ToOwned::to_owned),
                client_attestation_pop: req
                    .headers()
                    .get("OAuth-Client-Attestation-PoP")
                    .and_then(|value| value.to_str().ok())
                    .map(ToOwned::to_owned),
                request_url: format!(
                    "{}{}",
                    issuance_config.issuer().trim_end_matches('/'),
                    req.uri()
                ),
            })
            .await;
        return match response {
            Ok(response) => HttpResponse::Ok()
                .insert_header((actix_web::http::header::CACHE_CONTROL, "no-store"))
                .json(response),
            Err(error) => oauth_token_error(
                StatusCode::from_u16(error.status).unwrap_or(StatusCode::BAD_REQUEST),
                error.error,
                error.description,
                false,
            ),
        };
    }

    if issuance_config
        .authorization_server_profile()
        .requires_fapi2_security()
        && form.grant_type == "password"
    {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "FAPI2 profiles do not allow resource owner password credentials.",
            false,
        );
    }
    let auth_facts = token_client_auth_transport_facts(
        &req,
        TokenClientAuthForm {
            client_id: form.client_id.as_deref(),
            client_secret: form.client_secret.as_deref(),
            client_assertion_type: form.client_assertion_type.as_deref(),
            client_assertion: form.client_assertion.as_deref(),
        },
    );
    let client_auth_context = match token_client_authentication_context(auth_facts.presentation()) {
        Ok(context) => context,
        Err(_) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "同一 token 请求不能同时使用多种客户端认证方式.",
                false,
            );
        }
    };
    let attestation_headers = match client_attestation_headers(&req) {
        Ok(headers) => headers,
        Err(response) => return response,
    };
    if attestation_headers.is_some() && client_auth_context.has_any_client_auth_material {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Client attestation cannot be combined with another client authentication method.",
            false,
        );
    }
    let has_basic = client_auth_context.http_basic;
    let has_client_auth_material = client_auth_context.has_any_client_auth_material;
    let assertion_client_id = auth_facts
        .client_assertion()
        .filter(|_| auth_facts.client_assertion_type() == Some(CLIENT_ASSERTION_TYPE_JWT_BEARER))
        .and_then(unverified_client_assertion_client_id);
    let form_mtls_client_id =
        if !has_basic && !client_auth_context.has_assertion && form.client_secret.is_none() {
            form.client_id
                .as_ref()
                .filter(|_| {
                    request_mtls_client_certificate_from_trusted_proxy(
                        &req,
                        issuance_config.trusted_proxy_cidrs(),
                    )
                    .is_some()
                })
                .cloned()
        } else {
            None
        };
    let mut credentials =
        auth_facts.presented_credentials(assertion_client_id, form_mtls_client_id);
    if let Some((attestation, _)) = attestation_headers {
        credentials = ClientCredentials {
            client_id: crate::domain::Openid4vcClientAttestationValidator::unverified_client_id(
                attestation,
            ),
            client_secret: None,
            client_assertion: None,
            method: "attest_jwt_client_auth".to_owned(),
        };
    }
    if credentials.client_id.is_none()
        && !has_basic
        && form.client_secret.is_none()
        && !client_auth_context.has_assertion
    {
        match mtls_client_credentials_without_client_id(
            authorization_service,
            issuance_config.trusted_proxy_cidrs(),
            &req,
        )
        .await
        {
            Ok(Some(mtls_credentials)) => credentials = mtls_credentials,
            Ok(None) => {}
            Err(response) => return response,
        }
    }
    let Some(client_id) = credentials.client_id.as_deref() else {
        if !has_client_auth_material {
            if let Some(response) =
                client_credentials_holder_missing_client_error(&form, dpop_proof_present(&req))
            {
                return response;
            }
            if let Some(response) = missing_client_authorization_code_holder_error(
                token_service,
                authorization_service,
                &form,
            )
            .await
            {
                return response;
            }
        }
        return oauth_token_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "客户端认证失败.",
            has_basic,
        );
    };
    let client = match authorization_service.client_by_id(client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => {
            perform_dummy_client_secret_verification(
                &credentials,
                issuance_config.client_secret_pepper(),
            );
            return oauth_token_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "客户端不存在或已停用.",
                has_basic,
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to query oauth client for token request");
            return oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端查询失败.",
                false,
            );
        }
    };
    if let Err(response) = validate_token_client_enabled(&client, &form.grant_type) {
        return response;
    }
    let auth_request = client_auth_request_facts(&req, issuance_config.trusted_proxy_cidrs());
    let client_assertion = if let Some((attestation, proof)) = attestation_headers {
        if client.token_endpoint_auth_method != "attest_jwt_client_auth" {
            return oauth_token_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client_attestation",
                "Client attestation is not registered for this client.",
                false,
            );
        }
        let Some(validator) = handles.openid4vc.client_attestation.as_ref() else {
            return oauth_token_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client_attestation",
                "Client attestation is not configured.",
                false,
            );
        };
        let validated = match validator.validate(
            attestation,
            proof,
            issuance_config.issuer(),
            chrono::Utc::now().timestamp(),
        ) {
            Ok(validated) if validated.client_id == client.client_id => validated,
            _ => {
                return oauth_token_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client_attestation",
                    "Client attestation validation failed.",
                    false,
                );
            }
        };
        let replay_key = format!("client-attestation:{}", validated.client_id);
        match authorization_service
            .consume_private_key_jwt(
                &replay_key,
                &validated.replay_id,
                validated.replay_ttl_seconds,
            )
            .await
        {
            Ok(true) => None,
            Ok(false) => {
                return oauth_token_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client_attestation",
                    "Client attestation proof was replayed.",
                    false,
                );
            }
            Err(_) => {
                return oauth_token_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "Client attestation replay state is unavailable.",
                    false,
                );
            }
        }
    } else {
        match authenticate_client_with_dependencies(
            authorization_service,
            ClientAuthConfig::new(
                issuance_config.issuer(),
                issuance_config.client_secret_pepper(),
            )
            .with_remote_jwks(&handles.remote_client_documents),
            &auth_request,
            &client,
            &credentials,
            ClientAuthenticationContext::AllowPublicNone,
        )
        .await
        {
            Ok(assertion) => assertion,
            Err(TokenManagementClientAuthError::PublicClientCredentialsForbidden) => {
                return oauth_token_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client",
                    "public 客户端不能使用 client_secret.",
                    has_basic,
                );
            }
            Err(TokenManagementClientAuthError::InvalidClient) => {
                return oauth_token_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client",
                    "客户端认证失败.",
                    has_basic && credentials.method != "private_key_jwt",
                );
            }
            Err(TokenManagementClientAuthError::StoreUnavailable) => {
                return oauth_token_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "客户端认证状态不可用.",
                    false,
                );
            }
        }
    };
    if let Err(response) = validate_token_request_profile_with_profile(
        issuance_config.authorization_server_profile(),
        &client,
        client.token_endpoint_auth_method.as_str(),
    ) {
        return response;
    }
    let modules = runtime_modules.snapshot();
    let issuance = TokenIssuanceContext {
        config: issuance_config,
        modules: &modules,
        authorization: authorization_service,
    };
    match form.grant_type.as_str() {
        "authorization_code" => {
            token_authorization_code_with_service(
                token_service,
                &issuance,
                &req,
                &client,
                &form,
                client_assertion.as_ref(),
            )
            .await
        }
        "refresh_token" => {
            token_refresh_with_service(
                token_service,
                &issuance,
                &req,
                &client,
                &form,
                client_assertion.as_ref(),
            )
            .await
        }
        "client_credentials" => {
            token_client_credentials_with_service(
                token_service,
                authorization_service,
                &issuance,
                &req,
                &client,
                &form,
                client_assertion.as_ref(),
            )
            .await
        }
        JWT_BEARER_GRANT_TYPE => {
            token_jwt_bearer_with_service(
                token_service,
                &issuance,
                &req,
                &client,
                &form,
                client_assertion.as_ref(),
            )
            .await
        }
        DEVICE_CODE_GRANT_TYPE => {
            token_device_code_with_service(
                token_service,
                &issuance,
                device_service,
                &req,
                &client,
                &form,
                client_assertion.as_ref(),
            )
            .await
        }
        CIBA_GRANT_TYPE => {
            token_ciba(
                CibaTokenContext {
                    token_service,
                    issuance: &issuance,
                    handles: &handles.ciba,
                    request: &req,
                },
                &client,
                &form,
                client_assertion.as_ref(),
                client.token_endpoint_auth_method.as_str(),
            )
            .await
        }
        TOKEN_EXCHANGE_GRANT_TYPE => {
            token_exchange(
                token_service,
                authorization_service,
                &issuance,
                &req,
                &client,
                &form,
                client_assertion.as_ref(),
            )
            .await
        }
        _ => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "不支持的 grant_type.",
            false,
        ),
    }
}

fn pre_authorized_parameters(body: &Bytes) -> Result<(String, Option<String>), HttpResponse> {
    let mut pre_authorized_code = None;
    let mut tx_code = None;
    for (name, value) in url::form_urlencoded::parse(body) {
        match name.as_ref() {
            "pre-authorized_code" if pre_authorized_code.is_none() && !value.is_empty() => {
                pre_authorized_code = Some(value.into_owned());
            }
            "tx_code" if tx_code.is_none() && !value.is_empty() => {
                tx_code = Some(value.into_owned());
            }
            "pre-authorized_code" | "tx_code" => {
                return Err(oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "Pre-authorized issuance parameters must be non-empty and must not repeat.",
                    false,
                ));
            }
            _ => {}
        }
    }
    pre_authorized_code
        .map(|code| (code, tx_code))
        .ok_or_else(|| {
            oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "pre-authorized_code is required.",
                false,
            )
        })
}

fn client_attestation_headers(request: &HttpRequest) -> Result<Option<(&str, &str)>, HttpResponse> {
    let attestation = request
        .headers()
        .get("OAuth-Client-Attestation")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty());
    let proof = request
        .headers()
        .get("OAuth-Client-Attestation-PoP")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty());
    match (attestation, proof) {
        (None, None) => Ok(None),
        (Some(attestation), Some(proof)) => Ok(Some((attestation, proof))),
        _ => Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Both client attestation headers are required.",
            false,
        )),
    }
}

#[cfg(not(test))]
pub(crate) use token_with_service as token;

#[cfg(test)]
pub(crate) async fn token(
    state: Data<TestAppState>,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    let service = Data::new(ServerTokenService::new(
        nazo_postgres::TokenIssuanceRepository::new(state.diesel_db.clone()),
        nazo_valkey::TokenIssuanceStateAdapter::new(&state.valkey_connection()),
        state.keyset.clone(),
    ));
    let connection = state.valkey_connection();
    let authorization_service = Data::new(ServerAuthorizationService::new(
        nazo_postgres::AuthorizationFlowRepository::new(state.diesel_db.clone(), DEFAULT_TENANT_ID),
        nazo_valkey::AuthorizationStateAdapter::new(&connection),
        state.keyset.clone(),
    ));
    let ciba_service = Data::new(super::ciba::ServerCibaService::new(
        nazo_valkey::CibaStore::new(&connection),
    ));
    let ciba_users = Data::new(nazo_postgres::UserRepository::new(state.diesel_db.clone()));
    let ciba_config = Data::new(super::ciba::CibaHttpConfig::from(state.settings.as_ref()));
    let issuance_config = Data::new(TokenIssuanceConfig::from(state.settings.as_ref()));
    let device_service = Data::new(super::device::ServerDeviceGrantService::new(
        nazo_valkey::DeviceStore::new(&connection),
    ));
    let runtime_modules = Data::from(
        crate::runtime_modules::runtime_module_registry_for_test(
            state.diesel_db.clone(),
            state.settings.as_ref(),
        )
        .expect("test runtime module registry should be valid"),
    );
    token_with_service(
        Data::new(TokenEndpointHandles::new(
            TokenCoreHandles {
                token_service: service,
                authorization_service,
                device_service,
            },
            CibaTokenHandles::new(ciba_service, ciba_users, ciba_config),
            issuance_config,
            runtime_modules,
            Arc::new(
                crate::domain::remote_client_documents::RemoteClientDocumentResolver::new(&[])
                    .expect("empty remote document policy is valid"),
            ),
            Openid4vcTokenHandles::default(),
        )),
        req,
        body,
    )
    .await
}

fn validate_token_client_enabled(client: &ClientRow, grant_type: &str) -> Result<(), HttpResponse> {
    if !client.is_active || !client.grant_types.iter().any(|grant| grant == grant_type) {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "该客户端未启用当前授权类型.",
            false,
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn validate_token_request_profile(
    settings: &Settings,
    client: &ClientRow,
    auth_method: &str,
) -> Result<(), HttpResponse> {
    validate_token_request_profile_with_profile(
        settings.protocol.authorization_server_profile,
        client,
        auth_method,
    )
}

fn validate_token_request_profile_with_profile(
    server_profile: crate::settings::AuthorizationServerProfile,
    client: &ClientRow,
    auth_method: &str,
) -> Result<(), HttpResponse> {
    let profile = if server_profile.requires_fapi2_security() {
        SecurityProfile::Fapi2Security
    } else {
        SecurityProfile::Baseline
    };
    let sender_constraint = match (
        client.require_dpop_bound_tokens,
        client.require_mtls_bound_tokens,
    ) {
        (false, false) => SenderConstraintPolicy::BearerAllowed,
        (true, false) => SenderConstraintPolicy::DpopRequired,
        (false, true) => SenderConstraintPolicy::MtlsRequired,
        (true, true) => SenderConstraintPolicy::DpopOrMtls,
    };
    validate_auth_token_request_profile(
        profile,
        ClientProfile {
            client_type: &client.client_type,
            authentication_method: auth_method,
            sender_constraint,
        },
    )
    .map_err(|error| {
        let status = if error.code == ProtocolErrorCode::InvalidClient {
            StatusCode::UNAUTHORIZED
        } else {
            StatusCode::BAD_REQUEST
        };
        oauth_token_error(status, error.code.as_str(), error.description, false)
    })
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/token/tests/dispatch.rs"]
mod tests;
