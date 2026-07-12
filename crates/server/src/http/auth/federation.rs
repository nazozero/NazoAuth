//! External OIDC and trusted SAML-gateway federation.

use crate::http::prelude::*;
use crate::settings::{
    ExternalLoginProvider, ExternalLoginProviderAdapter, OidcFederationSettings,
};
use actix_web::web::Path;
use serde::Serialize;

mod oidc;
mod saml;
mod social;
use oidc::*;
use saml::*;
use social::*;

#[derive(Serialize)]
struct FederationProviderView {
    provider_id: String,
    display_name: String,
    adapter_type: &'static str,
    icon: Option<String>,
    display_order: i32,
    start_url: String,
}

pub(crate) async fn federation_provider_list(state: Data<AppState>) -> HttpResponse {
    // 登录入口只返回已启用 provider 的非敏感元数据；client_secret、
    // token endpoint 等配置绝不能出现在前端响应中。
    let providers = state
        .settings
        .federation
        .providers
        .enabled_public_providers()
        .map(provider_view)
        .collect::<Vec<_>>();
    json_response_no_store(json!({ "providers": providers }))
}

pub(crate) async fn federation_provider_start(
    state: Data<AppState>,
    req: HttpRequest,
    path: Path<String>,
) -> HttpResponse {
    // Actix 的 Path 提取器不暴露内部字段，动态 provider id 通过 into_inner 取得。
    let provider_id = path.into_inner();
    if let Err(response) = enforce_rate_limit(&state, &req, RateLimitPolicy::Auth).await {
        return response;
    }
    let Some(provider) = state
        .settings
        .federation
        .providers
        .enabled_provider(&provider_id)
    else {
        return unknown_provider_response();
    };
    match &provider.adapter {
        ExternalLoginProviderAdapter::Oidc(oidc) => start_oidc_provider(&state, oidc).await,
        ExternalLoginProviderAdapter::Social(social) => {
            start_social_provider(&state, &provider.provider_id, social).await
        }
    }
}

pub(crate) async fn federation_provider_callback(
    state: Data<AppState>,
    req: HttpRequest,
    path: Path<String>,
    Query(query): Query<OidcCallbackQuery>,
) -> HttpResponse {
    // callback 路径中的 provider id 是选择热插拔模块的唯一入口事实源。
    let provider_id = path.into_inner();
    if let Err(response) = enforce_rate_limit(&state, &req, RateLimitPolicy::Auth).await {
        return response;
    }
    let Some(provider) = state
        .settings
        .federation
        .providers
        .enabled_provider(&provider_id)
        .cloned()
    else {
        return unknown_provider_response();
    };
    let provider_id = provider.provider_id.clone();
    match provider.adapter {
        ExternalLoginProviderAdapter::Oidc(oidc) => {
            oidc_callback_after_rate_limit_for_provider(state, req, query, oidc).await
        }
        ExternalLoginProviderAdapter::Social(social) => {
            social_callback_after_rate_limit(state, req, query, provider_id, social).await
        }
    }
}

async fn start_oidc_provider(state: &AppState, provider: &OidcFederationSettings) -> HttpResponse {
    // 每次发起登录都生成 state、nonce 和 PKCE verifier，并把 verifier
    // 只保存在 Valkey 的短 TTL state 中，避免 provider callback 被重放。
    let state_token = random_urlsafe_token();
    let pkce_verifier = random_urlsafe_token();
    let nonce = random_urlsafe_token();
    let stored = OidcFederationState {
        nonce: nonce.clone(),
        pkce_verifier: pkce_verifier.clone(),
        created_at: Utc::now().timestamp(),
    };
    let body = match serde_json::to_string(&stored) {
        Ok(body) => body,
        Err(error) => {
            tracing::warn!(%error, "failed to serialize OIDC federation state");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "federation state failed.",
            );
        }
    };
    if valkey_set_ex(
        &state.valkey,
        oidc_state_key(&state_token),
        body,
        FEDERATION_STATE_TTL_SECONDS,
    )
    .await
    .is_err()
    {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "federation state failed.",
        );
    }
    redirect_found(oidc_authorization_url(
        provider,
        &state_token,
        &nonce,
        &pkce_verifier,
    ))
}

async fn oidc_callback_after_rate_limit_for_provider(
    state: Data<AppState>,
    req: HttpRequest,
    query: OidcCallbackQuery,
    provider: OidcFederationSettings,
) -> HttpResponse {
    let OidcCallbackInput { state_token, code } = match validate_oidc_callback_input(&query) {
        Ok(input) => input,
        Err(response) => return response,
    };
    let stored = match take_oidc_state(&state, &state_token).await {
        Ok(Some(stored)) => stored,
        Ok(None) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "federation state expired.",
            );
        }
        Err(response) => return response,
    };
    if Utc::now().timestamp().saturating_sub(stored.created_at)
        > FEDERATION_STATE_TTL_SECONDS as i64
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "federation state expired.",
        );
    }
    let token = match exchange_oidc_code(&provider, &code, &stored.pkce_verifier).await {
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
    let jwks = match fetch_oidc_jwks(&provider).await {
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
    let claims = match verify_oidc_id_token(&provider, &jwks, &token.id_token, &stored.nonce) {
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
    let email = match claims
        .email
        .as_deref()
        .and_then(|value| normalize_email_address(value).ok())
    {
        Some(email) => email,
        None => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "access_denied",
                "OIDC email claim required.",
            );
        }
    };
    if claims.email_verified != Some(true) {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "access_denied",
            "OIDC email must be verified.",
        );
    }
    let user = match resolve_external_identity(
        &state,
        "oidc",
        &provider.provider_id,
        &claims.sub,
        &email,
        claims.name.as_deref(),
        json!({
            "iss": claims.iss,
            "sub": claims.sub,
            "email": email,
            "name": claims.name,
            "given_name": claims.given_name,
            "family_name": claims.family_name,
        }),
    )
    .await
    {
        Ok(user) => user,
        Err(response) => return response,
    };
    create_federated_session(&state, &req, &user, "oidc").await
}

fn provider_view(provider: &ExternalLoginProvider) -> FederationProviderView {
    // start_url 只包含 provider_id，不包含任何 secret 或 endpoint 配置。
    FederationProviderView {
        provider_id: provider.provider_id.clone(),
        display_name: provider.display_name.clone(),
        adapter_type: provider.adapter_type(),
        icon: provider.icon.clone(),
        display_order: provider.display_order,
        start_url: format!("/auth/federation/{}/start", provider.provider_id),
    }
}

fn unknown_provider_response() -> HttpResponse {
    oauth_error(
        StatusCode::NOT_FOUND,
        "invalid_request",
        "federation provider is not configured.",
    )
}

async fn social_callback_after_rate_limit(
    state: Data<AppState>,
    req: HttpRequest,
    query: OidcCallbackQuery,
    provider_id: String,
    provider: crate::settings::SocialProviderSettings,
) -> HttpResponse {
    let OidcCallbackInput { state_token, code } = match validate_oidc_callback_input(&query) {
        Ok(input) => input,
        Err(response) => return response,
    };
    let stored = match take_social_state(&state, &state_token).await {
        Ok(Some(stored)) if stored.provider_id == provider_id => stored,
        Ok(Some(_)) | Ok(None) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "federation state expired.",
            );
        }
        Err(response) => return response,
    };
    if Utc::now().timestamp().saturating_sub(stored.created_at)
        > FEDERATION_STATE_TTL_SECONDS as i64
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "federation state expired.",
        );
    }
    let identity = match resolve_social_identity(&provider, &code, &stored.pkce_verifier).await {
        Ok(identity) => identity,
        Err(error) => {
            tracing::warn!(%error, %provider_id, "OAuth2 social federation failed");
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "access_denied",
                "social federation failed.",
            );
        }
    };
    complete_social_callback(state, req, provider_id, identity).await
}

async fn complete_social_callback(
    state: Data<AppState>,
    req: HttpRequest,
    provider_id: String,
    identity: SocialIdentity,
) -> HttpResponse {
    let user = if let Some(email) = identity.email.as_deref() {
        match resolve_external_identity(
            &state,
            "oauth2_social",
            &provider_id,
            &identity.subject,
            email,
            identity.display_name.as_deref(),
            identity.claims,
        )
        .await
        {
            Ok(user) => user,
            Err(response) => return response,
        }
    } else {
        match resolve_existing_external_identity(
            &state,
            "oauth2_social",
            &provider_id,
            &identity.subject,
            identity.claims,
        )
        .await
        {
            Ok(Some(user)) => user,
            Ok(None) => {
                return oauth_error(
                    StatusCode::UNAUTHORIZED,
                    "access_denied",
                    "verified external email or existing link required.",
                );
            }
            Err(response) => return response,
        }
    };
    create_federated_session(&state, &req, &user, "oauth2_social").await
}

pub(crate) async fn federation_saml_acs(
    state: Data<AppState>,
    req: HttpRequest,
    Json(payload): Json<SamlGatewayAssertion>,
) -> HttpResponse {
    if let Err(response) = enforce_rate_limit(&state, &req, RateLimitPolicy::Auth).await {
        return response;
    }
    let Some(settings) = state.settings.federation.saml_gateway.clone() else {
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
    if !valid_saml_gateway_assertion(&settings, &payload, &email) {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "access_denied",
            "SAML federation failed.",
        );
    }
    let user = match resolve_external_identity(
        &state,
        "saml",
        &settings.issuer,
        &payload.subject,
        &email,
        payload.name.as_deref(),
        json!({
            "iss": payload.issuer,
            "aud": payload.audience,
            "sub": payload.subject,
            "email": email,
            "name": payload.name,
        }),
    )
    .await
    {
        Ok(user) => user,
        Err(response) => return response,
    };
    create_federated_session(&state, &req, &user, "saml").await
}

#[derive(Debug, PartialEq, Eq)]
struct OidcCallbackInput {
    state_token: String,
    code: String,
}

fn validate_oidc_callback_input(
    query: &OidcCallbackQuery,
) -> Result<OidcCallbackInput, HttpResponse> {
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
        .and_then(normalize_federation_token)
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
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .filter(|value| value.len() <= 4096)
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "authorization code required.",
            )
        })?;
    Ok(OidcCallbackInput { state_token, code })
}

async fn take_oidc_state(
    state: &AppState,
    state_token: &str,
) -> Result<Option<OidcFederationState>, HttpResponse> {
    let raw = valkey_getdel(&state.valkey, oidc_state_key(state_token))
        .await
        .map_err(|error| {
            tracing::warn!(%error, "failed to load OIDC federation state");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "federation state failed.",
            )
        })?;
    raw.map(|value| {
        serde_json::from_str::<OidcFederationState>(&value).map_err(|error| {
            tracing::warn!(%error, "OIDC federation state is malformed");
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "federation state expired.",
            )
        })
    })
    .transpose()
}

async fn resolve_external_identity(
    state: &AppState,
    provider_type: &str,
    provider_id: &str,
    subject: &str,
    email: &str,
    display_name: Option<&str>,
    claims: Value,
) -> Result<PublicAccount, HttpResponse> {
    let tenant = default_tenant_context();
    let identity_tenant = tenant
        .as_identity_context()
        .expect("default tenant IDs are valid");
    let repository = nazo_postgres::FederationRepository::new(state.diesel_db.clone());
    if let Some(user) = repository
        .resolve_existing(nazo_identity::ports::FederationLogin {
            tenant: identity_tenant,
            provider_type: provider_type.into(),
            provider_id: provider_id.into(),
            subject: subject.into(),
            email: Some(email.into()),
            claims: claims.clone(),
        })
        .await
        .map_err(|error| {
            tracing::warn!(%error, "failed to query external identity link");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "federation login failed.",
            )
        })?
    {
        if !user.principal.active {
            return Err(oauth_error(
                StatusCode::UNAUTHORIZED,
                "access_denied",
                "federation login failed.",
            ));
        }
        return Ok(user);
    }
    let user = match find_user_by_email(&state.diesel_db, email).await {
        Ok(Some(_)) => {
            // 第三方 email claim 只能作为已验证联系信息，不能作为账号根身份。
            // 没有既有 external_identity_links 绑定时，遇到同邮箱本地账号必须拒绝，
            // 后续由显式 account linking 流程完成绑定。
            audit_event(
                "external_identity_relink_denied",
                audit_fields(&[
                    ("provider_type", json!(provider_type)),
                    ("provider_id", json!(provider_id)),
                    ("email_hash", json!(blake3_hex(email))),
                ]),
            );
            return Err(oauth_error(
                StatusCode::UNAUTHORIZED,
                "access_denied",
                "federation login failed.",
            ));
        }
        Ok(None) => {
            let password_hash = hash_password(&random_urlsafe_token()).map_err(|error| {
                tracing::warn!(%error, "failed to hash federated user bootstrap password");
                oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "federation login failed.",
                )
            })?;
            let password_hash =
                nazo_identity::PasswordHash::new(password_hash).map_err(|error| {
                    tracing::error!(%error, "generated federation password hash is invalid");
                    oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "federation login failed.",
                    )
                })?;
            repository
                .create_federated(nazo_identity::ports::NewFederatedIdentity {
                    login: nazo_identity::ports::FederationLogin {
                        tenant: identity_tenant,
                        provider_type: provider_type.into(),
                        provider_id: provider_id.into(),
                        subject: subject.into(),
                        email: Some(email.into()),
                        claims,
                    },
                    email: email.into(),
                    display_name: display_name.map(str::to_owned),
                    password_hash,
                })
                .await
                .map_err(|error| {
                    tracing::warn!(%error, "failed to create federated user and link");
                    oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "federation login failed.",
                    )
                })?
        }
        Err(error) => {
            tracing::warn!(%error, "failed to query federation user by email");
            return Err(oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "federation login failed.",
            ));
        }
    };
    audit_event(
        "external_identity_linked",
        audit_fields(&[
            ("user_id", json!(user.id())),
            ("provider_type", json!(provider_type)),
            ("provider_id", json!(provider_id)),
        ]),
    );
    Ok(user)
}

async fn resolve_existing_external_identity(
    state: &AppState,
    provider_type: &str,
    provider_id: &str,
    subject: &str,
    claims: Value,
) -> Result<Option<PublicAccount>, HttpResponse> {
    // QQ/微信这类 social provider 可能不返回 email。此时只能使用已有
    // external_identity_links 绑定登录，不能创建新用户或按 email 自动关联。
    let tenant = default_tenant_context();
    nazo_postgres::FederationRepository::new(state.diesel_db.clone())
        .resolve_existing(nazo_identity::ports::FederationLogin {
            tenant: tenant
                .as_identity_context()
                .expect("default tenant IDs are valid"),
            provider_type: provider_type.into(),
            provider_id: provider_id.into(),
            subject: subject.into(),
            email: None,
            claims,
        })
        .await
        .map_err(|error| {
            tracing::warn!(%error, "failed to query existing external identity link");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "federation login failed.",
            )
        })
}

fn normalize_federation_token(value: &str) -> Option<String> {
    nazo_identity::federation::normalize_federation_token(value)
}

async fn create_federated_session(
    state: &AppState,
    req: &HttpRequest,
    user: &PublicAccount,
    method: &str,
) -> HttpResponse {
    if let Err(response) = require_active_session_principal(user) {
        return response;
    }
    let session_id = random_urlsafe_token();
    let csrf_token = random_urlsafe_token();
    let session = SessionPayload {
        user_id: user.id(),
        auth_time: Utc::now().timestamp(),
        amr: vec![method.to_owned(), "federated".to_owned()],
        pending_mfa: false,
        oidc_sid: Some(random_urlsafe_token()),
    };
    let body = match serde_json::to_string(&session) {
        Ok(body) => body,
        Err(error) => {
            tracing::warn!(%error, "failed to serialize federation session");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "session write failed.",
            );
        }
    };
    if valkey_set_ex(
        &state.valkey,
        format!("oauth:session:{session_id}"),
        body,
        state.settings.session_ttl_seconds,
    )
    .await
    .is_err()
    {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "session write failed.",
        );
    }
    audit_event(
        "federation_login_success",
        audit_fields(&[
            ("user_id", json!(user.id())),
            ("method", json!(method)),
            (
                "source_ip_hash",
                json!(blake3_hex(&client_ip(req, &state.settings))),
            ),
        ]),
    );
    with_cookie_headers(
        json_response(json!({
            "expires_in": state.settings.session_ttl_seconds,
            "csrf_token": csrf_token,
            "mfa_required": false
        })),
        &[
            make_cookie(
                &state.settings.session_cookie_name,
                &session_id,
                true,
                state.settings.session_ttl_seconds,
                state.settings.cookie_secure,
            ),
            make_cookie(
                &state.settings.csrf_cookie_name,
                &csrf_token,
                false,
                state.settings.session_ttl_seconds,
                state.settings.cookie_secure,
            ),
        ],
    )
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/auth/tests/federation.rs"]
mod tests;
