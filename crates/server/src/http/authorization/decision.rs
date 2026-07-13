//! 授权确认提交端点。
#[cfg(test)]
use crate::domain::AppState;
#[cfg(test)]
use crate::domain::DatabaseUserFixture;
use crate::domain::{AuthorizationCodeState, CodePayload, ConsentPayload};
use crate::http::authorization::{
    AuthorizationHttpConfig, AuthorizationRequestContext, ServerAuthorizationService,
};
use crate::runtime_modules::ServerRuntimeModuleRegistry;
#[cfg(test)]
use crate::settings::Settings;
use crate::support::sessions::AdminSessionHandles;
use crate::support::{
    audit::audit_event, audit::audit_fields, client_ip::client_ip_with_config,
    security::blake3_hex, security::random_urlsafe_token, tenancy::default_tenant_context,
};
#[cfg(test)]
use crate::support::{
    tenancy::DEFAULT_ORGANIZATION_ID, tenancy::DEFAULT_REALM_ID, tenancy::DEFAULT_TENANT_ID,
    valkey::valkey_set_ex,
};
use actix_web::http::StatusCode;
#[cfg(test)]
use actix_web::http::header;
use actix_web::web::{Data, Form};
use actix_web::{HttpRequest, HttpResponse};
use chrono::{Duration, Utc};
use nazo_http_actix::{csrf_error, has_valid_csrf_token_for_cookies, oauth_error};
use serde::Deserialize;
#[cfg(test)]
use serde_json::Value;
use serde_json::json;
use uuid::Uuid;
// 同意时签发一次性授权码；拒绝时按 OAuth 规范把错误回传 redirect_uri。
#[cfg(test)]
use super::authorization_response_redirect;
use super::{
    AuthorizationResponseRedirect, PushedAuthorizationRequestConsumeError,
    authorization_response_redirect_with_context,
    consume_pushed_authorization_request_with_context,
};

#[derive(Deserialize)]
pub(crate) struct DecisionForm {
    request_id: String,
    decision: String,
    csrf_token: Option<String>,
}

enum AuthorizationDecision {
    Approve,
    Deny,
}

fn parse_authorization_decision(value: &str) -> Option<AuthorizationDecision> {
    match value {
        "approve" => Some(AuthorizationDecision::Approve),
        "deny" => Some(AuthorizationDecision::Deny),
        _ => None,
    }
}

#[cfg(test)]
fn parse_consent_payload(raw: Option<String>) -> Option<ConsentPayload> {
    raw.and_then(|value| serde_json::from_str::<ConsentPayload>(&value).ok())
}

async fn consume_pushed_request_uri_if_present(
    context: &AuthorizationRequestContext<'_>,
    payload: &ConsentPayload,
) -> Result<(), HttpResponse> {
    let Some(request_uri) = payload.pushed_request_uri.as_deref() else {
        return Ok(());
    };

    match consume_pushed_authorization_request_with_context(context, request_uri).await {
        Ok(()) => Ok(()),
        Err(PushedAuthorizationRequestConsumeError::Missing) => Err(
            authorization_error_redirect_with_context(context, payload, "invalid_request_uri")
                .await,
        ),
        Err(PushedAuthorizationRequestConsumeError::ReadFailed)
        | Err(PushedAuthorizationRequestConsumeError::Malformed) => {
            Err(authorization_error_redirect_with_context(context, payload, "server_error").await)
        }
    }
}

async fn authorization_error_redirect_with_context(
    context: &AuthorizationRequestContext<'_>,
    payload: &ConsentPayload,
    error: &str,
) -> HttpResponse {
    authorization_response_redirect_with_context(
        context,
        AuthorizationResponseRedirect {
            redirect_uri: &payload.redirect_uri,
            client_id: &payload.client_id,
            response_mode: payload.response_mode.as_deref(),
            code: None,
            error: Some(error),
            state: payload.state.as_deref(),
            oidc_sid: None,
        },
    )
    .await
}

#[cfg(test)]
async fn authorization_error_redirect(
    state: &AppState,
    payload: &ConsentPayload,
    error: &str,
) -> HttpResponse {
    let dependencies = super::TestAuthorizationDependencies::new(state);
    authorization_error_redirect_with_context(&dependencies.context(), payload, error).await
}

/// 处理用户对授权请求的同意或拒绝。
pub(crate) async fn authorize_decision(
    service: Data<ServerAuthorizationService>,
    config: Data<AuthorizationHttpConfig>,
    sessions: Data<AdminSessionHandles>,
    runtime_modules: Data<ServerRuntimeModuleRegistry>,
    req: HttpRequest,
    Form(form): Form<DecisionForm>,
) -> HttpResponse {
    let context = AuthorizationRequestContext::new(&service, &config, &sessions, &runtime_modules);
    authorize_decision_with_context(&context, req, form).await
}

async fn authorize_decision_with_context(
    context: &AuthorizationRequestContext<'_>,
    req: HttpRequest,
    form: DecisionForm,
) -> HttpResponse {
    if !has_valid_csrf_token_for_cookies(
        &req,
        form.csrf_token.as_deref(),
        context.sessions.http_config().session_cookie_name(),
        context.sessions.http_config().csrf_cookie_name(),
    ) {
        return csrf_error();
    }
    let Some(decision) = parse_authorization_decision(&form.decision) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "授权决策无效.");
    };
    let user = match context.sessions.current_user_or_login_required(&req).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let payload = match context.service.load_consent(&form.request_id).await {
        Ok(value) => value,
        Err(nazo_auth::AuthorizationPortError::CorruptData) => {
            tracing::warn!("authorization consent state is malformed");
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "授权请求不存在或已过期,请重新发起授权.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to read authorization consent state");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权请求读取失败.",
            );
        }
    };
    let Some(payload) = payload else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "授权请求不存在或已过期,请重新发起授权.",
        );
    };
    if payload.user_id != user.id() {
        return oauth_error(
            StatusCode::FORBIDDEN,
            "access_denied",
            "当前会话与授权请求不匹配.",
        );
    }
    let payload = match context.service.take_consent(&form.request_id).await {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(%error, "failed to consume authorization consent state");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权请求读取失败.",
            );
        }
    };
    let Some(payload) = payload else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "授权请求不存在或已过期,请重新发起授权.",
        );
    };
    if payload.user_id != user.id() {
        return oauth_error(
            StatusCode::FORBIDDEN,
            "access_denied",
            "当前会话与授权请求不匹配.",
        );
    }
    if let Err(response) = consume_pushed_request_uri_if_present(context, &payload).await {
        return response;
    }

    match decision {
        AuthorizationDecision::Deny => {
            audit_event(
                "authorization_denied",
                audit_fields(&[
                    ("user_id", json!(payload.user_id)),
                    ("client_id", json!(payload.client_id)),
                    ("scope", json!(payload.scopes.join(" "))),
                    (
                        "source_ip_hash",
                        json!(blake3_hex(&client_ip_with_config(
                            &req,
                            &context.config.client_ip,
                        ))),
                    ),
                ]),
            );
            return authorization_error_redirect_with_context(context, &payload, "access_denied")
                .await;
        }
        AuthorizationDecision::Approve => {}
    }

    let now = Utc::now();
    let code = random_urlsafe_token();
    let oidc_sid = payload.oidc_sid.clone();
    let code_payload = CodePayload {
        code_id: Uuid::now_v7().to_string(),
        user_id: payload.user_id,
        client_id: payload.client_id.clone(),
        redirect_uri: payload.redirect_uri.clone(),
        redirect_uri_was_supplied: payload.redirect_uri_was_supplied,
        scopes: payload.scopes.clone(),
        resource_indicators: payload.resource_indicators.clone(),
        authorization_details: payload.authorization_details.clone(),
        nonce: payload.nonce,
        auth_time: payload.auth_time,
        amr: payload.amr,
        oidc_sid: payload.oidc_sid,
        acr: payload.acr,
        userinfo_claims: payload.userinfo_claims,
        userinfo_claim_requests: payload.userinfo_claim_requests,
        id_token_claims: payload.id_token_claims,
        id_token_claim_requests: payload.id_token_claim_requests,
        code_challenge: payload.code_challenge,
        code_challenge_method: payload.code_challenge_method,
        dpop_jkt: payload.dpop_jkt,
        mtls_x5t_s256: payload.mtls_x5t_s256,
        issued_at: now,
        expires_at: now + Duration::seconds(context.config.auth_code_ttl_seconds as i64),
    };
    let code_hash = blake3_hex(&code);
    let client = match context.service.client_by_id(&payload.client_id).await {
        Ok(Some(client)) if default_tenant_context().same_tenant(client.tenant_id) => client,
        Ok(_) => {
            tracing::warn!("OAuth client disappeared before grant commit");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权记录写入失败.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to load OAuth client before grant commit");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权记录写入失败.",
            );
        }
    };
    if let Err(error) = context
        .service
        .approve(
            &code_hash,
            &AuthorizationCodeState::Pending {
                payload: code_payload,
            },
            context.config.auth_code_ttl_seconds,
            nazo_auth::GrantWrite {
                tenant_id: client.tenant_id,
                user_id: payload.user_id,
                client_id: client.id,
                scopes: &payload.scopes,
                resource_indicators: &payload.resource_indicators,
                authorization_details: &payload.authorization_details,
            },
        )
        .await
    {
        tracing::warn!(%error, "failed to persist user client grant");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "授权记录写入失败.",
        );
    }

    audit_event(
        "authorization_approved",
        audit_fields(&[
            ("user_id", json!(payload.user_id)),
            ("client_id", json!(payload.client_id)),
            ("scope", json!(payload.scopes.join(" "))),
            (
                "source_ip_hash",
                json!(blake3_hex(&client_ip_with_config(
                    &req,
                    &context.config.client_ip,
                ))),
            ),
        ]),
    );

    authorization_response_redirect_with_context(
        context,
        AuthorizationResponseRedirect {
            redirect_uri: &payload.redirect_uri,
            client_id: &payload.client_id,
            response_mode: payload.response_mode.as_deref(),
            code: Some(&code),
            error: None,
            state: payload.state.as_deref(),
            oidc_sid: oidc_sid.as_deref(),
        },
    )
    .await
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/authorization/tests/decision.rs"]
mod tests;
