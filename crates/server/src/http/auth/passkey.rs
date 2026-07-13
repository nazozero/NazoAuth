//! WebAuthn/passkey login endpoints.

use actix_web::http::{StatusCode, header};
use actix_web::web::{Data, Json};
use actix_web::{HttpRequest, HttpResponse};
use chrono::Utc;
use nazo_http_actix::{cookie_value, json_response, make_cookie, oauth_error, with_cookie_headers};
use nazo_identity::{PasskeyError, RememberedMfaProof};
use passkey_auth::AuthenticationResponse;
use serde::Deserialize;
use serde_json::json;

use crate::bootstrap::LocalPasskeyService;
use crate::domain::MFA_REMEMBERED_COOKIE_NAME;
use crate::support::client_ip::{ClientIpConfig, client_ip_with_config};
use crate::support::{rate_limit::AuthRequestLimiter, security::blake3_hex};

#[derive(Clone)]
pub(crate) struct PasskeyHttpConfig {
    session_cookie_name: String,
    csrf_cookie_name: String,
    session_ttl_seconds: u64,
    cookie_secure: bool,
}

impl PasskeyHttpConfig {
    pub(crate) fn new(
        session_cookie_name: impl Into<String>,
        csrf_cookie_name: impl Into<String>,
        session_ttl_seconds: u64,
        cookie_secure: bool,
    ) -> Self {
        Self {
            session_cookie_name: session_cookie_name.into(),
            csrf_cookie_name: csrf_cookie_name.into(),
            session_ttl_seconds,
            cookie_secure,
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct PasskeyLoginBeginRequest {
    email: String,
}

#[derive(Deserialize)]
pub(crate) struct PasskeyLoginFinishRequest {
    ceremony_id: String,
    response: AuthenticationResponse,
}

pub(crate) async fn passkey_login_begin(
    rate_limiter: Data<AuthRequestLimiter>,
    passkeys: Data<LocalPasskeyService>,
    req: HttpRequest,
    Json(payload): Json<PasskeyLoginBeginRequest>,
) -> HttpResponse {
    if let Err(response) = rate_limiter.enforce(&req).await {
        return response;
    }
    match passkeys
        .login_begin(payload.email.trim().to_lowercase())
        .await
    {
        Ok(begin) => json_response(json!({
            "ceremony_id": begin.ceremony_id,
            "publicKey": begin.challenge,
        })),
        Err(error) => passkey_login_error(error),
    }
}

pub(crate) async fn passkey_login_finish(
    rate_limiter: Data<AuthRequestLimiter>,
    client_ip_config: Data<ClientIpConfig>,
    passkeys: Data<LocalPasskeyService>,
    http_config: Data<PasskeyHttpConfig>,
    req: HttpRequest,
    Json(payload): Json<PasskeyLoginFinishRequest>,
) -> HttpResponse {
    if let Err(response) = rate_limiter.enforce(&req).await {
        return response;
    }
    let result = passkeys
        .login_finish(
            &payload.ceremony_id,
            payload.response,
            client_ip_with_config(&req, client_ip_config.get_ref()),
            remembered_mfa_proof(&req),
            Utc::now(),
        )
        .await;
    match result {
        Ok(success) => passkey_session_response(http_config.get_ref(), success),
        Err(error) => passkey_login_error(error),
    }
}

fn passkey_login_error(error: PasskeyError) -> HttpResponse {
    match error {
        PasskeyError::InvalidCeremonyId => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "invalid ceremony id.",
        ),
        PasskeyError::InvalidCredentialId => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "invalid passkey credential id.",
        ),
        PasskeyError::CeremonyExpired => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "passkey ceremony expired.",
        ),
        PasskeyError::Account(error) => {
            tracing::warn!(%error, "failed to query user for passkey login");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "user lookup failed.",
            )
        }
        PasskeyError::State(error) | PasskeyError::CeremonyState(error) => {
            tracing::warn!(%error, "passkey login state unavailable");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "passkey state unavailable.",
            )
        }
        PasskeyError::Mfa(error) => {
            tracing::warn!(%error, "failed to check remembered MFA device for passkey login");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "MFA state lookup failed.",
            )
        }
        PasskeyError::Session(error) => {
            tracing::warn!(%error, "failed to store passkey login session");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "session write failed.",
            )
        }
        PasskeyError::SessionCollision => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "session write failed.",
        ),
        _ => oauth_error(
            StatusCode::UNAUTHORIZED,
            "access_denied",
            "passkey login failed.",
        ),
    }
}

fn remembered_mfa_proof(req: &HttpRequest) -> Option<RememberedMfaProof> {
    let token = cookie_value(req, MFA_REMEMBERED_COOKIE_NAME)?;
    let user_agent_hash = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(blake3_hex);
    Some(RememberedMfaProof {
        token_hash: blake3_hex(token.trim()),
        user_agent_hash,
    })
}

fn passkey_session_response(
    config: &PasskeyHttpConfig,
    success: nazo_identity::LoginSuccess,
) -> HttpResponse {
    let cookies = [
        make_cookie(
            &config.session_cookie_name,
            &success.session_id,
            true,
            config.session_ttl_seconds,
            config.cookie_secure,
        ),
        make_cookie(
            &config.csrf_cookie_name,
            &success.csrf_token,
            false,
            config.session_ttl_seconds,
            config.cookie_secure,
        ),
    ];
    with_cookie_headers(
        json_response(json!({
            "expires_in": config.session_ttl_seconds,
            "csrf_token": success.csrf_token,
            "mfa_required": success.session.pending_mfa(),
        })),
        &cookies,
    )
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/auth/tests/passkey.rs"]
mod tests;
