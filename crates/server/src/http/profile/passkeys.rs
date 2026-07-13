//! Current-user WebAuthn/passkey registration and management.

use actix_web::http::StatusCode;
use actix_web::web::{Data, Json, Path};
use actix_web::{HttpRequest, HttpResponse};
use nazo_http_actix::{
    csrf_error, empty_response, json_response, json_response_status, oauth_error,
};
use nazo_identity::PasskeyError;
use nazo_identity::ports::PasskeyCredential;
use passkey_auth::RegistrationResponse;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::bootstrap::LocalPasskeyService;
use crate::support::sessions::SessionProfileHandles;

#[derive(Deserialize)]
pub(crate) struct PasskeyBeginRequest {
    label: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct PasskeyFinishRequest {
    ceremony_id: String,
    response: RegistrationResponse,
}

pub(crate) async fn passkey_registration_begin(
    sessions: Data<SessionProfileHandles>,
    passkeys: Data<LocalPasskeyService>,
    req: HttpRequest,
    Json(payload): Json<PasskeyBeginRequest>,
) -> HttpResponse {
    if !sessions.has_valid_csrf_token(&req, None) {
        return csrf_error();
    }
    let account = match sessions.current_user_or_login_required(&req).await {
        Ok(account) => account,
        Err(response) => return response,
    };
    match passkeys.registration_begin(&account, payload.label).await {
        Ok(begin) => json_response(json!({
            "ceremony_id": begin.ceremony_id,
            "publicKey": begin.challenge,
        })),
        Err(error) => registration_begin_error(error),
    }
}

pub(crate) async fn passkey_registration_finish(
    sessions: Data<SessionProfileHandles>,
    passkeys: Data<LocalPasskeyService>,
    req: HttpRequest,
    Json(payload): Json<PasskeyFinishRequest>,
) -> HttpResponse {
    if !sessions.has_valid_csrf_token(&req, None) {
        return csrf_error();
    }
    let account = match sessions.current_user_or_login_required(&req).await {
        Ok(account) => account,
        Err(response) => return response,
    };
    match passkeys
        .registration_finish(&account, &payload.ceremony_id, payload.response)
        .await
    {
        Ok(credential) => passkey_created_response(&credential),
        Err(error) => registration_error(error),
    }
}

pub(crate) async fn passkey_list(
    sessions: Data<SessionProfileHandles>,
    passkeys: Data<LocalPasskeyService>,
    req: HttpRequest,
) -> HttpResponse {
    let account = match sessions.current_user_or_login_required(&req).await {
        Ok(account) => account,
        Err(response) => return response,
    };
    match passkeys.list(&account).await {
        Ok(credentials) => passkey_list_response(&credentials),
        Err(error) => passkey_management_error(error, "passkey state unavailable."),
    }
}

pub(crate) async fn passkey_delete(
    sessions: Data<SessionProfileHandles>,
    passkeys: Data<LocalPasskeyService>,
    req: HttpRequest,
    path: Path<Uuid>,
) -> HttpResponse {
    if !sessions.has_valid_csrf_token(&req, None) {
        return csrf_error();
    }
    let account = match sessions.current_user_or_login_required(&req).await {
        Ok(account) => account,
        Err(response) => return response,
    };
    match passkeys.delete(&account, path.into_inner()).await {
        Ok(()) => passkey_delete_response(1),
        Err(PasskeyError::NotFound) => passkey_delete_response(0),
        Err(error) => passkey_management_error(error, "passkey delete failed."),
    }
}

fn passkey_delete_response(deleted_count: usize) -> HttpResponse {
    if deleted_count == 0 {
        return oauth_error(
            StatusCode::NOT_FOUND,
            "invalid_request",
            "passkey not found.",
        );
    }
    empty_response(StatusCode::NO_CONTENT)
}

fn registration_error(error: PasskeyError) -> HttpResponse {
    match error {
        PasskeyError::InvalidLabel => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "passkey label is too long.",
        ),
        PasskeyError::InvalidCeremonyId => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "invalid ceremony id.",
        ),
        PasskeyError::CeremonyExpired => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "passkey ceremony expired.",
        ),
        PasskeyError::CeremonyMismatch => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "passkey ceremony mismatch.",
        ),
        PasskeyError::RegistrationFailed => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "passkey registration failed.",
        ),
        PasskeyError::AlreadyRegistered => oauth_error(
            StatusCode::CONFLICT,
            "invalid_request",
            "passkey already registered.",
        ),
        PasskeyError::CeremonyState(error) => passkey_management_error(
            PasskeyError::CeremonyState(error),
            "passkey state unavailable.",
        ),
        error => passkey_management_error(error, "passkey registration failed."),
    }
}

fn registration_begin_error(error: PasskeyError) -> HttpResponse {
    match error {
        PasskeyError::InvalidLabel => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "passkey label is too long.",
        ),
        error => passkey_management_error(error, "passkey state unavailable."),
    }
}

fn passkey_management_error(error: PasskeyError, description: &'static str) -> HttpResponse {
    tracing::warn!(?error, "passkey operation failed");
    oauth_error(StatusCode::SERVICE_UNAVAILABLE, "server_error", description)
}

fn passkey_public_json(row: &PasskeyCredential) -> Value {
    json!({
        "id": row.id,
        "label": row.label,
        "credential_id": row.credential_id,
        "sign_count": row.sign_count,
        "last_used_at": row.last_used_at,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    })
}

fn passkey_list_response(rows: &[PasskeyCredential]) -> HttpResponse {
    json_response(json!({
        "passkeys": rows.iter().map(passkey_public_json).collect::<Vec<_>>()
    }))
}

fn passkey_created_response(row: &PasskeyCredential) -> HttpResponse {
    json_response_status(StatusCode::CREATED, passkey_public_json(row))
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/profile/tests/passkeys.rs"]
mod tests;
