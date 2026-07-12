//! Current-user WebAuthn/passkey registration and management.

use passkey_auth::RegistrationResponse;

use crate::http::prelude::*;

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
    state: Data<AppState>,
    req: HttpRequest,
    Json(payload): Json<PasskeyBeginRequest>,
) -> HttpResponse {
    if !has_valid_csrf_token(&state, &req, None) {
        return csrf_error();
    }
    let user = match current_user_or_login_required(&state, &req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let label = match normalize_passkey_label(payload.label) {
        Ok(label) => label,
        Err(response) => return response,
    };
    let existing = match load_user_passkeys(&state, &user).await {
        Ok(rows) => rows,
        Err(response) => return response,
    };
    let existing_ids = match passkey_credential_ids(&existing) {
        Ok(ids) => ids,
        Err(error) => {
            tracing::warn!(%error, user_id = %user.id(), "stored passkey credential is malformed");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "passkey state unavailable.",
            );
        }
    };
    let webauthn = passkey_webauthn(&state.settings);
    let user_handle = match passkey_user_handle(&user) {
        Ok(user_handle) => user_handle,
        Err(error) => {
            tracing::warn!(%error, user_id = %user.id(), "stored passkey owner identifiers are invalid");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "passkey state unavailable.",
            );
        }
    };
    let (challenge, registration_state) = webauthn.start_registration(
        &user_handle,
        &user.account.email,
        user.profile
            .display_name
            .as_deref()
            .unwrap_or(&user.account.email),
        &existing_ids,
    );
    let ceremony_id = random_urlsafe_token();
    let stored = StoredPasskeyRegistration {
        user_id: user.id(),
        tenant_id: user.tenant_id(),
        label,
        state: registration_state,
    };
    if let Err(error) =
        store_passkey_ceremony(&state, registration_key(&ceremony_id), &stored).await
    {
        tracing::warn!(%error, user_id = %user.id(), "failed to store passkey registration ceremony");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "passkey state unavailable.",
        );
    }

    json_response(json!({
        "ceremony_id": ceremony_id,
        "publicKey": challenge
    }))
}

pub(crate) async fn passkey_registration_finish(
    state: Data<AppState>,
    req: HttpRequest,
    Json(payload): Json<PasskeyFinishRequest>,
) -> HttpResponse {
    if !has_valid_csrf_token(&state, &req, None) {
        return csrf_error();
    }
    let user = match current_user_or_login_required(&state, &req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let ceremony_id = match normalize_ceremony_id(&payload.ceremony_id) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let stored = match take_passkey_ceremony::<StoredPasskeyRegistration>(
        &state,
        registration_key(&ceremony_id),
    )
    .await
    {
        Ok(Some(stored)) => stored,
        Ok(None) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "passkey ceremony expired.",
            );
        }
        Err(response) => return response,
    };
    if stored.user_id != user.id() || stored.tenant_id != user.tenant_id() {
        audit_event(
            "passkey_registration_rejected",
            audit_fields(&[
                ("user_id", json!(user.id())),
                ("reason", json!("ceremony_user_mismatch")),
            ]),
        );
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "passkey ceremony mismatch.",
        );
    }
    let credential = match passkey_webauthn(&state.settings)
        .finish_registration(&stored.state, &payload.response)
    {
        Ok(credential) => credential,
        Err(error) => {
            audit_event(
                "passkey_registration_rejected",
                audit_fields(&[
                    ("user_id", json!(user.id())),
                    ("reason", json!(error.to_string())),
                ]),
            );
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "passkey registration failed.",
            );
        }
    };
    let credential_id = passkey_credential_id(&credential);
    let credential_json = match serde_json::to_value(&credential) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(%error, "failed to serialize passkey credential");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "passkey registration failed.",
            );
        }
    };
    let inserted = nazo_postgres::PasskeyRepository::new(state.diesel_db.clone())
        .insert(
            user.tenant().tenant_id,
            user.user_id(),
            credential_id,
            credential_json,
            stored.label,
            i64::from(credential.counter),
        )
        .await;
    match inserted {
        Ok(row) => {
            audit_event(
                "passkey_registered",
                audit_fields(&[
                    ("user_id", json!(user.id())),
                    ("credential_id", json!(row.id)),
                ]),
            );
            passkey_created_response(&row)
        }
        Err(nazo_identity::ports::RepositoryError::Conflict) => {
            passkey_already_registered_response()
        }
        Err(error) => {
            tracing::warn!(%error, "failed to insert passkey credential");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "passkey registration failed.",
            )
        }
    }
}

pub(crate) async fn passkey_list(state: Data<AppState>, req: HttpRequest) -> HttpResponse {
    let user = match current_user_or_login_required(&state, &req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let rows = match load_user_passkeys(&state, &user).await {
        Ok(rows) => rows,
        Err(response) => return response,
    };
    passkey_list_response(&rows)
}

fn passkey_list_response(rows: &[PasskeyCredential]) -> HttpResponse {
    json_response(json!({
        "passkeys": rows.iter().map(passkey_public_json).collect::<Vec<_>>()
    }))
}

fn passkey_created_response(row: &PasskeyCredential) -> HttpResponse {
    json_response_status(StatusCode::CREATED, passkey_public_json(row))
}

fn passkey_already_registered_response() -> HttpResponse {
    oauth_error(
        StatusCode::CONFLICT,
        "invalid_request",
        "passkey already registered.",
    )
}

pub(crate) async fn passkey_delete(
    state: Data<AppState>,
    req: HttpRequest,
    path: actix_web::web::Path<Uuid>,
) -> HttpResponse {
    if !has_valid_csrf_token(&state, &req, None) {
        return csrf_error();
    }
    let user = match current_user_or_login_required(&state, &req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    match nazo_postgres::PasskeyRepository::new(state.diesel_db.clone())
        .delete(user.tenant().tenant_id, user.user_id(), path.into_inner())
        .await
    {
        Ok(deleted) => passkey_delete_response(usize::from(deleted)),
        Err(error) => {
            tracing::warn!(%error, "failed to delete passkey credential");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "passkey delete failed.",
            )
        }
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

pub(crate) async fn load_user_passkeys(
    state: &AppState,
    user: &PublicAccount,
) -> Result<Vec<PasskeyCredential>, HttpResponse> {
    nazo_postgres::PasskeyRepository::new(state.diesel_db.clone())
        .list(user.tenant().tenant_id, user.user_id())
        .await
        .map_err(|error| {
            tracing::warn!(%error, user_id = %user.id(), "failed to load passkey credentials");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "passkey state unavailable.",
            )
        })
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/profile/tests/passkeys.rs"]
mod tests;
