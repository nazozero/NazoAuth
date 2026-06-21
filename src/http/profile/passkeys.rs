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
            tracing::warn!(%error, user_id = %user.id, "stored passkey credential is malformed");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "passkey state unavailable.",
            );
        }
    };
    let webauthn = passkey_webauthn(&state.settings);
    let (challenge, registration_state) = webauthn.start_registration(
        &passkey_user_handle(&user),
        &user.email,
        user.display_name.as_deref().unwrap_or(&user.email),
        &existing_ids,
    );
    let ceremony_id = random_urlsafe_token();
    let stored = StoredPasskeyRegistration {
        user_id: user.id,
        tenant_id: user.tenant_id,
        label,
        state: registration_state,
    };
    if let Err(error) =
        store_passkey_ceremony(&state, registration_key(&ceremony_id), &stored).await
    {
        tracing::warn!(%error, user_id = %user.id, "failed to store passkey registration ceremony");
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
    if stored.user_id != user.id || stored.tenant_id != user.tenant_id {
        audit_event(
            "passkey_registration_rejected",
            audit_fields(&[
                ("user_id", json!(user.id)),
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
                    ("user_id", json!(user.id)),
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
    let mut conn = match get_conn(&state.diesel_db).await {
        Ok(conn) => conn,
        Err(error) => {
            tracing::warn!(%error, "failed to get database connection for passkey insert");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "passkey registration failed.",
            );
        }
    };
    let inserted = diesel::insert_into(user_passkey_credentials::table)
        .values((
            user_passkey_credentials::tenant_id.eq(user.tenant_id),
            user_passkey_credentials::user_id.eq(user.id),
            user_passkey_credentials::credential_id.eq(credential_id),
            user_passkey_credentials::credential.eq(credential_json),
            user_passkey_credentials::label.eq(stored.label),
            user_passkey_credentials::sign_count.eq(i64::from(credential.counter)),
        ))
        .returning(PasskeyCredentialRow::as_returning())
        .get_result::<PasskeyCredentialRow>(&mut conn)
        .await;
    match inserted {
        Ok(row) => {
            audit_event(
                "passkey_registered",
                audit_fields(&[
                    ("user_id", json!(user.id)),
                    ("credential_id", json!(row.id)),
                ]),
            );
            passkey_created_response(&row)
        }
        Err(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        )) => passkey_already_registered_response(),
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

fn passkey_list_response(rows: &[PasskeyCredentialRow]) -> HttpResponse {
    json_response(json!({
        "passkeys": rows.iter().map(passkey_public_json).collect::<Vec<_>>()
    }))
}

fn passkey_created_response(row: &PasskeyCredentialRow) -> HttpResponse {
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
    let mut conn = match get_conn(&state.diesel_db).await {
        Ok(conn) => conn,
        Err(error) => {
            tracing::warn!(%error, "failed to get database connection for passkey delete");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "passkey delete failed.",
            );
        }
    };
    match diesel::delete(
        user_passkey_credentials::table
            .find(path.into_inner())
            .filter(user_passkey_credentials::tenant_id.eq(user.tenant_id))
            .filter(user_passkey_credentials::user_id.eq(user.id)),
    )
    .execute(&mut conn)
    .await
    {
        Ok(deleted) => passkey_delete_response(deleted),
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
    user: &UserRow,
) -> Result<Vec<PasskeyCredentialRow>, HttpResponse> {
    let mut conn = get_conn(&state.diesel_db).await.map_err(|error| {
        tracing::warn!(%error, "failed to get database connection for passkey lookup");
        oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "passkey state unavailable.",
        )
    })?;
    user_passkey_credentials::table
        .filter(user_passkey_credentials::tenant_id.eq(user.tenant_id))
        .filter(user_passkey_credentials::user_id.eq(user.id))
        .select(PasskeyCredentialRow::as_select())
        .order(user_passkey_credentials::created_at.asc())
        .load::<PasskeyCredentialRow>(&mut conn)
        .await
        .map_err(|error| {
            tracing::warn!(%error, user_id = %user.id, "failed to load passkey credentials");
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
