//! WebAuthn/passkey login endpoints.

use passkey_auth::AuthenticationResponse;

use crate::http::load_user_passkeys;
use crate::http::prelude::*;

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
    state: Data<AppState>,
    req: HttpRequest,
    Json(payload): Json<PasskeyLoginBeginRequest>,
) -> HttpResponse {
    if let Err(response) = enforce_rate_limit(&state, &req, RateLimitPolicy::Auth).await {
        return response;
    }
    let email = payload.email.trim().to_lowercase();
    let user = match find_user_by_email(&state.diesel_db, &email).await {
        Ok(Some(user)) if user.is_active => user,
        Ok(_) => {
            audit_event(
                "passkey_login_failure",
                audit_fields(&[
                    ("email_hash", json!(blake3_hex(&email))),
                    ("reason", json!("user_not_found")),
                ]),
            );
            return passkey_login_failed_response();
        }
        Err(error) => {
            tracing::warn!(%error, "failed to query user for passkey login");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "user lookup failed.",
            );
        }
    };
    let rows = match load_user_passkeys(&state, &user).await {
        Ok(rows) if !rows.is_empty() => rows,
        Ok(_) => {
            return passkey_login_failed_response();
        }
        Err(response) => return response,
    };
    let credentials = match rows
        .iter()
        .map(passkey_credential_from_row)
        .collect::<anyhow::Result<Vec<_>>>()
    {
        Ok(credentials) => credentials,
        Err(error) => {
            tracing::warn!(%error, user_id = %user.id, "stored passkey credential is malformed");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "passkey state unavailable.",
            );
        }
    };
    let (challenge, authentication_state) = passkey_webauthn(&state.settings)
        .start_authentication_with_creds_for_user(&passkey_user_handle(&user), &credentials);
    let ceremony_id = random_urlsafe_token();
    let stored = StoredPasskeyAuthentication {
        user_id: user.id,
        tenant_id: user.tenant_id,
        state: authentication_state,
    };
    if let Err(error) =
        store_passkey_ceremony(&state, authentication_key(&ceremony_id), &stored).await
    {
        tracing::warn!(%error, user_id = %user.id, "failed to store passkey authentication ceremony");
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

pub(crate) async fn passkey_login_finish(
    state: Data<AppState>,
    req: HttpRequest,
    Json(payload): Json<PasskeyLoginFinishRequest>,
) -> HttpResponse {
    if let Err(response) = enforce_rate_limit(&state, &req, RateLimitPolicy::Auth).await {
        return response;
    }
    let ceremony_id = match normalize_ceremony_id(&payload.ceremony_id) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let stored = match take_passkey_ceremony::<StoredPasskeyAuthentication>(
        &state,
        authentication_key(&ceremony_id),
    )
    .await
    {
        Ok(Some(stored)) => stored,
        Ok(None) => {
            return passkey_ceremony_expired_response();
        }
        Err(response) => return response,
    };
    let user = match find_user_by_id(&state.diesel_db, stored.user_id).await {
        Ok(Some(user)) if user.is_active && user.tenant_id == stored.tenant_id => user,
        Ok(_) => {
            return passkey_login_failed_response();
        }
        Err(error) => {
            tracing::warn!(%error, "failed to query passkey login user");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "user lookup failed.",
            );
        }
    };
    let credential_id = match credential_id_from_response(&payload.response.id) {
        Ok(id) => id.to_b64url(),
        Err(response) => return response,
    };
    let row = match load_passkey_by_credential_id(&state, &user, &credential_id).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return passkey_login_failed_response();
        }
        Err(response) => return response,
    };
    let credential = match passkey_credential_from_row(&row) {
        Ok(credential) => credential,
        Err(error) => {
            tracing::warn!(%error, credential_id = %row.id, "stored passkey credential is malformed");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "passkey state unavailable.",
            );
        }
    };
    let outcome = match passkey_webauthn(&state.settings).finish_authentication(
        &stored.state,
        &payload.response,
        &credential,
    ) {
        Ok(outcome) => outcome,
        Err(error) => {
            audit_event(
                "passkey_login_failure",
                audit_fields(&[
                    ("user_id", json!(user.id)),
                    ("reason", json!(error.to_string())),
                ]),
            );
            return passkey_login_failed_response();
        }
    };
    if let Err(response) = update_passkey_counter(&state, &user, &row, outcome.new_counter).await {
        return response;
    }
    create_passkey_session(&state, &req, &user).await
}

fn passkey_login_failed_response() -> HttpResponse {
    oauth_error(
        StatusCode::UNAUTHORIZED,
        "access_denied",
        "passkey login failed.",
    )
}

fn passkey_ceremony_expired_response() -> HttpResponse {
    oauth_error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "passkey ceremony expired.",
    )
}

async fn load_passkey_by_credential_id(
    state: &AppState,
    user: &UserRow,
    credential_id: &str,
) -> Result<Option<PasskeyCredentialRow>, HttpResponse> {
    let mut conn = get_conn(&state.diesel_db).await.map_err(|error| {
        tracing::warn!(%error, "failed to get database connection for passkey credential lookup");
        oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "passkey state unavailable.",
        )
    })?;
    user_passkey_credentials::table
        .filter(user_passkey_credentials::tenant_id.eq(user.tenant_id))
        .filter(user_passkey_credentials::user_id.eq(user.id))
        .filter(user_passkey_credentials::credential_id.eq(credential_id))
        .select(PasskeyCredentialRow::as_select())
        .first::<PasskeyCredentialRow>(&mut conn)
        .await
        .optional()
        .map_err(|error| {
            tracing::warn!(%error, "failed to load passkey credential");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "passkey state unavailable.",
            )
        })
}

async fn update_passkey_counter(
    state: &AppState,
    user: &UserRow,
    row: &PasskeyCredentialRow,
    new_counter: u32,
) -> Result<(), HttpResponse> {
    let mut credential = passkey_credential_from_row(row).map_err(|error| {
        tracing::warn!(%error, credential_id = %row.id, "stored passkey credential is malformed");
        oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "passkey state unavailable.",
        )
    })?;
    credential.counter = new_counter;
    let credential_json = serde_json::to_value(&credential).map_err(|error| {
        tracing::warn!(%error, "failed to serialize updated passkey credential");
        oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "passkey state unavailable.",
        )
    })?;
    let mut conn = get_conn(&state.diesel_db).await.map_err(|error| {
        tracing::warn!(%error, "failed to get database connection for passkey counter update");
        oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "passkey state unavailable.",
        )
    })?;
    diesel::update(
        user_passkey_credentials::table
            .find(row.id)
            .filter(user_passkey_credentials::tenant_id.eq(user.tenant_id))
            .filter(user_passkey_credentials::user_id.eq(user.id)),
    )
    .set((
        user_passkey_credentials::credential.eq(credential_json),
        user_passkey_credentials::sign_count.eq(i64::from(new_counter)),
        user_passkey_credentials::last_used_at.eq(Utc::now()),
        user_passkey_credentials::updated_at.eq(diesel_now),
    ))
    .execute(&mut conn)
    .await
    .map_err(|error| {
        tracing::warn!(%error, "failed to update passkey counter");
        oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "passkey state unavailable.",
        )
    })?;
    Ok(())
}

async fn create_passkey_session(
    state: &AppState,
    req: &HttpRequest,
    user: &UserRow,
) -> HttpResponse {
    let session_id = random_urlsafe_token();
    let csrf_token = random_urlsafe_token();
    let key = format!("oauth:session:{session_id}");
    let remembered_mfa = if user.mfa_enabled {
        match remembered_mfa_device_valid(state, req, user).await {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(%error, "failed to check remembered MFA device for passkey login");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "MFA state lookup failed.",
                );
            }
        }
    } else {
        false
    };
    let mut amr = vec!["passkey".to_owned()];
    if remembered_mfa {
        amr.push("remembered_mfa".to_owned());
        amr.push("mfa".to_owned());
    }
    let session = SessionPayload {
        user_id: user.id,
        auth_time: Utc::now().timestamp(),
        amr,
        pending_mfa: user.mfa_enabled && !remembered_mfa,
        oidc_sid: Some(random_urlsafe_token()),
    };
    let session_body = match serde_json::to_string(&session) {
        Ok(body) => body,
        Err(error) => {
            tracing::warn!(%error, "failed to serialize passkey session");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "session write failed.",
            );
        }
    };
    if valkey_set_ex(
        &state.valkey,
        key,
        session_body,
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
        "passkey_login_success",
        audit_fields(&[
            ("user_id", json!(user.id)),
            (
                "source_ip_hash",
                json!(blake3_hex(&client_ip(req, &state.settings))),
            ),
        ]),
    );
    passkey_session_response(
        &state.settings,
        &session_id,
        &csrf_token,
        state.settings.session_ttl_seconds,
        session.pending_mfa,
    )
}

fn passkey_session_response(
    settings: &Settings,
    session_id: &str,
    csrf_token: &str,
    expires_in: u64,
    mfa_required: bool,
) -> HttpResponse {
    with_cookie_headers(
        json_response(json!({
            "expires_in": expires_in,
            "csrf_token": csrf_token,
            "mfa_required": mfa_required
        })),
        &[
            make_cookie(
                &settings.session_cookie_name,
                session_id,
                true,
                expires_in,
                settings.cookie_secure,
            ),
            make_cookie(
                &settings.csrf_cookie_name,
                csrf_token,
                false,
                expires_in,
                settings.cookie_secure,
            ),
        ],
    )
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/auth/tests/passkey.rs"]
mod tests;
