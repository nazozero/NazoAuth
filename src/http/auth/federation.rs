//! External OIDC and trusted SAML-gateway federation.

use crate::http::prelude::*;

mod oidc;
mod saml;
use oidc::*;
use saml::*;

pub(crate) async fn federation_oidc_start(state: Data<AppState>, req: HttpRequest) -> HttpResponse {
    if let Err(response) = enforce_rate_limit(&state, &req, RateLimitPolicy::Auth).await {
        return response;
    }
    let Some(provider) = state.settings.federation.oidc.as_ref() else {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "OIDC federation is not configured.",
        );
    };
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

pub(crate) async fn federation_oidc_callback(
    state: Data<AppState>,
    req: HttpRequest,
    Query(query): Query<OidcCallbackQuery>,
) -> HttpResponse {
    if let Err(response) = enforce_rate_limit(&state, &req, RateLimitPolicy::Auth).await {
        return response;
    }
    federation_oidc_callback_after_rate_limit(state, req, query).await
}

async fn federation_oidc_callback_after_rate_limit(
    state: Data<AppState>,
    req: HttpRequest,
    query: OidcCallbackQuery,
) -> HttpResponse {
    let Some(provider) = state.settings.federation.oidc.clone() else {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "OIDC federation is not configured.",
        );
    };
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
) -> Result<UserRow, HttpResponse> {
    let tenant = default_tenant_context();
    let mut conn = get_conn(&state.diesel_db).await.map_err(|error| {
        tracing::warn!(%error, "failed to get database connection for federation login");
        oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "federation login failed.",
        )
    })?;
    if let Some(link) = external_identity_links::table
        .filter(external_identity_links::tenant_id.eq(tenant.tenant_id))
        .filter(external_identity_links::provider_type.eq(provider_type))
        .filter(external_identity_links::provider_id.eq(provider_id))
        .filter(external_identity_links::subject.eq(subject))
        .select(ExternalIdentityLinkRow::as_select())
        .first::<ExternalIdentityLinkRow>(&mut conn)
        .await
        .optional()
        .map_err(|error| {
            tracing::warn!(%error, "failed to query external identity link");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "federation login failed.",
            )
        })?
    {
        let user = users::table
            .find(link.user_id)
            .filter(users::tenant_id.eq(tenant.tenant_id))
            .filter(users::is_active.eq(true))
            .select(UserRow::as_select())
            .first::<UserRow>(&mut conn)
            .await
            .map_err(|error| {
                tracing::warn!(%error, link_id = %link.id, "linked federation user is unavailable");
                oauth_error(
                    StatusCode::UNAUTHORIZED,
                    "access_denied",
                    "federation login failed.",
                )
            })?;
        let _ = diesel::update(external_identity_links::table.find(link.id))
            .set((
                external_identity_links::email.eq(email),
                external_identity_links::claims.eq(claims),
                external_identity_links::last_login_at.eq(Utc::now()),
                external_identity_links::updated_at.eq(diesel_now),
            ))
            .execute(&mut conn)
            .await;
        return Ok(user);
    }
    let user = match find_user_by_email(&state.diesel_db, email).await {
        Ok(Some(user)) if user.is_active && user.tenant_id == tenant.tenant_id => user,
        Ok(Some(_)) => {
            return Err(oauth_error(
                StatusCode::UNAUTHORIZED,
                "access_denied",
                "federation login failed.",
            ));
        }
        Ok(None) => create_federated_user(&mut conn, &tenant, email, display_name).await?,
        Err(error) => {
            tracing::warn!(%error, "failed to query federation user by email");
            return Err(oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "federation login failed.",
            ));
        }
    };
    diesel::insert_into(external_identity_links::table)
        .values((
            external_identity_links::tenant_id.eq(user.tenant_id),
            external_identity_links::user_id.eq(user.id),
            external_identity_links::provider_type.eq(provider_type),
            external_identity_links::provider_id.eq(provider_id),
            external_identity_links::subject.eq(subject),
            external_identity_links::email.eq(email),
            external_identity_links::claims.eq(claims),
            external_identity_links::last_login_at.eq(Utc::now()),
        ))
        .execute(&mut conn)
        .await
        .map_err(|error| {
            tracing::warn!(%error, user_id = %user.id, "failed to insert external identity link");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "federation login failed.",
            )
        })?;
    Ok(user)
}

async fn create_federated_user(
    conn: &mut crate::db::DbConnection,
    tenant: &TenantContext,
    email: &str,
    display_name: Option<&str>,
) -> Result<UserRow, HttpResponse> {
    let password_hash = hash_password(&random_urlsafe_token()).map_err(|error| {
        tracing::warn!(%error, "failed to hash federated user bootstrap password");
        oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "federation login failed.",
        )
    })?;
    diesel::insert_into(users::table)
        .values((
            users::tenant_id.eq(tenant.tenant_id),
            users::realm_id.eq(tenant.realm_id),
            users::organization_id.eq(tenant.organization_id),
            users::username.eq(email),
            users::email.eq(email),
            users::password_hash.eq(password_hash),
            users::email_verified.eq(true),
            users::display_name.eq(display_name),
        ))
        .returning(UserRow::as_returning())
        .get_result::<UserRow>(conn)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "failed to create federated user");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "federation login failed.",
            )
        })
}

fn normalize_federation_token(value: &str) -> Option<String> {
    let value = value.trim();
    (value.len() >= 32
        && value.len() <= 256
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
    .then_some(value.to_owned())
}

async fn create_federated_session(
    state: &AppState,
    req: &HttpRequest,
    user: &UserRow,
    method: &str,
) -> HttpResponse {
    let session_id = random_urlsafe_token();
    let csrf_token = random_urlsafe_token();
    let session = SessionPayload {
        user_id: user.id,
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
            ("user_id", json!(user.id)),
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
