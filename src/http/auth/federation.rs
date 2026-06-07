//! External OIDC and trusted SAML-gateway federation.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;

use crate::http::prelude::*;
use crate::settings::{OidcFederationSettings, SamlGatewaySettings};

type HmacSha256 = Hmac<Sha256>;

const FEDERATION_STATE_TTL_SECONDS: u64 = 300;

#[derive(Serialize, Deserialize)]
struct OidcFederationState {
    nonce: String,
    pkce_verifier: String,
    created_at: i64,
}

#[derive(Deserialize)]
pub(crate) struct OidcCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct OidcTokenResponse {
    id_token: String,
}

#[derive(Deserialize)]
struct OidcIdTokenClaims {
    iss: String,
    sub: String,
    aud: Value,
    exp: i64,
    iat: Option<i64>,
    nonce: Option<String>,
    email: Option<String>,
    email_verified: Option<bool>,
    name: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct SamlGatewayAssertion {
    issuer: String,
    audience: String,
    subject: String,
    email: String,
    name: Option<String>,
    iat: i64,
    exp: i64,
    signature: String,
}

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
    if query.error.is_some() {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "access_denied",
            "OIDC federation failed.",
        );
    }
    let Some(provider) = state.settings.federation.oidc.clone() else {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "OIDC federation is not configured.",
        );
    };
    let state_token = match query.state.as_deref().and_then(normalize_federation_token) {
        Some(value) => value,
        None => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "invalid federation state.",
            );
        }
    };
    let code = match query
        .code
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(value) if value.len() <= 4096 => value.to_owned(),
        _ => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "authorization code required.",
            );
        }
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
    if claims.email_verified == Some(false) {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "access_denied",
            "OIDC email is not verified.",
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

fn oidc_authorization_url(
    provider: &OidcFederationSettings,
    state: &str,
    nonce: &str,
    verifier: &str,
) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer
        .append_pair("response_type", "code")
        .append_pair("client_id", &provider.client_id)
        .append_pair("redirect_uri", &provider.redirect_uri)
        .append_pair("scope", &provider.scopes)
        .append_pair("state", state)
        .append_pair("nonce", nonce)
        .append_pair("code_challenge_method", "S256")
        .append_pair("code_challenge", &pkce_s256(verifier));
    format!(
        "{}?{}",
        provider.authorization_endpoint,
        serializer.finish()
    )
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

fn oidc_state_key(state: &str) -> String {
    format!("oauth:federation:oidc:state:{}", blake3_hex(state))
}

async fn exchange_oidc_code(
    provider: &OidcFederationSettings,
    code: &str,
    verifier: &str,
) -> anyhow::Result<OidcTokenResponse> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", code)
        .append_pair("redirect_uri", &provider.redirect_uri)
        .append_pair("code_verifier", verifier)
        .finish();
    let response = client
        .post(&provider.token_endpoint)
        .basic_auth(&provider.client_id, Some(&provider.client_secret))
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(body)
        .send()
        .await?
        .error_for_status()?;
    Ok(response.json::<OidcTokenResponse>().await?)
}

async fn fetch_oidc_jwks(provider: &OidcFederationSettings) -> anyhow::Result<Value> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let value = client
        .get(&provider.jwks_url)
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?;
    if value.get("keys").and_then(Value::as_array).is_none() {
        anyhow::bail!("OIDC JWKS does not contain keys array");
    }
    Ok(value)
}

fn verify_oidc_id_token(
    provider: &OidcFederationSettings,
    jwks: &Value,
    token: &str,
    expected_nonce: &str,
) -> anyhow::Result<OidcIdTokenClaims> {
    let header = jsonwebtoken::decode_header(token)?;
    let kid = header
        .kid
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("missing kid"))?;
    let keys = jwks
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("missing keys"))?;
    let key = keys
        .iter()
        .find(|key| key.get("kid").and_then(Value::as_str) == Some(kid))
        .ok_or_else(|| anyhow::anyhow!("kid not found"))?;
    let decoding_key = jwt_decoding_key_from_jwk(key, header.alg)
        .ok_or_else(|| anyhow::anyhow!("unsupported OIDC JWK"))?;
    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.set_issuer(&[provider.issuer.as_str()]);
    validation.set_audience(&[provider.client_id.as_str()]);
    let token = jsonwebtoken::decode::<OidcIdTokenClaims>(token, &decoding_key, &validation)?;
    let claims = token.claims;
    if claims.nonce.as_deref() != Some(expected_nonce)
        || !audience_contains(&claims.aud, &provider.client_id)
        || claims.exp <= Utc::now().timestamp()
        || claims
            .iat
            .is_some_and(|iat| iat > Utc::now().timestamp().saturating_add(60))
    {
        anyhow::bail!("OIDC ID Token claims failed policy");
    }
    Ok(claims)
}

fn audience_contains(aud: &Value, client_id: &str) -> bool {
    match aud {
        Value::String(value) => value == client_id,
        Value::Array(values) => values.iter().any(|value| value.as_str() == Some(client_id)),
        _ => false,
    }
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

fn valid_saml_gateway_assertion(
    settings: &SamlGatewaySettings,
    assertion: &SamlGatewayAssertion,
    normalized_email: &str,
) -> bool {
    let now = Utc::now().timestamp();
    if assertion.issuer != settings.issuer
        || assertion.audience != settings.audience
        || assertion.subject.trim().is_empty()
        || assertion.iat > now.saturating_add(60)
        || assertion.exp <= now
        || assertion.exp.saturating_sub(assertion.iat) > 300
    {
        return false;
    }
    let expected = saml_gateway_signature(
        &settings.secret,
        &assertion.issuer,
        &assertion.audience,
        &assertion.subject,
        normalized_email,
        assertion.iat,
        assertion.exp,
    );
    constant_time_eq(expected.as_bytes(), assertion.signature.as_bytes())
}

fn saml_gateway_signature(
    secret: &str,
    issuer: &str,
    audience: &str,
    subject: &str,
    email: &str,
    iat: i64,
    exp: i64,
) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key");
    mac.update(format!("{issuer}\n{audience}\n{subject}\n{email}\n{iat}\n{exp}").as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
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
mod tests {
    use super::*;

    #[test]
    fn federation_token_accepts_only_urlsafe_values() {
        assert!(
            normalize_federation_token("abcdefghijklmnopqrstuvwxyzABCDEF0123456789-_").is_some()
        );
        assert!(normalize_federation_token("short").is_none());
        assert!(
            normalize_federation_token("abcdefghijklmnopqrstuvwxyzABCDEF0123456789+/").is_none()
        );
    }

    #[test]
    fn saml_gateway_signature_is_bound_to_assertion_fields() {
        let settings = SamlGatewaySettings {
            issuer: "gateway".to_owned(),
            audience: "nazo".to_owned(),
            secret: "01234567890123456789012345678901".to_owned(),
        };
        let now = Utc::now().timestamp();
        let signature = saml_gateway_signature(
            &settings.secret,
            &settings.issuer,
            &settings.audience,
            "subject",
            "user@example.com",
            now,
            now + 60,
        );
        let assertion = SamlGatewayAssertion {
            issuer: settings.issuer.clone(),
            audience: settings.audience.clone(),
            subject: "subject".to_owned(),
            email: "user@example.com".to_owned(),
            name: None,
            iat: now,
            exp: now + 60,
            signature,
        };
        assert!(valid_saml_gateway_assertion(
            &settings,
            &assertion,
            "user@example.com"
        ));
        assert!(!valid_saml_gateway_assertion(
            &settings,
            &assertion,
            "other@example.com"
        ));
    }
}
