//! OpenID Connect CIBA poll-mode grant.

use super::{
    TokenForm, consume_token_client_assertion, consume_token_management_client_assertion,
    issue_token_response, token_management_auth_error, validate_token_request_profile,
    verify_confidential_client,
};
use crate::http::prelude::*;
use actix_web::web::Payload;
use std::collections::HashSet;

pub(crate) const CIBA_GRANT_TYPE: &str = "urn:openid:params:grant-type:ciba";

#[derive(Deserialize, serde::Serialize)]
struct CibaRequestState {
    client_id: String,
    user_id: Uuid,
    scopes: Vec<String>,
    audiences: Vec<String>,
    status: CibaStatus,
    interval_seconds: u64,
    expires_at: i64,
    last_poll_at: Option<i64>,
}

#[derive(Clone, Copy, Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum CibaStatus {
    Pending,
    Approved,
    Denied,
}

#[derive(Default)]
struct BackchannelAuthenticationForm {
    scope: Option<String>,
    login_hint: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    client_assertion_type: Option<String>,
    client_assertion: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct CibaDecisionRequest {
    decision: String,
    csrf_token: Option<String>,
}

pub(crate) async fn backchannel_authentication(
    state: Data<AppState>,
    req: HttpRequest,
    mut payload: Payload,
) -> HttpResponse {
    if !state.settings.enable_ciba {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let form = match parse_backchannel_authentication_form(&req, &mut payload).await {
        Ok(form) => form,
        Err(response) => return response,
    };
    let has_basic = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim_start().starts_with("Basic "));
    let has_assertion = form.client_assertion_type.is_some() || form.client_assertion.is_some();
    if has_basic && (form.client_id.is_some() || form.client_secret.is_some() || has_assertion)
        || has_assertion && form.client_secret.is_some()
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "CIBA request cannot mix client authentication methods.",
        );
    }
    let credentials = extract_client_credentials(
        &req,
        &state.settings,
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
        form.client_assertion_type.as_deref(),
        form.client_assertion.as_deref(),
    );
    let Some(client_id) = credentials.client_id.as_deref() else {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "客户端认证失败.",
        );
    };
    let client = match find_client(&state.diesel_db, client_id).await {
        Ok(Some(client)) if client.is_active => client,
        Ok(_) => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "客户端认证失败.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to query CIBA client");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "CIBA failed.",
            );
        }
    };
    if !client_supports_grant(&client, CIBA_GRANT_TYPE) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "该客户端未启用 CIBA 授权类型.",
        );
    }
    let assertion = match verify_confidential_client(&state, &req, &client, &credentials) {
        Ok(assertion) => assertion,
        Err(error) => return token_management_auth_error(error),
    };
    if let Err(error) =
        consume_token_management_client_assertion(&state, &client, assertion.as_ref()).await
    {
        return token_management_auth_error(error);
    }
    if let Err(response) =
        validate_token_request_profile(&state.settings, &client, credentials.method.as_str())
    {
        return response;
    }
    let scopes = parse_scope(form.scope.as_deref().unwrap_or(""));
    if !scopes.iter().any(|scope| scope == "openid")
        || !is_subset(&scopes, &json_array_to_strings(&client.scopes))
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "CIBA requires an allowed openid scope.",
        );
    }
    let Some(login_hint) = form
        .login_hint
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "CIBA requires login_hint.",
        );
    };
    let user = match find_user_by_email(&state.diesel_db, login_hint).await {
        Ok(Some(user)) if user.is_active => user,
        Ok(_) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "unknown_user_id",
                "CIBA login_hint does not identify an active user.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to query CIBA login_hint user");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "CIBA failed.",
            );
        }
    };
    let auth_req_id = random_urlsafe_token();
    let state_payload = CibaRequestState {
        client_id: client.client_id,
        user_id: user.id,
        scopes,
        audiences: vec![state.settings.default_audience.clone()],
        status: CibaStatus::Pending,
        interval_seconds: state.settings.ciba_poll_interval_seconds,
        expires_at: Utc::now().timestamp() + state.settings.ciba_auth_req_id_ttl_seconds as i64,
        last_poll_at: None,
    };
    let body =
        serde_json::to_string(&state_payload).expect("CIBA state serialization must be infallible");
    if let Err(error) = valkey_set_ex(
        &state.valkey,
        ciba_request_key(&auth_req_id),
        body,
        state.settings.ciba_auth_req_id_ttl_seconds,
    )
    .await
    {
        tracing::warn!(%error, "failed to store CIBA auth_req_id");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "CIBA failed.",
        );
    }
    json_response_no_store(json!({
        "auth_req_id": auth_req_id,
        "expires_in": state.settings.ciba_auth_req_id_ttl_seconds,
        "interval": state.settings.ciba_poll_interval_seconds
    }))
}

async fn parse_backchannel_authentication_form(
    req: &HttpRequest,
    payload: &mut Payload,
) -> Result<BackchannelAuthenticationForm, HttpResponse> {
    if !request_uses_form_urlencoded(req) {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "CIBA request must use application/x-www-form-urlencoded.",
        ));
    }
    let mut body = Bytes::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk.map_err(|_| {
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "CIBA body is invalid.",
            )
        })?;
        if body.len().saturating_add(chunk.len()) > 16 * 1024 {
            return Err(oauth_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "invalid_request",
                "CIBA body is too large.",
            ));
        }
        let mut combined = Vec::with_capacity(body.len() + chunk.len());
        combined.extend_from_slice(&body);
        combined.extend_from_slice(&chunk);
        body = Bytes::from(combined);
    }
    let mut form = BackchannelAuthenticationForm::default();
    let mut seen = HashSet::new();
    for (key, value) in url::form_urlencoded::parse(&body) {
        let value = value.into_owned();
        let key = key.into_owned();
        if !seen.insert(key.clone()) {
            return Err(oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "CIBA parameters must not repeat.",
            ));
        }
        match key.as_str() {
            "scope" => form.scope = non_empty(value),
            "login_hint" => form.login_hint = non_empty(value),
            "client_id" => form.client_id = non_empty(value),
            "client_secret" => form.client_secret = non_empty(value),
            "client_assertion_type" => form.client_assertion_type = non_empty(value),
            "client_assertion" => form.client_assertion = non_empty(value),
            _ => {}
        }
    }
    Ok(form)
}

fn non_empty(value: String) -> Option<String> {
    (!value.trim().is_empty()).then(|| value.trim().to_owned())
}

pub(crate) async fn ciba_decision(
    state: Data<AppState>,
    req: HttpRequest,
    path: actix_web::web::Path<String>,
    Json(payload): Json<CibaDecisionRequest>,
) -> HttpResponse {
    if !state.settings.enable_ciba {
        return empty_response(StatusCode::NOT_FOUND);
    }
    if !has_valid_csrf_token(&state, &req, payload.csrf_token.as_deref()) {
        return csrf_error();
    }
    let user = match current_user_or_login_required(&state, &req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let auth_req_id = path.into_inner();
    let mut state_payload = match load_ciba_request_state(&state, &auth_req_id).await {
        Ok(Some(value)) => value,
        Ok(None) => {
            return oauth_error(
                StatusCode::NOT_FOUND,
                "invalid_request",
                "CIBA request expired.",
            );
        }
        Err(response) => return response,
    };
    if state_payload.user_id != user.id {
        return oauth_error(
            StatusCode::FORBIDDEN,
            "access_denied",
            "CIBA request user mismatch.",
        );
    }
    state_payload.status = match payload.decision.as_str() {
        "approve" => CibaStatus::Approved,
        "deny" => CibaStatus::Denied,
        _ => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "CIBA decision is invalid.",
            );
        }
    };
    if let Err(response) = store_ciba_request_state(&state, &auth_req_id, &state_payload).await {
        return response;
    }
    json_response_no_store(json!({"success": true}))
}

pub(crate) async fn token_ciba(
    state: &AppState,
    req: &HttpRequest,
    client: &ClientRow,
    form: &TokenForm,
    client_assertion: Option<&ValidatedClientAssertion>,
) -> HttpResponse {
    if !state.settings.enable_ciba {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "CIBA is not enabled.",
            false,
        );
    }
    let Some(auth_req_id) = form.auth_req_id.as_deref() else {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "CIBA token request requires auth_req_id.",
            false,
        );
    };
    if let Err(response) = consume_token_client_assertion(state, client, client_assertion).await {
        return response;
    }
    let mut ciba = match load_ciba_request_state(state, auth_req_id).await {
        Ok(Some(value)) => value,
        Ok(None) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "expired_token",
                "CIBA auth_req_id is expired.",
                false,
            );
        }
        Err(response) => return response,
    };
    if ciba.client_id != client.client_id {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "CIBA auth_req_id was not issued to this client.",
            false,
        );
    }
    let now = Utc::now().timestamp();
    if ciba.expires_at <= now {
        let _ = valkey_del(&state.valkey, ciba_request_key(auth_req_id)).await;
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "expired_token",
            "CIBA auth_req_id is expired.",
            false,
        );
    }
    if ciba.status == CibaStatus::Pending {
        if ciba
            .last_poll_at
            .is_some_and(|last| now.saturating_sub(last) < ciba.interval_seconds as i64)
        {
            ciba.interval_seconds = ciba.interval_seconds.saturating_add(5);
            ciba.last_poll_at = Some(now);
            let _ = store_ciba_request_state(state, auth_req_id, &ciba).await;
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "slow_down",
                "CIBA polling too fast.",
                false,
            );
        }
        ciba.last_poll_at = Some(now);
        let _ = store_ciba_request_state(state, auth_req_id, &ciba).await;
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "authorization_pending",
            "CIBA authorization is pending.",
            false,
        );
    }
    if ciba.status == CibaStatus::Denied {
        let _ = valkey_del(&state.valkey, ciba_request_key(auth_req_id)).await;
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "access_denied",
            "CIBA authorization was denied.",
            false,
        );
    }
    let user = match find_user_by_id(&state.diesel_db, ciba.user_id).await {
        Ok(Some(user)) if user.is_active => user,
        Ok(_) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "CIBA user is unavailable.",
                false,
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to load CIBA user");
            return oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "CIBA failed.",
                false,
            );
        }
    };
    let subject = match ciba_subject_for_client(&state.settings, ciba.user_id, client) {
        Ok(subject) => subject,
        Err(error) => {
            tracing::warn!(%error, "failed to compute CIBA subject");
            return oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "CIBA failed.",
                false,
            );
        }
    };
    let (dpop_jkt, mtls_x5t_s256) = match ciba_issue_binding(state, req, client).await {
        Ok(binding) => binding,
        Err(response) => return response,
    };
    let _ = valkey_del(&state.valkey, ciba_request_key(auth_req_id)).await;
    issue_token_response(
        state,
        client,
        TokenIssue {
            user_id: Some(user.id),
            subject,
            scopes: ciba.scopes,
            authorization_details: json!([]),
            audiences: ciba.audiences,
            nonce: None,
            auth_time: Some(Utc::now().timestamp()),
            amr: vec!["ciba".to_owned()],
            oidc_sid: None,
            acr: None,
            userinfo_claims: Vec::new(),
            userinfo_claim_requests: Vec::new(),
            id_token_claims: Vec::new(),
            id_token_claim_requests: Vec::new(),
            include_refresh: false,
            refresh_token_policy: RefreshTokenPolicy::PreserveExisting,
            dpop_jkt: dpop_jkt.clone(),
            refresh_token_dpop_jkt: None,
            mtls_x5t_s256: mtls_x5t_s256.clone(),
            refresh_token_mtls_x5t_s256: None,
            authorization_code_hash: None,
            actor: None,
            issued_token_type: None,
            native_sso: None,
        },
    )
    .await
}

async fn ciba_issue_binding(
    state: &AppState,
    req: &HttpRequest,
    client: &ClientRow,
) -> Result<(Option<String>, Option<String>), HttpResponse> {
    if client.require_dpop_bound_tokens {
        let dpop_jkt = validate_dpop_proof(state, req, None, None)
            .await
            .map_err(|error| dpop_error_response(error, DpopErrorContext::TokenEndpoint))?;
        if dpop_jkt.is_none() {
            return Err(dpop_error_response(
                DpopError::MissingProof,
                DpopErrorContext::TokenEndpoint,
            ));
        }
        return Ok((dpop_jkt, None));
    }
    if client.require_mtls_bound_tokens {
        let Some(x5t_s256) = request_mtls_thumbprint(req, &state.settings) else {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "CIBA requires mTLS sender constraint.",
                false,
            ));
        };
        return Ok((None, Some(x5t_s256)));
    }
    Ok((None, None))
}

fn ciba_subject_for_client(
    settings: &Settings,
    user_id: Uuid,
    client: &ClientRow,
) -> anyhow::Result<String> {
    let redirect_uri = json_array_to_strings(&client.redirect_uris)
        .into_iter()
        .next()
        .unwrap_or_default();
    compute_subject_for_client(
        settings,
        user_id,
        &client.subject_type,
        client.sector_identifier_host.as_deref(),
        &redirect_uri,
    )
}

async fn load_ciba_request_state(
    state: &AppState,
    auth_req_id: &str,
) -> Result<Option<CibaRequestState>, HttpResponse> {
    let raw = valkey_get(&state.valkey, ciba_request_key(auth_req_id))
        .await
        .map_err(|error| {
            tracing::warn!(%error, "failed to load CIBA state");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "CIBA state unavailable.",
            )
        })?;
    raw.map(|raw| serde_json::from_str(&raw))
        .transpose()
        .map_err(|error| {
            tracing::warn!(%error, "CIBA state is malformed");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "CIBA state invalid.",
            )
        })
}

async fn store_ciba_request_state(
    state: &AppState,
    auth_req_id: &str,
    payload: &CibaRequestState,
) -> Result<(), HttpResponse> {
    let ttl = payload
        .expires_at
        .saturating_sub(Utc::now().timestamp())
        .max(1) as u64;
    let body = serde_json::to_string(payload).expect("CIBA state serialization must be infallible");
    valkey_set_ex(&state.valkey, ciba_request_key(auth_req_id), body, ttl)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "failed to store CIBA state");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "CIBA state unavailable.",
            )
        })
}

fn ciba_request_key(auth_req_id: &str) -> String {
    format!("oauth:ciba:{}", blake3_hex(auth_req_id))
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/token/tests/ciba.rs"]
mod tests;
