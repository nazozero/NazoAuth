//! 授权请求入口端点。
// 该端点只创建 consent 临时状态，不签发授权码。
use super::{
    apply_request_object, pushed_authorization_request_key, unverified_request_object_client_id,
};
use crate::http::prelude::*;

pub(crate) const AUTHORIZED_REQUEST_PARAMETERS: &[&str] = &[
    "response_type",
    "client_id",
    "redirect_uri",
    "scope",
    "state",
    "code_challenge",
    "code_challenge_method",
    "nonce",
    "claims",
    "acr_values",
    "prompt",
    "max_age",
    "dpop_jkt",
    "response_mode",
    "request_uri",
    "request",
];
const AUTHORIZATION_NONCE_MAX_BYTES: usize = 256;

fn authorization_pkce(q: &HashMap<String, String>) -> Result<(Option<String>, Option<String>), ()> {
    match (
        q.get("code_challenge").map(String::as_str),
        q.get("code_challenge_method").map(String::as_str),
    ) {
        (None, None) => Ok((None, None)),
        (Some(code_challenge), Some("S256")) if is_valid_pkce_value(code_challenge) => {
            Ok((Some(code_challenge.to_owned()), Some("S256".to_owned())))
        }
        _ => Err(()),
    }
}

fn authorization_request_requires_pkce(client: &ClientRow) -> bool {
    client.client_type == "public"
        || client.require_dpop_bound_tokens
        || client.require_mtls_bound_tokens
}

fn authorization_response_mode(q: &HashMap<String, String>) -> Result<Option<String>, ()> {
    match q.get("response_mode").map(String::as_str) {
        None | Some("query") => Ok(None),
        Some("jwt") => Ok(Some("jwt".to_owned())),
        _ => Err(()),
    }
}

fn requested_acr(q: &HashMap<String, String>, claims_acr: Option<String>) -> Option<String> {
    q.get("acr_values")
        .and_then(|value| {
            value
                .split_whitespace()
                .find(|value| !value.is_empty())
                .map(str::to_owned)
        })
        .or(claims_acr)
}

#[derive(Debug, PartialEq)]
struct RequestedClaims {
    userinfo: Vec<OidcClaimRequest>,
    id_token: Vec<OidcClaimRequest>,
    acr: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PromptDirectives {
    login: bool,
    consent: bool,
    select_account: bool,
    none: bool,
}

fn requested_prompt(q: &HashMap<String, String>) -> Result<PromptDirectives, ()> {
    let Some(raw) = q.get("prompt") else {
        return Ok(PromptDirectives::default());
    };
    let mut directives = PromptDirectives::default();
    for value in raw.split_whitespace() {
        match value {
            "login" => directives.login = true,
            "consent" => directives.consent = true,
            "select_account" => directives.select_account = true,
            "none" => directives.none = true,
            "" => {}
            _ => return Err(()),
        }
    }
    if directives.none && (directives.login || directives.consent || directives.select_account) {
        return Err(());
    }
    Ok(directives)
}

fn requested_claims(q: &HashMap<String, String>) -> Result<RequestedClaims, ()> {
    let Some(raw_claims) = q.get("claims") else {
        return Ok(RequestedClaims {
            userinfo: Vec::new(),
            id_token: Vec::new(),
            acr: None,
        });
    };
    let claims: Value = serde_json::from_str(raw_claims).map_err(|_| ())?;
    let userinfo = requested_claim_requests(claims.get("userinfo"))?;
    let id_token = requested_claim_requests(claims.get("id_token"))?;
    let acr = requested_acr_claim(claims.get("id_token"))?;
    Ok(RequestedClaims {
        userinfo,
        id_token,
        acr,
    })
}

fn requested_claim_requests(value: Option<&Value>) -> Result<Vec<OidcClaimRequest>, ()> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let Some(object) = value.as_object() else {
        return Err(());
    };
    let mut requests = Vec::new();
    for (name, request) in object {
        if supported_user_claim(name) {
            requests.push(parse_claim_request(name, request)?);
        } else {
            validate_claim_request(request)?;
        }
    }
    requests.sort_by(|left, right| left.name.cmp(&right.name));
    requests.dedup_by(|left, right| left.name == right.name);
    Ok(requests)
}

fn requested_acr_claim(value: Option<&Value>) -> Result<Option<String>, ()> {
    let Some(value) = value else {
        return Ok(None);
    };
    let Some(object) = value.as_object() else {
        return Err(());
    };
    let Some(acr) = object.get("acr") else {
        return Ok(None);
    };
    validate_claim_request(acr)?;
    let Some(acr) = acr.as_object() else {
        return Ok(None);
    };
    if let Some(value) = acr.get("value") {
        let value = value.as_str().ok_or(())?.trim();
        return Ok((!value.is_empty()).then(|| value.to_owned()));
    }
    if let Some(values) = acr.get("values") {
        let values = values.as_array().ok_or(())?;
        for value in values {
            let value = value.as_str().ok_or(())?.trim();
            if !value.is_empty() {
                return Ok(Some(value.to_owned()));
            }
        }
    }
    Ok(None)
}

fn validate_claim_request(value: &Value) -> Result<(), ()> {
    parse_optional_claim_request(None, value).map(|_| ())
}

fn parse_claim_request(name: &str, value: &Value) -> Result<OidcClaimRequest, ()> {
    parse_optional_claim_request(Some(name), value)?.ok_or(())
}

fn parse_optional_claim_request(
    name: Option<&str>,
    value: &Value,
) -> Result<Option<OidcClaimRequest>, ()> {
    if value.is_null() {
        return Ok(name.map(|name| OidcClaimRequest {
            name: name.to_owned(),
            essential: false,
            value: None,
            values: Vec::new(),
        }));
    }
    let Some(object) = value.as_object() else {
        return Err(());
    };
    let essential = match object.get("essential") {
        Some(essential) => essential.as_bool().ok_or(())?,
        None => false,
    };
    if object.contains_key("value") && object.contains_key("values") {
        return Err(());
    }
    let requested_value = object.get("value").cloned();
    let mut requested_values = Vec::new();
    if let Some(values) = object.get("values") {
        let Some(values) = values.as_array() else {
            return Err(());
        };
        if values.is_empty() {
            return Err(());
        }
        requested_values = values.clone();
    }
    Ok(name.map(|name| OidcClaimRequest {
        name: name.to_owned(),
        essential,
        value: requested_value,
        values: requested_values,
    }))
}

fn claim_request_names(requests: &[OidcClaimRequest]) -> Vec<String> {
    requests
        .iter()
        .map(|request| request.name.clone())
        .collect()
}

fn preserve_verified_dpop_binding(q: &mut HashMap<String, String>, dpop_jkt: Option<&str>) {
    if let Some(dpop_jkt) = dpop_jkt
        && !q.contains_key("dpop_jkt")
    {
        q.insert("dpop_jkt".to_owned(), dpop_jkt.to_owned());
    }
}

/// 校验 OAuth authorize 参数并创建待确认授权请求。
pub(crate) async fn authorize_get(
    state: Data<AppState>,
    req: HttpRequest,
    Query(mut q): Query<HashMap<String, String>>,
) -> HttpResponse {
    authorize_request(state, req, &mut q).await
}

pub(crate) async fn authorize_post(
    state: Data<AppState>,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !content_type.split(';').next().is_some_and(|value| {
        value
            .trim()
            .eq_ignore_ascii_case("application/x-www-form-urlencoded")
    }) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "authorization request must use application/x-www-form-urlencoded.",
        );
    }
    let raw = match std::str::from_utf8(&body) {
        Ok(raw) => raw,
        Err(_) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "authorization request form is invalid.",
            );
        }
    };
    if has_duplicate_oauth_parameter(req.query_string(), AUTHORIZED_REQUEST_PARAMETERS) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "OAuth 参数不能重复.",
        );
    }
    let mut q = HashMap::new();
    let mut seen = std::collections::HashSet::new();
    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        let key = key.into_owned();
        if AUTHORIZED_REQUEST_PARAMETERS.contains(&key.as_str()) && !seen.insert(key.clone()) {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "OAuth 参数不能重复.",
            );
        }
        q.insert(key, value.into_owned());
    }
    authorize_request(state, req, &mut q).await
}

async fn authorize_request(
    state: Data<AppState>,
    req: HttpRequest,
    q: &mut HashMap<String, String>,
) -> HttpResponse {
    if has_duplicate_oauth_parameter(req.query_string(), AUTHORIZED_REQUEST_PARAMETERS) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "OAuth 参数不能重复.",
        );
    }

    let original_authorization_query = q.clone();
    let mut pushed_dpop_jkt = None;
    let mut pushed_mtls_x5t_s256 = None;
    let mut consumed_request_uri_error: Option<&'static str> = None;
    let mut used_pushed_authorization_request = false;
    let mut pending_pushed_request_uri = None;
    if let Some(request_uri) = q.get("request_uri").cloned() {
        let raw = match valkey_get(
            &state.valkey,
            pushed_authorization_request_key(&request_uri),
        )
        .await
        {
            Ok(Some(raw)) => raw,
            Ok(None) => {
                consumed_request_uri_error = Some("invalid_request_uri");
                String::new()
            }
            Err(error) => {
                tracing::warn!(%error, "failed to read PAR request_uri");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "request_uri 读取失败.",
                );
            }
        };
        if consumed_request_uri_error.is_none() {
            let pushed = match serde_json::from_str::<PushedAuthorizationRequest>(&raw) {
                Ok(pushed) => pushed,
                Err(error) => {
                    tracing::warn!(%error, "PAR payload is malformed");
                    return oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "request_uri 状态无效.",
                    );
                }
            };
            if q.get("client_id")
                .is_some_and(|client_id| client_id != &pushed.client_id)
            {
                consumed_request_uri_error = Some("invalid_request_uri");
            } else if !outer_request_uri_parameters_match_pushed(q, &pushed.params) {
                consumed_request_uri_error = Some("invalid_request");
                *q = pushed.params;
            } else {
                pushed_dpop_jkt = pushed.dpop_jkt;
                pushed_mtls_x5t_s256 = pushed.mtls_x5t_s256;
                used_pushed_authorization_request = true;
                pending_pushed_request_uri = Some(request_uri);
                *q = pushed.params;
            }
        }
    } else if state.settings.require_pushed_authorization_requests {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "该服务要求使用 pushed authorization request.",
        );
    }

    if !q.contains_key("client_id")
        && let Some(request_object) = q.get("request")
        && let Some(client_id) = unverified_request_object_client_id(request_object)
    {
        q.insert("client_id".to_owned(), client_id);
    }

    let Some(client_id) = q.get("client_id") else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "缺少 client_id.",
        );
    };

    let client = match find_client(&state.diesel_db, client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "unauthorized_client",
                "客户端不存在或已停用.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to query oauth client");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端查询失败.",
            );
        }
    };
    if !client.is_active {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized_client",
            "客户端不存在或已停用.",
        );
    }
    if !client_supports_grant(&client, "authorization_code") {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "该客户端未启用 authorization_code 授权类型.",
        );
    }
    let request_object_error = apply_request_object(&state, q, &client).await.err();
    let request_dpop_jkt = match q.get("dpop_jkt") {
        Some(value) if is_valid_dpop_jkt(value) => Some(value.clone()),
        Some(_) => {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "dpop_jkt 无效.");
        }
        None => None,
    };
    let dpop_jkt = match (pushed_dpop_jkt, request_dpop_jkt) {
        (Some(pushed), Some(requested)) if pushed != requested => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "dpop_jkt 与 PAR 绑定不匹配.",
            );
        }
        (Some(pushed), _) => Some(pushed),
        (None, requested) => requested,
    };
    preserve_verified_dpop_binding(q, dpop_jkt.as_deref());
    let mtls_x5t_s256 = pushed_mtls_x5t_s256;
    let redirect_uri =
        match registered_redirect_uri(&client, q.get("redirect_uri").map(String::as_str)) {
            Ok(value) => value,
            Err(RedirectUriError::Missing) => {
                return authorization_error_page(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "redirect_uri is required for this authorization request.",
                );
            }
            Err(RedirectUriError::Invalid) => {
                return authorization_error_page(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "redirect_uri is not registered for this client.",
                );
            }
        };

    if let Some(error) = consumed_request_uri_error {
        return authorization_oauth_error_redirect(&state, &redirect_uri, error, q);
    }
    if let Some(error_response) = request_object_error {
        if let Some(error) = oauth_json_error(&error_response) {
            return authorization_oauth_error_redirect(&state, &redirect_uri, &error, q);
        }
        return error_response;
    }
    if (client.require_dpop_bound_tokens || client.require_mtls_bound_tokens)
        && !used_pushed_authorization_request
        && !q.contains_key("request")
    {
        return authorization_oauth_error_redirect(&state, &redirect_uri, "invalid_request", q);
    }
    if authorization_nonce_too_long(q) {
        return authorization_oauth_error_redirect(&state, &redirect_uri, "invalid_request", q);
    }

    if q.get("response_type").map(String::as_str) != Some("code") {
        return authorization_oauth_error_redirect(
            &state,
            &redirect_uri,
            "unsupported_response_type",
            q,
        );
    }
    let response_mode = match authorization_response_mode(q) {
        Ok(value) => value,
        Err(()) => {
            return authorization_oauth_error_redirect(&state, &redirect_uri, "invalid_request", q);
        }
    };
    let (code_challenge, code_challenge_method) = match authorization_pkce(q) {
        Ok(value) => value,
        Err(()) => {
            return authorization_oauth_error_redirect(&state, &redirect_uri, "invalid_request", q);
        }
    };
    if authorization_request_requires_pkce(&client) && code_challenge.is_none() {
        return authorization_oauth_error_redirect(&state, &redirect_uri, "invalid_request", q);
    }

    let prompt = match requested_prompt(q) {
        Ok(prompt) => prompt,
        Err(()) => {
            return authorization_oauth_error_redirect(&state, &redirect_uri, "invalid_request", q);
        }
    };
    let max_age = match q.get("max_age") {
        Some(value) => match value.parse::<i64>() {
            Ok(value) if value >= 0 => Some(value),
            _ => {
                return authorization_oauth_error_redirect(
                    &state,
                    &redirect_uri,
                    "invalid_request",
                    q,
                );
            }
        },
        None => None,
    };
    let requested_claims = match requested_claims(q) {
        Ok(value) => value,
        Err(()) => {
            return authorization_oauth_error_redirect(&state, &redirect_uri, "invalid_request", q);
        }
    };

    let session = match current_session(&state, &req).await {
        Ok(session) => session,
        Err(error) => {
            tracing::warn!(%error, "failed to resolve authorization request user");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "会话查询失败.",
            );
        }
    };
    let Some(session) = session else {
        if prompt.none {
            return authorization_response_redirect(
                &state,
                &redirect_uri,
                q.get("client_id").map(String::as_str).unwrap_or(""),
                q.get("response_mode").map(String::as_str),
                None,
                Some("login_required"),
                q.get("state").map(String::as_str),
            );
        }
        return redirect_found(authorization_login_url(
            &state,
            authorization_login_query(
                q,
                &original_authorization_query,
                pending_pushed_request_uri.as_ref(),
            ),
            prompt.login || prompt.select_account,
        ));
    };
    if prompt.login
        || prompt.select_account
        || max_age.is_some_and(|max_age| Utc::now().timestamp() - session.auth_time > max_age)
    {
        if prompt.none {
            return authorization_response_redirect(
                &state,
                &redirect_uri,
                q.get("client_id").map(String::as_str).unwrap_or(""),
                q.get("response_mode").map(String::as_str),
                None,
                Some("login_required"),
                q.get("state").map(String::as_str),
            );
        }
        return redirect_found(authorization_login_url(
            &state,
            authorization_login_query(
                q,
                &original_authorization_query,
                pending_pushed_request_uri.as_ref(),
            ),
            prompt.login || prompt.select_account,
        ));
    }

    let requested_scopes = parse_scope(q.get("scope").map(String::as_str).unwrap_or(""));
    if !is_subset(&requested_scopes, &json_array_to_strings(&client.scopes)) {
        return authorization_oauth_error_redirect(&state, &redirect_uri, "invalid_scope", q);
    }
    let now = Utc::now();
    let request_id = Uuid::now_v7().to_string();
    let payload = ConsentPayload {
        request_id: request_id.clone(),
        user_id: session.user.id,
        client_id: client.client_id,
        client_name: client.client_name,
        redirect_uri: redirect_uri.clone(),
        redirect_uri_was_supplied: q.contains_key("redirect_uri"),
        scopes: requested_scopes,
        state: q.get("state").cloned(),
        response_mode,
        nonce: q.get("nonce").cloned(),
        auth_time: session.auth_time,
        amr: session.amr,
        acr: requested_acr(q, requested_claims.acr),
        userinfo_claims: claim_request_names(&requested_claims.userinfo),
        userinfo_claim_requests: requested_claims.userinfo,
        id_token_claims: claim_request_names(&requested_claims.id_token),
        id_token_claim_requests: requested_claims.id_token,
        code_challenge,
        code_challenge_method,
        dpop_jkt,
        mtls_x5t_s256,
        pushed_request_uri: pending_pushed_request_uri,
        issued_at: now,
        expires_at: now + Duration::seconds(state.settings.auth_code_ttl_seconds as i64),
    };
    if prompt.none {
        match user_grant_covers_requested_scopes(
            &state,
            payload.user_id,
            client.id,
            &payload.scopes,
        )
        .await
        {
            Ok(true) => {
                return issue_authorization_code_without_interaction(&state, &req, payload).await;
            }
            Ok(false) => {
                return authorization_oauth_error_redirect(
                    &state,
                    &redirect_uri,
                    "consent_required",
                    q,
                );
            }
            Err(response) => return response,
        }
    }
    let key = format!("oauth:consent:{request_id}");
    let body = match serde_json::to_string(&payload) {
        Ok(body) => body,
        Err(error) => {
            tracing::warn!(%error, "failed to serialize consent request");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权请求创建失败.",
            );
        }
    };
    if let Err(error) = valkey_set_ex(
        &state.valkey,
        key,
        body,
        state.settings.auth_code_ttl_seconds,
    )
    .await
    {
        tracing::warn!(%error, "failed to persist consent request");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "授权请求创建失败.",
        );
    }

    redirect_found(format!(
        "{}/consent?request_id={request_id}",
        state.settings.frontend_base_url.trim_end_matches('/')
    ))
}

async fn user_grant_covers_requested_scopes(
    state: &AppState,
    user_id: Uuid,
    client_id: Uuid,
    requested_scopes: &[String],
) -> Result<bool, HttpResponse> {
    let mut conn = match get_conn(&state.diesel_db).await {
        Ok(conn) => conn,
        Err(error) => {
            tracing::warn!(%error, "failed to get database connection for authorization grant lookup");
            return Err(oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权记录查询失败.",
            ));
        }
    };
    let stored_scopes = match user_client_grants::table
        .filter(user_client_grants::user_id.eq(user_id))
        .filter(user_client_grants::client_id.eq(client_id))
        .select(user_client_grants::last_scopes)
        .first::<Value>(&mut conn)
        .await
        .optional()
    {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(%error, "failed to query authorization grant");
            return Err(oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权记录查询失败.",
            ));
        }
    };
    Ok(stored_scopes
        .as_ref()
        .is_some_and(|scopes| stored_grant_covers_requested_scopes(scopes, requested_scopes)))
}

fn stored_grant_covers_requested_scopes(
    stored_scopes: &Value,
    requested_scopes: &[String],
) -> bool {
    is_subset(requested_scopes, &json_array_to_strings(stored_scopes))
}

async fn issue_authorization_code_without_interaction(
    state: &AppState,
    req: &HttpRequest,
    payload: ConsentPayload,
) -> HttpResponse {
    if let Some(request_uri) = payload.pushed_request_uri.as_deref() {
        match consume_pushed_authorization_request(state, request_uri).await {
            Ok(()) => {}
            Err(PushedAuthorizationRequestConsumeError::Missing) => {
                return authorization_response_redirect(
                    state,
                    &payload.redirect_uri,
                    &payload.client_id,
                    payload.response_mode.as_deref(),
                    None,
                    Some("invalid_request_uri"),
                    payload.state.as_deref(),
                );
            }
            Err(PushedAuthorizationRequestConsumeError::ReadFailed)
            | Err(PushedAuthorizationRequestConsumeError::Malformed) => {
                return authorization_response_redirect(
                    state,
                    &payload.redirect_uri,
                    &payload.client_id,
                    payload.response_mode.as_deref(),
                    None,
                    Some("server_error"),
                    payload.state.as_deref(),
                );
            }
        }
    }

    let now = Utc::now();
    let code = random_urlsafe_token();
    let code_payload = CodePayload {
        code_id: Uuid::now_v7().to_string(),
        user_id: payload.user_id,
        client_id: payload.client_id.clone(),
        redirect_uri: payload.redirect_uri.clone(),
        redirect_uri_was_supplied: payload.redirect_uri_was_supplied,
        scopes: payload.scopes.clone(),
        nonce: payload.nonce,
        auth_time: payload.auth_time,
        amr: payload.amr,
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
        expires_at: now + Duration::seconds(state.settings.auth_code_ttl_seconds as i64),
    };
    let body = match serde_json::to_string(&AuthorizationCodeState::Pending {
        payload: code_payload,
    }) {
        Ok(body) => body,
        Err(error) => {
            tracing::warn!(%error, "failed to serialize prompt=none authorization code state");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权码创建失败.",
            );
        }
    };
    if let Err(error) = valkey_set_ex(
        &state.valkey,
        authorization_code_key(&code),
        body,
        state.settings.auth_code_ttl_seconds,
    )
    .await
    {
        tracing::warn!(%error, "failed to persist prompt=none authorization code");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "授权码创建失败.",
        );
    }
    audit_event(
        "authorization_prompt_none_approved",
        audit_fields(&[
            ("user_id", json!(payload.user_id)),
            ("client_id", json!(payload.client_id)),
            ("scope", json!(payload.scopes.join(" "))),
            (
                "source_ip_hash",
                json!(blake3_hex(&client_ip(req, &state.settings))),
            ),
        ]),
    );
    authorization_response_redirect(
        state,
        &payload.redirect_uri,
        &payload.client_id,
        payload.response_mode.as_deref(),
        Some(&code),
        None,
        payload.state.as_deref(),
    )
}

fn outer_request_uri_parameters_match_pushed(
    outer: &HashMap<String, String>,
    pushed: &HashMap<String, String>,
) -> bool {
    outer.iter().all(|(key, outer_value)| {
        if key == "request_uri" || key == "client_id" {
            return true;
        }
        pushed.get(key) == Some(outer_value)
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PushedAuthorizationRequestConsumeError {
    Missing,
    ReadFailed,
    Malformed,
}

pub(crate) async fn consume_pushed_authorization_request(
    state: &AppState,
    request_uri: &str,
) -> Result<(), PushedAuthorizationRequestConsumeError> {
    let raw =
        match valkey_getdel(&state.valkey, pushed_authorization_request_key(request_uri)).await {
            Ok(Some(raw)) => raw,
            Ok(None) => {
                return Err(PushedAuthorizationRequestConsumeError::Missing);
            }
            Err(error) => {
                tracing::warn!(%error, "failed to consume PAR request_uri");
                return Err(PushedAuthorizationRequestConsumeError::ReadFailed);
            }
        };
    if let Err(error) = serde_json::from_str::<PushedAuthorizationRequest>(&raw) {
        tracing::warn!(%error, "PAR payload is malformed");
        return Err(PushedAuthorizationRequestConsumeError::Malformed);
    }
    Ok(())
}

pub(crate) fn authorization_oauth_error_redirect(
    state: &AppState,
    redirect_uri: &str,
    error: &str,
    q: &HashMap<String, String>,
) -> HttpResponse {
    authorization_response_redirect(
        state,
        redirect_uri,
        q.get("client_id").map(String::as_str).unwrap_or(""),
        q.get("response_mode").map(String::as_str),
        None,
        Some(error),
        q.get("state").map(String::as_str),
    )
}

pub(crate) fn authorization_response_redirect(
    state: &AppState,
    redirect_uri: &str,
    client_id: &str,
    response_mode: Option<&str>,
    code: Option<&str>,
    error: Option<&str>,
    state_value: Option<&str>,
) -> HttpResponse {
    if response_mode == Some("jwt") && !client_id.trim().is_empty() {
        return authorization_response_jwt_result(
            redirect_uri,
            make_authorization_response_jwt(
                state,
                AuthorizationResponseJwtInput {
                    client_id,
                    code,
                    error,
                    state: state_value,
                    ttl: state.settings.auth_code_ttl_seconds as i64,
                },
            ),
        );
    }
    redirect_found(append_authorization_response_query(
        redirect_uri,
        state.settings.issuer.as_str(),
        code,
        error,
        state_value,
    ))
}

fn authorization_response_jwt_result(
    redirect_uri: &str,
    result: jsonwebtoken::errors::Result<String>,
) -> HttpResponse {
    match result {
        Ok(response) => authorization_response_jwt_redirect(redirect_uri, &response),
        Err(signing_error) => {
            tracing::warn!(%signing_error, "failed to sign JARM authorization response");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "authorization response signing failed.",
            )
        }
    }
}

fn authorization_response_jwt_redirect(redirect_uri: &str, response: &str) -> HttpResponse {
    redirect_found(append_query(redirect_uri, &[("response", response)]))
}

fn append_authorization_response_query(
    redirect_uri: &str,
    issuer: &str,
    code: Option<&str>,
    error: Option<&str>,
    state_value: Option<&str>,
) -> String {
    let Ok(mut url) = url::Url::parse(redirect_uri) else {
        return redirect_uri.to_owned();
    };
    {
        let mut query = url.query_pairs_mut();
        if let Some(code) = code {
            query.append_pair("code", code);
        }
        if let Some(error) = error {
            query.append_pair("error", error);
        }
        if let Some(state_value) = state_value {
            query.append_pair("state", state_value);
        }
        query.append_pair("iss", issuer);
    }
    url.to_string()
}

fn authorization_nonce_too_long(q: &HashMap<String, String>) -> bool {
    q.get("nonce")
        .is_some_and(|value| value.len() > AUTHORIZATION_NONCE_MAX_BYTES)
}

fn oauth_json_error(response: &HttpResponse) -> Option<String> {
    let extensions = response.extensions();
    extensions
        .get::<OAuthJsonErrorFields>()
        .map(|fields| fields.error.clone())
}

fn authorization_login_query<'a>(
    expanded: &'a HashMap<String, String>,
    original: &'a HashMap<String, String>,
    request_uri: Option<&String>,
) -> &'a HashMap<String, String> {
    if request_uri.is_some() {
        original
    } else {
        expanded
    }
}

fn authorization_login_url(
    state: &AppState,
    q: &HashMap<String, String>,
    remove_prompt_login: bool,
) -> String {
    let query = q
        .iter()
        .filter(|(key, value)| {
            !(remove_prompt_login && key.as_str() == "prompt" && value.as_str() == "login")
        })
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let next = if query.is_empty() {
        "/authorize".to_string()
    } else {
        format!("/authorize?{query}")
    };
    format!(
        "{}/auth?next={}",
        state.settings.frontend_base_url.trim_end_matches('/'),
        urlencoding::encode(&next)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(values: &[(&str, &str)]) -> HashMap<String, String> {
        values
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn first_acr_value_is_used_for_id_token_acr() {
        assert_eq!(
            requested_acr(&query(&[("acr_values", "urn:one urn:two")]), None),
            Some("urn:one".to_owned())
        );
        assert_eq!(
            requested_acr(
                &query(&[("acr_values", "urn:one urn:two")]),
                Some("urn:claims".to_owned()),
            ),
            Some("urn:one".to_owned())
        );
        assert_eq!(
            requested_acr(
                &query(&[("acr_values", "   ")]),
                Some("urn:claims".to_owned())
            ),
            Some("urn:claims".to_owned())
        );
    }

    #[test]
    fn claims_parameter_extracts_supported_user_claim_names() {
        let requested = requested_claims(&query(&[(
            "claims",
            r#"{"userinfo":{"name":{"essential":true},"unknown":null},"id_token":{"email":{"essential":true},"acr":{"value":"urn:acr:1"}}}"#,
        )]))
        .unwrap();

        assert_eq!(claim_request_names(&requested.userinfo), vec!["name"]);
        assert!(requested.userinfo[0].essential);
        assert_eq!(claim_request_names(&requested.id_token), vec!["email"]);
        assert!(requested.id_token[0].essential);
        assert_eq!(requested.acr, Some("urn:acr:1".to_owned()));
    }

    #[test]
    fn claims_parameter_accepts_value_values_and_null_requests() {
        let requested = requested_claims(&query(&[(
            "claims",
            r#"{"userinfo":{"name":null,"email":{"value":"alice@example.com"},"phone_number":{"values":["+15555550000","+15555550001"]}},"id_token":{"email_verified":{"essential":false},"acr":{"values":["urn:acr:2"]}}}"#,
        )]))
        .unwrap();

        assert_eq!(
            claim_request_names(&requested.userinfo),
            vec!["email", "name", "phone_number"]
        );
        let email = requested
            .userinfo
            .iter()
            .find(|request| request.name == "email")
            .expect("email claim request");
        assert_eq!(email.value, Some(json!("alice@example.com")));
        let phone = requested
            .userinfo
            .iter()
            .find(|request| request.name == "phone_number")
            .expect("phone claim request");
        assert_eq!(
            phone.values,
            vec![json!("+15555550000"), json!("+15555550001")]
        );
        assert_eq!(
            claim_request_names(&requested.id_token),
            vec!["email_verified"]
        );
        assert!(!requested.id_token[0].essential);
        assert_eq!(requested.acr, Some("urn:acr:2".to_owned()));
    }

    #[test]
    fn malformed_claims_parameter_is_invalid() {
        assert!(requested_claims(&query(&[("claims", "not-json")])).is_err());
        assert!(requested_claims(&query(&[("claims", r#"{"userinfo":[]}"#)])).is_err());
        assert!(requested_claims(&query(&[("claims", r#"{"id_token":{"acr":[]}}"#)])).is_err());
        assert!(
            requested_claims(&query(&[(
                "claims",
                r#"{"userinfo":{"email":{"essential":"yes"}}}"#
            )]))
            .is_err()
        );
        assert!(
            requested_claims(&query(&[(
                "claims",
                r#"{"userinfo":{"email":{"value":"a@example.com","values":["a@example.com"]}}}"#
            )]))
            .is_err()
        );
        assert!(
            requested_claims(&query(&[(
                "claims",
                r#"{"userinfo":{"email":{"values":"a@example.com"}}}"#
            )]))
            .is_err()
        );
        assert!(
            requested_claims(&query(&[(
                "claims",
                r#"{"userinfo":{"email":{"values":[]}}}"#
            )]))
            .is_err()
        );
        assert!(
            requested_claims(&query(&[(
                "claims",
                r#"{"id_token":{"acr":{"values":"one"}}}"#
            )]))
            .is_err()
        );
    }

    #[test]
    fn claims_parameter_uses_first_non_empty_acr_values_entry() {
        let requested = requested_claims(&query(&[(
            "claims",
            r#"{"id_token":{"acr":{"values":["","urn:acr:2","urn:acr:3"]}}}"#,
        )]))
        .unwrap();

        assert_eq!(requested.acr, Some("urn:acr:2".to_owned()));
    }

    #[test]
    fn request_uri_allows_outer_parameters_only_when_equal_to_pushed_values() {
        let pushed = query(&[
            ("client_id", "client-1"),
            ("redirect_uri", "https://client.example/callback"),
            ("response_type", "code"),
            ("scope", "openid profile"),
        ]);

        assert!(outer_request_uri_parameters_match_pushed(
            &query(&[
                ("client_id", "client-1"),
                ("request_uri", "urn:ietf:params:oauth:request_uri:abc"),
                ("redirect_uri", "https://client.example/callback"),
                ("response_type", "code"),
                ("scope", "openid profile"),
            ]),
            &pushed,
        ));
        assert!(!outer_request_uri_parameters_match_pushed(
            &query(&[
                ("client_id", "client-1"),
                ("request_uri", "urn:ietf:params:oauth:request_uri:abc"),
                ("redirect_uri", "https://attacker.example/callback"),
            ]),
            &pushed,
        ));
        assert!(!outer_request_uri_parameters_match_pushed(
            &query(&[
                ("client_id", "client-1"),
                ("request_uri", "urn:ietf:params:oauth:request_uri:abc"),
                ("state", "outer-state"),
            ]),
            &pushed,
        ));
    }

    #[test]
    fn authorization_nonce_length_check_allows_long_state_but_rejects_long_nonce() {
        assert!(!authorization_nonce_too_long(&query(&[(
            "state",
            &"s".repeat(1000),
        )])));
        assert!(authorization_nonce_too_long(&query(&[(
            "nonce",
            &"n".repeat(AUTHORIZATION_NONCE_MAX_BYTES + 1),
        )])));
    }

    #[test]
    fn authorization_response_query_preserves_explicit_empty_state() {
        let location = append_authorization_response_query(
            "https://client.example/callback",
            "https://issuer.example",
            Some("code-1"),
            None,
            Some(""),
        );

        let url = url::Url::parse(&location).unwrap();
        let pairs = url.query_pairs().collect::<Vec<_>>();
        assert_eq!(
            pairs,
            vec![
                ("code".into(), "code-1".into()),
                ("state".into(), "".into()),
                ("iss".into(), "https://issuer.example".into()),
            ]
        );
    }

    #[test]
    fn authorization_response_query_omits_absent_state_and_inapplicable_result() {
        let location = append_authorization_response_query(
            "https://client.example/callback",
            "https://issuer.example",
            None,
            Some("invalid_request"),
            None,
        );

        let url = url::Url::parse(&location).unwrap();
        let pairs = url.query_pairs().collect::<Vec<_>>();
        assert_eq!(
            pairs,
            vec![
                ("error".into(), "invalid_request".into()),
                ("iss".into(), "https://issuer.example".into()),
            ]
        );
    }

    #[test]
    fn authorization_response_jwt_redirect_uses_only_response_parameter() {
        let response = authorization_response_jwt_redirect(
            "https://client.example/callback?existing=1",
            "signed-jarm",
        );

        assert_eq!(response.status(), StatusCode::FOUND);
        let location = response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        let url = url::Url::parse(location).unwrap();
        let pairs = url.query_pairs().collect::<Vec<_>>();
        assert_eq!(
            pairs,
            vec![
                ("existing".into(), "1".into()),
                ("response".into(), "signed-jarm".into()),
            ]
        );
        assert!(
            !pairs
                .iter()
                .any(|(key, _)| matches!(key.as_ref(), "code" | "error" | "state" | "iss"))
        );
    }

    #[test]
    fn authorization_response_jwt_signing_failure_does_not_fallback_to_query() {
        let response = authorization_response_jwt_result(
            "https://client.example/callback",
            Err(jsonwebtoken::errors::new_error(
                jsonwebtoken::errors::ErrorKind::Signing("test signing failure".to_owned()),
            )),
        );

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(response.headers().get(header::LOCATION).is_none());
        assert_eq!(
            response
                .extensions()
                .get::<OAuthJsonErrorFields>()
                .map(|fields| fields.error.as_str()),
            Some("server_error")
        );
    }

    #[test]
    fn preserve_verified_dpop_binding_adds_missing_authorization_parameter() {
        let mut q = query(&[("client_id", "client-1")]);
        let dpop_jkt = "w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ";

        preserve_verified_dpop_binding(&mut q, Some(dpop_jkt));

        assert_eq!(q.get("dpop_jkt").map(String::as_str), Some(dpop_jkt));
    }

    #[test]
    fn preserve_verified_dpop_binding_keeps_explicit_authorization_parameter() {
        let mut q = query(&[
            ("client_id", "client-1"),
            ("dpop_jkt", "w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ"),
        ]);

        preserve_verified_dpop_binding(&mut q, Some("Vx6mH6nGWV2DnuqEbuGX4Xw_Dc0p0AQxnKpEG7o5YS8"));

        assert_eq!(
            q.get("dpop_jkt").map(String::as_str),
            Some("w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ")
        );
    }

    #[test]
    fn prompt_parsing_accepts_oidc_values_and_rejects_invalid_combinations() {
        let directives =
            requested_prompt(&query(&[("prompt", "login consent select_account")])).unwrap();
        assert!(directives.login);
        assert!(directives.consent);
        assert!(directives.select_account);
        assert!(!directives.none);

        assert_eq!(
            requested_prompt(&query(&[("prompt", "none")])).unwrap(),
            PromptDirectives {
                none: true,
                ..PromptDirectives::default()
            }
        );
        assert!(requested_prompt(&query(&[("prompt", "none consent")])).is_err());
        assert!(requested_prompt(&query(&[("prompt", "unsupported")])).is_err());
    }

    #[test]
    fn stored_grant_covers_requested_scopes_when_request_is_subset() {
        assert!(stored_grant_covers_requested_scopes(
            &json!(["openid", "profile", "email"]),
            &parse_scope("openid email"),
        ));
    }

    #[test]
    fn stored_grant_does_not_cover_new_or_malformed_scope_sets() {
        assert!(!stored_grant_covers_requested_scopes(
            &json!(["openid", "profile"]),
            &parse_scope("openid email"),
        ));
        assert!(!stored_grant_covers_requested_scopes(
            &json!({"scope": "openid"}),
            &parse_scope("openid"),
        ));
    }

    #[test]
    fn authorization_request_accepts_optional_pkce_but_rejects_invalid_pkce() {
        assert_eq!(authorization_pkce(&query(&[])).unwrap(), (None, None));
        let valid_challenge = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";

        assert!(
            authorization_pkce(&query(&[
                ("code_challenge", valid_challenge),
                ("code_challenge_method", "plain"),
            ]))
            .is_err()
        );
        assert!(authorization_pkce(&query(&[("code_challenge", valid_challenge)])).is_err());
        assert!(
            authorization_pkce(&query(&[
                ("code_challenge", valid_challenge),
                ("code_challenge_method", "S256"),
            ]))
            .is_ok()
        );
    }
}
