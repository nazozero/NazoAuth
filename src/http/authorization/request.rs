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
    "prompt",
    "max_age",
    "request_uri",
    "request",
];

/// 校验 OAuth authorize 参数并创建待确认授权请求。
pub(crate) async fn authorize(
    state: Data<AppState>,
    req: HttpRequest,
    Query(mut q): Query<HashMap<String, String>>,
) -> HttpResponse {
    if has_duplicate_oauth_parameter(req.query_string(), AUTHORIZED_REQUEST_PARAMETERS) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "OAuth 参数不能重复.",
        );
    }

    if let Some(request_uri) = q.get("request_uri").cloned() {
        if q.keys()
            .any(|key| key != "request_uri" && key != "client_id")
        {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "request_uri 请求不能被外层参数覆盖.",
            );
        }
        let raw = match valkey_getdel(
            &state.valkey,
            pushed_authorization_request_key(&request_uri),
        )
        .await
        {
            Ok(Some(raw)) => raw,
            Ok(None) => {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request_uri",
                    "request_uri 无效或已过期.",
                );
            }
            Err(error) => {
                tracing::warn!(%error, "failed to consume PAR request_uri");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "request_uri 读取失败.",
                );
            }
        };
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
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "request_uri 与 client_id 不匹配.",
            );
        }
        q = pushed.params;
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
    if let Err(response) = apply_request_object(&state, &mut q, &client).await {
        return response;
    }
    let redirect_uri =
        match registered_redirect_uri(&client, q.get("redirect_uri").map(String::as_str)) {
            Ok(value) => value,
            Err(RedirectUriError::Missing) => {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "缺少 redirect_uri.",
                );
            }
            Err(RedirectUriError::Invalid) => {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "redirect_uri 与客户端注册信息不匹配.",
                );
            }
        };

    if q.get("response_type").map(String::as_str) != Some("code") {
        return redirect_found(append_query(
            &redirect_uri,
            &[
                ("error", "unsupported_response_type"),
                ("state", q.get("state").map(String::as_str).unwrap_or("")),
                ("iss", state.settings.issuer.as_str()),
            ],
        ));
    }
    let Some(code_challenge) = q.get("code_challenge") else {
        return redirect_found(append_query(
            &redirect_uri,
            &[
                ("error", "invalid_request"),
                ("state", q.get("state").map(String::as_str).unwrap_or("")),
                ("iss", state.settings.issuer.as_str()),
            ],
        ));
    };
    if q.get("code_challenge_method").map(String::as_str) != Some("S256")
        || !is_valid_pkce_value(code_challenge)
    {
        return redirect_found(append_query(
            &redirect_uri,
            &[
                ("error", "invalid_request"),
                ("state", q.get("state").map(String::as_str).unwrap_or("")),
                ("iss", state.settings.issuer.as_str()),
            ],
        ));
    }

    let prompt = q.get("prompt").map(String::as_str);
    if let Some(prompt) = prompt
        && !matches!(prompt, "login" | "none")
    {
        return redirect_found(append_query(
            &redirect_uri,
            &[
                ("error", "invalid_request"),
                ("state", q.get("state").map(String::as_str).unwrap_or("")),
                ("iss", state.settings.issuer.as_str()),
            ],
        ));
    }
    let max_age = match q.get("max_age") {
        Some(value) => match value.parse::<i64>() {
            Ok(value) if value >= 0 => Some(value),
            _ => {
                return redirect_found(append_query(
                    &redirect_uri,
                    &[
                        ("error", "invalid_request"),
                        ("state", q.get("state").map(String::as_str).unwrap_or("")),
                        ("iss", state.settings.issuer.as_str()),
                    ],
                ));
            }
        },
        None => None,
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
        if prompt == Some("none") {
            return redirect_found(append_query(
                &redirect_uri,
                &[
                    ("error", "login_required"),
                    ("state", q.get("state").map(String::as_str).unwrap_or("")),
                    ("iss", state.settings.issuer.as_str()),
                ],
            ));
        }
        return redirect_found(authorization_login_url(&state, &q, prompt == Some("login")));
    };
    if prompt == Some("login")
        || max_age.is_some_and(|max_age| Utc::now().timestamp() - session.auth_time > max_age)
    {
        if prompt == Some("none") {
            return redirect_found(append_query(
                &redirect_uri,
                &[
                    ("error", "login_required"),
                    ("state", q.get("state").map(String::as_str).unwrap_or("")),
                    ("iss", state.settings.issuer.as_str()),
                ],
            ));
        }
        return redirect_found(authorization_login_url(&state, &q, prompt == Some("login")));
    }

    let requested_scopes = parse_scope(q.get("scope").map(String::as_str).unwrap_or(""));
    if !is_subset(&requested_scopes, &json_array_to_strings(&client.scopes)) {
        return redirect_found(append_query(
            &redirect_uri,
            &[
                ("error", "invalid_scope"),
                ("state", q.get("state").map(String::as_str).unwrap_or("")),
                ("iss", state.settings.issuer.as_str()),
            ],
        ));
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
        nonce: q.get("nonce").cloned(),
        auth_time: session.auth_time,
        amr: session.amr,
        code_challenge: code_challenge.clone(),
        code_challenge_method: "S256".into(),
        issued_at: now,
        expires_at: now + Duration::seconds(state.settings.auth_code_ttl_seconds as i64),
    };
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
