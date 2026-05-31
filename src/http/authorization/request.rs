//! 授权请求入口端点。
// 该端点只创建 consent 临时状态，不签发授权码。
use crate::http::prelude::*;

/// 校验 OAuth authorize 参数并创建待确认授权请求。
pub(crate) async fn authorize(
    state: Data<AppState>,
    req: HttpRequest,
    Query(q): Query<HashMap<String, String>>,
) -> HttpResponse {
    if has_duplicate_oauth_parameter(
        req.query_string(),
        &[
            "response_type",
            "client_id",
            "redirect_uri",
            "scope",
            "state",
            "code_challenge",
            "code_challenge_method",
            "nonce",
        ],
    ) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "OAuth 参数不能重复.",
        );
    }

    let user = match current_user(&state, &req).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            let query = q
                .iter()
                .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
                .collect::<Vec<_>>()
                .join("&");
            let next = if query.is_empty() {
                "/authorize".to_string()
            } else {
                format!("/authorize?{query}")
            };
            return redirect_found(format!(
                "{}/auth?next={}",
                state.settings.frontend_base_url.trim_end_matches('/'),
                urlencoding::encode(&next)
            ));
        }
        Err(error) => {
            tracing::warn!(%error, "failed to resolve authorization request user");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "会话查询失败.",
            );
        }
    };

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
        user_id: user.id,
        client_id: client.client_id,
        client_name: client.client_name,
        redirect_uri: redirect_uri.clone(),
        redirect_uri_was_supplied: q.contains_key("redirect_uri"),
        scopes: requested_scopes,
        state: q.get("state").cloned(),
        nonce: q.get("nonce").cloned(),
        code_challenge: code_challenge.clone(),
        code_challenge_method: "S256".into(),
        issued_at: now,
        expires_at: now + Duration::seconds(state.settings.auth_code_ttl_seconds as i64),
    };
    let key = format!("oauth:consent:{request_id}");
    let body = serde_json::to_string(&payload).unwrap();
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
