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
    "request_uri",
    "request",
];

fn authorization_pkce(
    client: &ClientRow,
    q: &HashMap<String, String>,
) -> Result<(Option<String>, Option<String>), ()> {
    match (
        q.get("code_challenge").map(String::as_str),
        q.get("code_challenge_method").map(String::as_str),
    ) {
        (Some(code_challenge), Some("S256")) if is_valid_pkce_value(code_challenge) => {
            Ok((Some(code_challenge.to_owned()), Some("S256".to_owned())))
        }
        (None, None) if client.client_type == "confidential" => Ok((None, None)),
        _ => Err(()),
    }
}

fn requested_acr(q: &HashMap<String, String>) -> Option<String> {
    q.get("acr_values").and_then(|value| {
        value
            .split_whitespace()
            .find(|value| !value.is_empty())
            .map(str::to_owned)
    })
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

fn requested_claims(q: &HashMap<String, String>) -> Result<(Vec<String>, Vec<String>), ()> {
    let Some(raw_claims) = q.get("claims") else {
        return Ok((Vec::new(), Vec::new()));
    };
    let claims: Value = serde_json::from_str(raw_claims).map_err(|_| ())?;
    let userinfo = requested_claim_names(claims.get("userinfo"))?;
    let id_token = requested_claim_names(claims.get("id_token"))?;
    Ok((userinfo, id_token))
}

fn requested_claim_names(value: Option<&Value>) -> Result<Vec<String>, ()> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let Some(object) = value.as_object() else {
        return Err(());
    };
    let mut names = Vec::new();
    for name in object.keys() {
        if supported_user_claim(name) {
            names.push(name.clone());
        }
    }
    names.sort();
    names.dedup();
    Ok(names)
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

    let mut pushed_dpop_jkt = None;
    if let Some(request_uri) = q.get("request_uri").cloned() {
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
        if !outer_request_uri_parameters_match_pushed(q, &pushed.params) {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "request_uri 请求不能被外层参数覆盖.",
            );
        }
        pushed_dpop_jkt = pushed.dpop_jkt;
        *q = pushed.params;
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
    if let Err(response) = apply_request_object(&state, q, &client).await {
        return response;
    }
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
    if client.require_dpop_bound_tokens && dpop_jkt.is_none() {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "该客户端要求 DPoP sender constraint.",
        );
    }
    preserve_verified_dpop_binding(q, dpop_jkt.as_deref());
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
    let (code_challenge, code_challenge_method) = match authorization_pkce(&client, q) {
        Ok(value) => value,
        Err(()) => {
            return redirect_found(append_query(
                &redirect_uri,
                &[
                    ("error", "invalid_request"),
                    ("state", q.get("state").map(String::as_str).unwrap_or("")),
                    ("iss", state.settings.issuer.as_str()),
                ],
            ));
        }
    };

    let prompt = match requested_prompt(q) {
        Ok(prompt) => prompt,
        Err(()) => {
            return redirect_found(append_query(
                &redirect_uri,
                &[
                    ("error", "invalid_request"),
                    ("state", q.get("state").map(String::as_str).unwrap_or("")),
                    ("iss", state.settings.issuer.as_str()),
                ],
            ));
        }
    };
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
    let (userinfo_claims, id_token_claims) = match requested_claims(q) {
        Ok(value) => value,
        Err(()) => {
            return redirect_found(append_query(
                &redirect_uri,
                &[
                    ("error", "invalid_request"),
                    ("state", q.get("state").map(String::as_str).unwrap_or("")),
                    ("iss", state.settings.issuer.as_str()),
                ],
            ));
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
            return redirect_found(append_query(
                &redirect_uri,
                &[
                    ("error", "login_required"),
                    ("state", q.get("state").map(String::as_str).unwrap_or("")),
                    ("iss", state.settings.issuer.as_str()),
                ],
            ));
        }
        return redirect_found(authorization_login_url(
            &state,
            q,
            prompt.login || prompt.select_account,
        ));
    };
    if prompt.login
        || prompt.select_account
        || max_age.is_some_and(|max_age| Utc::now().timestamp() - session.auth_time > max_age)
    {
        if prompt.none {
            return redirect_found(append_query(
                &redirect_uri,
                &[
                    ("error", "login_required"),
                    ("state", q.get("state").map(String::as_str).unwrap_or("")),
                    ("iss", state.settings.issuer.as_str()),
                ],
            ));
        }
        return redirect_found(authorization_login_url(
            &state,
            q,
            prompt.login || prompt.select_account,
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
        acr: requested_acr(q),
        userinfo_claims,
        id_token_claims,
        code_challenge,
        code_challenge_method,
        dpop_jkt,
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn client(client_type: &str) -> ClientRow {
        ClientRow {
            id: Uuid::now_v7(),
            client_id: "client-1".to_owned(),
            client_name: "Client".to_owned(),
            client_type: client_type.to_owned(),
            client_secret_argon2_hash: None,
            redirect_uris: json!(["https://client.example/callback"]),
            scopes: json!(["openid"]),
            allowed_audiences: json!(["api"]),
            grant_types: json!(["authorization_code"]),
            token_endpoint_auth_method: if client_type == "confidential" {
                "client_secret_basic".to_owned()
            } else {
                "none".to_owned()
            },
            require_dpop_bound_tokens: false,
            is_active: true,
            jwks: None,
        }
    }

    fn query(values: &[(&str, &str)]) -> HashMap<String, String> {
        values
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn first_acr_value_is_used_for_id_token_acr() {
        assert_eq!(
            requested_acr(&query(&[("acr_values", "urn:one urn:two")])),
            Some("urn:one".to_owned())
        );
        assert_eq!(requested_acr(&query(&[("acr_values", "   ")])), None);
    }

    #[test]
    fn claims_parameter_extracts_supported_user_claim_names() {
        let (userinfo, id_token) = requested_claims(&query(&[(
            "claims",
            r#"{"userinfo":{"name":{"essential":true},"unknown":null},"id_token":{"email":{"essential":true}}}"#,
        )]))
        .unwrap();

        assert_eq!(userinfo, vec!["name".to_owned()]);
        assert_eq!(id_token, vec!["email".to_owned()]);
    }

    #[test]
    fn malformed_claims_parameter_is_invalid() {
        assert!(requested_claims(&query(&[("claims", "not-json")])).is_err());
        assert!(requested_claims(&query(&[("claims", r#"{"userinfo":[]}"#)])).is_err());
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
    fn public_authorization_request_requires_s256_pkce() {
        assert!(authorization_pkce(&client("public"), &query(&[])).is_err());
        assert!(
            authorization_pkce(
                &client("public"),
                &query(&[
                    (
                        "code_challenge",
                        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
                    ),
                    ("code_challenge_method", "plain"),
                ]),
            )
            .is_err()
        );
        assert!(
            authorization_pkce(
                &client("public"),
                &query(&[
                    (
                        "code_challenge",
                        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
                    ),
                    ("code_challenge_method", "S256"),
                ]),
            )
            .is_ok()
        );
    }

    #[test]
    fn confidential_authorization_request_may_use_oidc_core_without_pkce() {
        assert!(authorization_pkce(&client("confidential"), &query(&[])).is_ok());
        assert!(
            authorization_pkce(
                &client("confidential"),
                &query(&[
                    (
                        "code_challenge",
                        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
                    ),
                    ("code_challenge_method", "S256"),
                ]),
            )
            .is_ok()
        );
        assert!(
            authorization_pkce(
                &client("confidential"),
                &query(&[
                    (
                        "code_challenge",
                        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
                    ),
                    ("code_challenge_method", "plain"),
                ]),
            )
            .is_err()
        );
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
