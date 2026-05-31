//! token revoke 端点。
// 只处理 refresh token 撤销和 access token jti 黑名单写入。
use super::{TokenOnlyForm, authenticate_token_management_client};
use crate::http::prelude::*;

pub(crate) async fn revoke(
    state: Data<AppState>,
    req: HttpRequest,
    Form(form): Form<TokenOnlyForm>,
) -> HttpResponse {
    if let Err(response) = enforce_rate_limit(&state, &req, RateLimitPolicy::TokenManagement).await
    {
        return response;
    }

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
            "同一请求不能同时使用多种客户端认证方式.",
        );
    }
    let credentials = extract_client_credentials(
        req.headers(),
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
    let Some(client) = find_client(&state.diesel_db, client_id)
        .await
        .ok()
        .flatten()
    else {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "客户端认证失败.",
        );
    };
    if !authenticate_token_management_client(&state, &req, &client, &credentials).await {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "客户端认证失败.",
        );
    }
    let refresh_hash = blake3_hex(&form.token);
    let updated = match get_conn(&state.diesel_db).await {
        Ok(mut conn) => diesel::update(
            oauth_tokens::table
                .filter(oauth_tokens::refresh_token_blake3.eq(&refresh_hash))
                .filter(oauth_tokens::client_id.eq(client.id)),
        )
        .set(oauth_tokens::revoked_at.eq(diesel_now))
        .execute(&mut conn)
        .await
        .unwrap_or(0),
        Err(_) => 0,
    };
    if updated == 0
        && let Some(claims) = decode_access_claims(&state, &form.token)
        && claims.client_id == client.client_id
        && let (Some(expires_at), Ok(mut conn)) = (
            DateTime::<Utc>::from_timestamp(claims.exp, 0),
            get_conn(&state.diesel_db).await,
        )
    {
        let _ = diesel::insert_into(access_token_revocations::table)
            .values((
                access_token_revocations::access_token_jti_blake3.eq(blake3_hex(&claims.jti)),
                access_token_revocations::client_id.eq(client.id),
                access_token_revocations::revoked_at.eq(Utc::now()),
                access_token_revocations::expires_at.eq(expires_at),
            ))
            .on_conflict(access_token_revocations::access_token_jti_blake3)
            .do_nothing()
            .execute(&mut conn)
            .await;
    }
    json_response(json!({"result": "已处理"}))
}
