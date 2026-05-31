//! token revoke 端点。
// 只处理 refresh token 撤销和 access token jti 黑名单写入。
use super::{TokenOnlyForm, authenticate_revocation_client, token_management_auth_error};
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

    let has_basic = has_basic_authorization_scheme(req.headers());
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
    let client = match find_client(&state.diesel_db, client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "客户端认证失败.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to query oauth client for token revocation");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端查询失败.",
            );
        }
    };
    if let Err(error) = authenticate_revocation_client(&state, &req, &client, &credentials).await {
        return token_management_auth_error(error);
    }
    let refresh_hash = blake3_hex(&form.token);
    let updated = match get_conn(&state.diesel_db).await {
        Ok(mut conn) => match diesel::update(
            oauth_tokens::table
                .filter(oauth_tokens::refresh_token_blake3.eq(&refresh_hash))
                .filter(oauth_tokens::client_id.eq(client.id)),
        )
        .set(oauth_tokens::revoked_at.eq(diesel_now))
        .execute(&mut conn)
        .await
        {
            Ok(updated) => updated,
            Err(error) => {
                tracing::warn!(%error, "failed to revoke refresh token");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "token 撤销失败.",
                );
            }
        },
        Err(error) => {
            tracing::warn!(%error, "failed to get database connection for token revocation");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "token 撤销失败.",
            );
        }
    };
    if updated == 0
        && let Some(claims) = decode_access_claims(&state, &form.token)
        && claims.client_id == client.client_id
        && let Some(expires_at) = DateTime::<Utc>::from_timestamp(claims.exp, 0)
    {
        let mut conn = match get_conn(&state.diesel_db).await {
            Ok(conn) => conn,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "failed to get database connection for access token revocation"
                );
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "token 撤销失败.",
                );
            }
        };
        if let Err(error) = diesel::insert_into(access_token_revocations::table)
            .values((
                access_token_revocations::access_token_jti_blake3.eq(blake3_hex(&claims.jti)),
                access_token_revocations::client_id.eq(client.id),
                access_token_revocations::revoked_at.eq(Utc::now()),
                access_token_revocations::expires_at.eq(expires_at),
            ))
            .on_conflict(access_token_revocations::access_token_jti_blake3)
            .do_nothing()
            .execute(&mut conn)
            .await
        {
            tracing::warn!(%error, "failed to revoke access token");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "token 撤销失败.",
            );
        }
    }
    json_response_no_store(json!({"result": "已处理"}))
}
