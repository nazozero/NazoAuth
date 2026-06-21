//! token revoke 端点。
// 只处理 refresh token 撤销和 access token jti 黑名单写入。
use super::{
    TokenManagementClientAuthError, authenticate_revocation_client, parse_token_management_form,
    token_management_client_auth_error, token_management_form_error,
    token_management_has_conflicting_client_auth, token_management_oauth_error,
};
use crate::http::prelude::*;

pub(crate) async fn revoke(state: Data<AppState>, req: HttpRequest, body: Bytes) -> HttpResponse {
    if let Err(response) = enforce_rate_limit(&state, &req, RateLimitPolicy::TokenManagement).await
    {
        return response;
    }
    revoke_after_rate_limit(state, req, body).await
}

pub(crate) async fn revoke_after_rate_limit(
    state: Data<AppState>,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    let form = match parse_token_management_form(&req, &body) {
        Ok(form) => form,
        Err(error) => return token_management_form_error(error),
    };

    let has_basic = has_basic_authorization_scheme(req.headers());
    if token_management_has_conflicting_client_auth(has_basic, &form) {
        return token_management_oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "同一请求不能同时使用多种客户端认证方式.",
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
        return token_management_client_auth_error(
            TokenManagementClientAuthError::InvalidClient,
            has_basic,
        );
    };
    let mut conn = match get_conn(&state.diesel_db).await {
        Ok(conn) => conn,
        Err(error) => {
            tracing::warn!(%error, "failed to get database connection for token revocation client lookup");
            return token_management_oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端查询失败.",
            );
        }
    };
    let client = match oauth_clients::table
        .filter(oauth_clients::tenant_id.eq(DEFAULT_TENANT_ID))
        .filter(oauth_clients::client_id.eq(client_id))
        .select(ClientRow::as_select())
        .first::<ClientRow>(&mut conn)
        .await
        .optional()
    {
        Ok(Some(client)) => client,
        Ok(None) => {
            return token_management_client_auth_error(
                TokenManagementClientAuthError::InvalidClient,
                has_basic,
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to query oauth client for token revocation");
            return token_management_oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端查询失败.",
            );
        }
    };
    if let Err(error) = authenticate_revocation_client(&state, &req, &client, &credentials).await {
        return token_management_client_auth_error(error, has_basic);
    }
    let refresh_hash = blake3_hex(&form.token);
    let updated = match diesel::update(
        oauth_tokens::table
            .filter(oauth_tokens::tenant_id.eq(client.tenant_id))
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
            return token_management_oauth_error(
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
        if let Err(error) = diesel::insert_into(access_token_revocations::table)
            .values((
                access_token_revocations::access_token_jti_blake3.eq(blake3_hex(&claims.jti)),
                access_token_revocations::tenant_id.eq(client.tenant_id),
                access_token_revocations::client_id.eq(client.id),
                access_token_revocations::revoked_at.eq(Utc::now()),
                access_token_revocations::expires_at.eq(expires_at),
            ))
            .on_conflict((
                access_token_revocations::tenant_id,
                access_token_revocations::access_token_jti_blake3,
            ))
            .do_nothing()
            .execute(&mut conn)
            .await
        {
            tracing::warn!(%error, "failed to revoke access token");
            return token_management_oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "token 撤销失败.",
            );
        }
    }
    audit_event(
        "token_revoked",
        audit_fields(&[
            ("client_id", json!(client.client_id)),
            ("token_hash", json!(blake3_hex(&form.token))),
            ("updated", json!(updated)),
            (
                "source_ip_hash",
                json!(blake3_hex(&client_ip(&req, &state.settings))),
            ),
        ]),
    );
    empty_response_no_store(StatusCode::OK)
}

#[cfg(test)]
#[path = "../../../tests/unit/src/http/token/tests/revoke.rs"]
mod tests;
