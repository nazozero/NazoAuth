//! refresh_token grant 处理。
// 只处理 refresh token 校验、复用检测和轮换前置约束。
use super::{TokenForm, issue_token_response, should_issue_refresh_token};
use crate::http::prelude::*;

async fn mark_token_family_reuse(state: &AppState, token_family_id: Uuid) -> anyhow::Result<()> {
    let mut conn = get_conn(&state.diesel_db).await?;
    diesel::update(oauth_tokens::table.filter(oauth_tokens::token_family_id.eq(token_family_id)))
        .set(oauth_tokens::reuse_detected_at.eq(diesel_now))
        .execute(&mut conn)
        .await?;
    diesel::update(
        oauth_tokens::table
            .filter(oauth_tokens::token_family_id.eq(token_family_id))
            .filter(oauth_tokens::revoked_at.is_null()),
    )
    .set(oauth_tokens::revoked_at.eq(diesel_now))
    .execute(&mut conn)
    .await?;
    Ok(())
}

pub(crate) async fn token_refresh(
    state: &AppState,
    req: &HttpRequest,
    client: &ClientRow,
    form: &TokenForm,
) -> HttpResponse {
    let Some(refresh_token) = &form.refresh_token else {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "缺少 refresh_token.",
            false,
        );
    };
    let hash = blake3_hex(refresh_token);
    let token = match get_conn(&state.diesel_db).await {
        Ok(mut conn) => match oauth_tokens::table
            .filter(oauth_tokens::refresh_token_blake3.eq(hash))
            .select(TokenRow::as_select())
            .first::<TokenRow>(&mut conn)
            .await
            .optional()
        {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(%error, "failed to load refresh token");
                return oauth_token_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "refresh_token 校验失败.",
                    false,
                );
            }
        },
        Err(error) => {
            tracing::warn!(%error, "failed to get database connection for refresh token lookup");
            return oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "refresh_token 校验失败.",
                false,
            );
        }
    };
    let Some(token) = token else {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh_token 无效.",
            false,
        );
    };
    if token.client_id != client.id || token.expires_at <= Utc::now() {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh_token 无效或已撤销.",
            false,
        );
    }
    if token.revoked_at.is_some() {
        if let Err(error) = mark_token_family_reuse(state, token.token_family_id).await {
            tracing::warn!(%error, "failed to mark refresh token family reuse");
            return oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "refresh_token 复用处理失败.",
                false,
            );
        }
        audit_event(
            "refresh_reuse_detected",
            audit_fields(&[
                ("client_id", json!(client.client_id)),
                ("token_family_id", json!(token.token_family_id)),
                (
                    "source_ip_hash",
                    json!(blake3_hex(&client_ip(req, &state.settings))),
                ),
            ]),
        );
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh_token 无效或已撤销.",
            false,
        );
    }
    let dpop_jkt = if let Some(expected_jkt) = token.dpop_jkt.clone() {
        match validate_dpop_proof(state, req, None, Some(&expected_jkt)).await {
            Ok(_) => Some(expected_jkt),
            Err(error) => return dpop_error_response(error, DpopErrorContext::TokenEndpoint),
        }
    } else {
        if dpop_proof_present(req) {
            return dpop_error_response(DpopError::TokenNotBound, DpopErrorContext::TokenEndpoint);
        }
        None
    };
    let original_scopes = json_array_to_strings(&token.scopes);
    if !should_issue_refresh_token(client, &original_scopes) {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh_token 不具备离线访问授权.",
            false,
        );
    }
    let requested_scopes = form.scope.as_deref().map(parse_scope);
    let scopes = match requested_scopes {
        Some(requested) if requested.is_empty() => original_scopes,
        Some(requested) if is_subset(&requested, &original_scopes) => requested,
        Some(_) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_scope",
                "请求的作用域超出 refresh_token 原始授权范围.",
                false,
            );
        }
        None => original_scopes,
    };
    let audience = form
        .audience
        .clone()
        .unwrap_or_else(|| state.settings.default_audience.clone());
    if !audience_allowed(client, &audience) {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "请求的 audience 不在客户端允许范围内.",
            false,
        );
    }
    issue_token_response(
        state,
        client,
        TokenIssue {
            user_id: token.user_id,
            subject: token.subject,
            scopes,
            audience,
            nonce: None,
            auth_time: None,
            amr: Vec::new(),
            include_refresh: true,
            rotation: Some((token.token_family_id, Some(token.id))),
            dpop_jkt,
            authorization_code_hash: None,
        },
    )
    .await
}
