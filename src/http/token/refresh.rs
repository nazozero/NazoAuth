//! refresh_token grant 处理。
// 只处理 refresh token 校验、复用检测和轮换前置约束。
use super::{
    TokenForm, consume_token_client_assertion, issue_token_response, should_issue_refresh_token,
};
use crate::http::prelude::*;
use crate::settings::AuthorizationServerProfile;

const LOST_REFRESH_TOKEN_RETRY_SECONDS: i64 = 30;

fn refresh_token_policy_for_authorization_server_profile(
    profile: AuthorizationServerProfile,
    client: &ClientRow,
    token: &TokenRow,
) -> RefreshTokenPolicy {
    if profile.requires_fapi2_security()
        || confidential_client_has_sender_constrained_refresh_token(client, token)
    {
        RefreshTokenPolicy::PreserveExisting
    } else {
        RefreshTokenPolicy::Rotate {
            family_id: token.token_family_id,
            rotated_from_id: token.id,
        }
    }
}

fn confidential_client_has_sender_constrained_refresh_token(
    client: &ClientRow,
    token: &TokenRow,
) -> bool {
    if client.client_type != "confidential"
        || !matches!(
            client.token_endpoint_auth_method.as_str(),
            "private_key_jwt" | "tls_client_auth" | "self_signed_tls_client_auth"
        )
    {
        return false;
    }

    client.require_dpop_bound_tokens
        || client.require_mtls_bound_tokens
        || token.dpop_jkt.is_some()
        || token.mtls_x5t_s256.is_some()
}

fn refresh_token_policy_for_profile(
    settings: &Settings,
    client: &ClientRow,
    token: &TokenRow,
) -> RefreshTokenPolicy {
    refresh_token_policy_for_authorization_server_profile(
        settings.authorization_server_profile,
        client,
        token,
    )
}

fn within_lost_refresh_token_retry_window(revoked_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    let elapsed = now.signed_duration_since(revoked_at);
    elapsed >= Duration::zero() && elapsed <= Duration::seconds(LOST_REFRESH_TOKEN_RETRY_SECONDS)
}

fn refresh_token_scopes(
    original_scopes: &[String],
    requested_scope: Option<&str>,
) -> Result<Vec<String>, ()> {
    let Some(requested) = requested_scope.map(parse_scope) else {
        return Ok(original_scopes.to_vec());
    };
    if requested.is_empty() {
        return Ok(original_scopes.to_vec());
    }
    if is_subset(&requested, original_scopes) {
        Ok(requested)
    } else {
        Err(())
    }
}

async fn mark_token_family_reuse(
    state: &AppState,
    tenant_id: Uuid,
    token_family_id: Uuid,
) -> anyhow::Result<()> {
    let mut conn = get_conn(&state.diesel_db).await?;
    diesel::update(
        oauth_tokens::table
            .filter(oauth_tokens::tenant_id.eq(tenant_id))
            .filter(oauth_tokens::token_family_id.eq(token_family_id)),
    )
    .set(oauth_tokens::reuse_detected_at.eq(diesel_now))
    .execute(&mut conn)
    .await?;
    diesel::update(
        oauth_tokens::table
            .filter(oauth_tokens::tenant_id.eq(tenant_id))
            .filter(oauth_tokens::token_family_id.eq(token_family_id))
            .filter(oauth_tokens::revoked_at.is_null()),
    )
    .set(oauth_tokens::revoked_at.eq(diesel_now))
    .execute(&mut conn)
    .await?;
    Ok(())
}

async fn lost_refresh_token_successor(
    state: &AppState,
    token: &TokenRow,
    client_id: Uuid,
) -> anyhow::Result<Option<TokenRow>> {
    let Some(revoked_at) = token.revoked_at else {
        return Ok(None);
    };
    if !within_lost_refresh_token_retry_window(revoked_at, Utc::now()) {
        return Ok(None);
    }

    let mut conn = get_conn(&state.diesel_db).await?;
    let reuse_count = oauth_tokens::table
        .filter(oauth_tokens::tenant_id.eq(token.tenant_id))
        .filter(oauth_tokens::token_family_id.eq(token.token_family_id))
        .filter(oauth_tokens::reuse_detected_at.is_not_null())
        .select(diesel::dsl::count_star())
        .first::<i64>(&mut conn)
        .await?;
    if reuse_count != 0 {
        return Ok(None);
    }

    let now = Utc::now();
    let mut successors = oauth_tokens::table
        .filter(oauth_tokens::tenant_id.eq(token.tenant_id))
        .filter(oauth_tokens::rotated_from_id.eq(token.id))
        .filter(oauth_tokens::token_family_id.eq(token.token_family_id))
        .filter(oauth_tokens::client_id.eq(client_id))
        .filter(oauth_tokens::revoked_at.is_null())
        .filter(oauth_tokens::expires_at.gt(now))
        .select(TokenRow::as_select())
        .load::<TokenRow>(&mut conn)
        .await?;
    if successors.len() == 1 {
        Ok(successors.pop())
    } else {
        Ok(None)
    }
}

pub(crate) async fn token_refresh(
    state: &AppState,
    req: &HttpRequest,
    client: &ClientRow,
    form: &TokenForm,
    client_assertion: Option<&ValidatedClientAssertion>,
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
            .filter(oauth_tokens::tenant_id.eq(client.tenant_id))
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
    let Some(mut token) = token else {
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
        match lost_refresh_token_successor(state, &token, client.id).await {
            Ok(Some(successor)) => {
                token = successor;
            }
            Ok(None) => {
                if let Err(error) =
                    mark_token_family_reuse(state, token.tenant_id, token.token_family_id).await
                {
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
            Err(error) => {
                tracing::warn!(%error, "failed to inspect rotated refresh token successor");
                return oauth_token_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "refresh_token 校验失败.",
                    false,
                );
            }
        }
    }
    let dpop_jkt = if dpop_proof_present(req) {
        match validate_dpop_proof(state, req, None, token.dpop_jkt.as_deref()).await {
            Ok(value) => value.or(token.dpop_jkt.clone()),
            Err(error) => return dpop_error_response(error, DpopErrorContext::TokenEndpoint),
        }
    } else if token.dpop_jkt.is_some() {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh_token requires proof of possession.",
            false,
        );
    } else {
        None
    };
    if client.require_dpop_bound_tokens && dpop_jkt.is_none() {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh_token requires proof of possession.",
            false,
        );
    }
    let mtls_x5t_s256 = if let Some(expected) = token.mtls_x5t_s256.clone() {
        match request_mtls_thumbprint(req, &state.settings) {
            Some(actual) if constant_time_eq(expected.as_bytes(), actual.as_bytes()) => {
                Some(expected)
            }
            _ => {
                return oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "refresh_token requires mTLS proof of possession.",
                    false,
                );
            }
        }
    } else if client.require_mtls_bound_tokens {
        match request_mtls_thumbprint(req, &state.settings) {
            Some(actual) => Some(actual),
            None => {
                return oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "refresh_token requires mTLS proof of possession.",
                    false,
                );
            }
        }
    } else {
        None
    };
    if let Err(response) = consume_token_client_assertion(state, client, client_assertion).await {
        return response;
    }
    let original_scopes = json_array_to_strings(&token.scopes);
    if !should_issue_refresh_token(client, &original_scopes) {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh_token 不具备离线访问授权.",
            false,
        );
    }
    let scopes = match refresh_token_scopes(&original_scopes, form.scope.as_deref()) {
        Ok(scopes) => scopes,
        Err(()) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_scope",
                "请求的作用域超出 refresh_token 原始授权范围.",
                false,
            );
        }
    };
    let audiences = if form.audiences.is_empty() {
        vec![state.settings.default_audience.clone()]
    } else {
        form.audiences.clone()
    };
    if !audiences_allowed(client, &audiences) {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "请求的 audience 不在客户端允许范围内.",
            false,
        );
    }
    let refresh_token_policy = refresh_token_policy_for_profile(&state.settings, client, &token);
    issue_token_response(
        state,
        client,
        TokenIssue {
            user_id: token.user_id,
            subject: token.subject,
            scopes,
            authorization_details: token.authorization_details,
            audiences,
            nonce: None,
            auth_time: None,
            amr: Vec::new(),
            oidc_sid: None,
            acr: None,
            userinfo_claims: Vec::new(),
            userinfo_claim_requests: Vec::new(),
            id_token_claims: Vec::new(),
            id_token_claim_requests: Vec::new(),
            include_refresh: true,
            refresh_token_policy,
            dpop_jkt: dpop_jkt.clone(),
            refresh_token_dpop_jkt: token.dpop_jkt,
            mtls_x5t_s256: mtls_x5t_s256.clone(),
            refresh_token_mtls_x5t_s256: mtls_x5t_s256,
            authorization_code_hash: None,
        },
    )
    .await
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/token/tests/refresh.rs"]
mod tests;
