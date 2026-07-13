//! refresh_token grant 处理。
// 只处理 refresh token 校验、复用检测和轮换前置约束。
use super::{
    TokenForm, consume_token_client_assertion, issue_token_response, should_issue_refresh_token,
};
use crate::http::prelude::*;
use crate::settings::AuthorizationServerProfile;

fn refresh_token_policy_for_authorization_server_profile(
    profile: AuthorizationServerProfile,
    _client: &ClientRow,
    token: &TokenRow,
) -> RefreshTokenPolicy {
    if profile.requires_fapi2_security() && refresh_token_has_stable_sender_constraint(token) {
        RefreshTokenPolicy::PreserveExisting
    } else {
        RefreshTokenPolicy::Rotate {
            family_id: token.token_family_id,
            rotated_from_id: token.id,
        }
    }
}

fn refresh_token_has_stable_sender_constraint(token: &TokenRow) -> bool {
    token.dpop_jkt.is_some() || token.mtls_x5t_s256.is_some()
}

fn refresh_token_policy_for_profile(
    settings: &Settings,
    client: &ClientRow,
    token: &TokenRow,
) -> RefreshTokenPolicy {
    refresh_token_policy_for_authorization_server_profile(
        settings.protocol().authorization_server_profile,
        client,
        token,
    )
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
    if is_subset(&requested, original_scopes)
        && requested.iter().any(|scope| scope == "offline_access")
    {
        Ok(requested)
    } else {
        Err(())
    }
}

fn refresh_token_audiences(
    settings: &Settings,
    token: &TokenRow,
    form: &TokenForm,
) -> Result<Vec<String>, ()> {
    let original_audiences = json_array_to_strings(&token.audience);
    let original_audiences = if original_audiences.is_empty() {
        vec![settings.default_audience.clone()]
    } else {
        original_audiences
    };
    if form.audiences.is_empty() {
        return Ok(original_audiences);
    }
    is_subset(&form.audiences, &original_audiences)
        .then(|| form.audiences.clone())
        .ok_or(())
}

async fn lost_response_successor_or_mark_reuse(
    state: &AppState,
    token: &TokenRow,
    client_id: Uuid,
    retry_started_at: DateTime<Utc>,
) -> anyhow::Result<Option<TokenRow>> {
    nazo_postgres::TokenRepository::new(state.diesel_db.clone())
        .lost_response_successor_or_compromise(token, client_id, retry_started_at)
        .await
        .map_err(|error| anyhow::anyhow!("failed to inspect refresh family: {error}"))
}

pub(crate) async fn token_refresh(
    state: &AppState,
    req: &HttpRequest,
    client: &ClientRow,
    form: &TokenForm,
    client_assertion: Option<&ValidatedClientAssertion>,
) -> HttpResponse {
    let request_started_at = Utc::now();
    let Some(refresh_token) = &form.refresh_token else {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "缺少 refresh_token.",
            false,
        );
    };
    let token = match nazo_postgres::TokenRepository::new(state.diesel_db.clone())
        .by_raw_refresh_token(client.tenant_id, refresh_token)
        .await
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
    let mut lost_response_original_id = None;
    if token.revoked_at.is_some() {
        let successor =
            lost_response_successor_or_mark_reuse(state, &token, client.id, request_started_at)
                .await;
        match successor {
            Ok(Some(successor)) => {
                lost_response_original_id = Some(token.id);
                token = successor;
            }
            Ok(None) => {
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
                tracing::warn!(%error, "failed to inspect or mark rotated refresh token family");
                return oauth_token_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "refresh_token 复用处理失败.",
                    false,
                );
            }
        }
    }
    let original_scopes = json_array_to_strings(&token.scopes);
    if let Some(user_id) = token.user_id {
        match (
            nazo_identity::TenantId::new(token.tenant_id),
            nazo_identity::UserId::new(user_id),
        ) {
            (Ok(tenant_id), Ok(user_id)) => {
                match nazo_postgres::UserRepository::new(state.diesel_db.clone())
                    .principal_by_tenant_id(tenant_id, user_id)
                    .await
                {
                    Ok(Some(principal)) if principal.active => {}
                    Ok(_) => {
                        return oauth_token_error(
                            StatusCode::BAD_REQUEST,
                            "invalid_grant",
                            "授权用户不存在或已停用.",
                            false,
                        );
                    }
                    Err(error) => {
                        tracing::warn!(%error, "failed to load refresh token user");
                        return oauth_token_error(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "server_error",
                            "refresh_token 用户校验失败.",
                            false,
                        );
                    }
                }
            }
            _ => {
                tracing::warn!("persisted refresh token contains invalid identity IDs");
                return oauth_token_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "refresh_token 用户校验失败.",
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
    if client.client_type == "public"
        && client.require_dpop_bound_tokens
        && token.dpop_jkt.is_none()
    {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh_token is not DPoP-bound.",
            false,
        );
    }
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
    let audiences = match refresh_token_audiences(&state.settings, &token, form) {
        Ok(audiences) => audiences,
        Err(()) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_target",
                "请求的 resource 超出 refresh_token 原始授权范围.",
                false,
            );
        }
    };
    if !audiences_allowed(client, &audiences) {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "请求的 audience 不在客户端允许范围内.",
            false,
        );
    }
    let refresh_token_policy = match lost_response_original_id {
        Some(original_id) => RefreshTokenPolicy::RotateLostResponse {
            family_id: token.token_family_id,
            original_id,
            successor_id: token.id,
            retry_started_at: request_started_at,
        },
        None => refresh_token_policy_for_profile(&state.settings, client, &token),
    };
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
            actor: None,
            issued_token_type: None,
            native_sso: None,
        },
    )
    .await
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/token/tests/refresh.rs"]
mod tests;
