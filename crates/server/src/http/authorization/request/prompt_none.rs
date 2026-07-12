use crate::http::authorization::request::{
    AuthorizationResponseRedirect, PushedAuthorizationRequestConsumeError,
    authorization_response_redirect, consume_pushed_authorization_request,
};
use crate::http::prelude::*;

pub(super) async fn user_grant_covers_requested_scopes(
    state: &AppState,
    user_id: Uuid,
    client_id: Uuid,
    requested_scopes: &[String],
    requested_resource_indicators: &[String],
    requested_authorization_details: &Value,
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
    let stored = match user_client_grants::table
        .filter(user_client_grants::tenant_id.eq(DEFAULT_TENANT_ID))
        .filter(user_client_grants::user_id.eq(user_id))
        .filter(user_client_grants::client_id.eq(client_id))
        .select((
            user_client_grants::last_scopes,
            user_client_grants::last_resource_indicators,
            user_client_grants::last_authorization_details,
        ))
        .first::<(Value, Value, Value)>(&mut conn)
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
    Ok(stored.as_ref().is_some_and(
        |(stored_scopes, stored_resource_indicators, stored_authorization_details)| {
            stored_grant_covers_requested_authorization(
                stored_scopes,
                stored_resource_indicators,
                stored_authorization_details,
                requested_scopes,
                requested_resource_indicators,
                requested_authorization_details,
            )
        },
    ))
}

pub(super) fn stored_grant_covers_requested_authorization(
    stored_scopes: &Value,
    stored_resource_indicators: &Value,
    stored_authorization_details: &Value,
    requested_scopes: &[String],
    requested_resource_indicators: &[String],
    requested_authorization_details: &Value,
) -> bool {
    if !is_subset(requested_scopes, &json_array_to_strings(stored_scopes)) {
        return false;
    }
    if !is_subset(
        requested_resource_indicators,
        &json_array_to_strings(stored_resource_indicators),
    ) {
        return false;
    }
    if authorization_details_empty(requested_authorization_details) {
        return true;
    }
    if high_risk_authorization_details(requested_authorization_details) {
        return false;
    }
    canonical_authorization_details(stored_authorization_details).ok()
        == canonical_authorization_details(requested_authorization_details).ok()
}

pub(super) async fn issue_authorization_code_without_interaction(
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
                    AuthorizationResponseRedirect {
                        redirect_uri: &payload.redirect_uri,
                        client_id: &payload.client_id,
                        response_mode: payload.response_mode.as_deref(),
                        code: None,
                        error: Some("invalid_request_uri"),
                        state: payload.state.as_deref(),
                        oidc_sid: None,
                    },
                )
                .await;
            }
            Err(PushedAuthorizationRequestConsumeError::ReadFailed)
            | Err(PushedAuthorizationRequestConsumeError::Malformed) => {
                return authorization_response_redirect(
                    state,
                    AuthorizationResponseRedirect {
                        redirect_uri: &payload.redirect_uri,
                        client_id: &payload.client_id,
                        response_mode: payload.response_mode.as_deref(),
                        code: None,
                        error: Some("server_error"),
                        state: payload.state.as_deref(),
                        oidc_sid: None,
                    },
                )
                .await;
            }
        }
    }

    let now = Utc::now();
    let code = random_urlsafe_token();
    let oidc_sid = payload.oidc_sid.clone();
    let code_payload = CodePayload {
        code_id: Uuid::now_v7().to_string(),
        user_id: payload.user_id,
        client_id: payload.client_id.clone(),
        redirect_uri: payload.redirect_uri.clone(),
        redirect_uri_was_supplied: payload.redirect_uri_was_supplied,
        scopes: payload.scopes.clone(),
        resource_indicators: payload.resource_indicators,
        authorization_details: payload.authorization_details,
        nonce: payload.nonce,
        auth_time: payload.auth_time,
        amr: payload.amr,
        oidc_sid: payload.oidc_sid,
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
    let body = serde_json::to_string(&AuthorizationCodeState::Pending {
        payload: code_payload,
    })
    .expect("prompt=none authorization code state serialization must be infallible");
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
        AuthorizationResponseRedirect {
            redirect_uri: &payload.redirect_uri,
            client_id: &payload.client_id,
            response_mode: payload.response_mode.as_deref(),
            code: Some(&code),
            error: None,
            state: payload.state.as_deref(),
            oidc_sid: oidc_sid.as_deref(),
        },
    )
    .await
}
