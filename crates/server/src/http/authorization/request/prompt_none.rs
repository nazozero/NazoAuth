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
    let stored = match nazo_postgres::GrantRepository::new(state.diesel_db.clone())
        .authorization(user_id, client_id)
        .await
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
    Ok(stored.as_ref().is_some_and(|stored| {
        stored_grant_covers_requested_authorization(
            &stored.scopes,
            &stored.resource_indicators,
            &stored.authorization_details,
            requested_scopes,
            requested_resource_indicators,
            requested_authorization_details,
        )
    }))
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
        expires_at: now + Duration::seconds(state.settings.protocol().auth_code_ttl_seconds as i64),
    };
    if let Err(error) = nazo_valkey::AuthorizationStore::new(&state.valkey_connection())
        .store_authorization_code_hash(
            &blake3_hex(&code),
            &AuthorizationCodeState::Pending {
                payload: code_payload,
            },
            state.settings.protocol().auth_code_ttl_seconds,
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
