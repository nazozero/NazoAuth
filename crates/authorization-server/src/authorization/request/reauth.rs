use crate::contracts::oauth_error::OAuthEndpointError;
use crate::crypto::random_urlsafe_token;
use chrono::Utc;
use http::StatusCode;

use std::collections::HashMap;

use super::{
    AuthorizationRequestContext, REAUTH_NONCE_PARAMETER, authorization_login_url_for_frontend,
};

const REAUTH_NONCE_TTL_SECONDS: u64 = 600;

pub(super) async fn consume_reauth_nonce_with_context(
    context: &AuthorizationRequestContext<'_>,
    nonce: Option<&str>,
    q: &HashMap<String, String>,
) -> Option<i64> {
    let key = reauth_nonce_key(nonce?, q);
    match context.service.take_reauth_nonce(&key).await {
        Ok(Some(started_at)) => (started_at > 0).then_some(started_at),
        Ok(None) => None,
        Err(error) => {
            tracing::warn!(%error, "failed to consume reauthentication nonce");
            None
        }
    }
}

pub(super) async fn authorization_login_url_with_context(
    context: &AuthorizationRequestContext<'_>,
    q: &HashMap<String, String>,
    reauthentication_required: bool,
) -> Result<String, OAuthEndpointError> {
    let reauth_nonce = if reauthentication_required {
        Some(issue_reauth_nonce(context, q).await?)
    } else {
        None
    };
    Ok(authorization_login_url_for_frontend(
        context.config.frontend_base_url.as_ref(),
        q,
        reauth_nonce.as_deref(),
    ))
}

async fn issue_reauth_nonce(
    context: &AuthorizationRequestContext<'_>,
    q: &HashMap<String, String>,
) -> Result<String, OAuthEndpointError> {
    let nonce = random_urlsafe_token();
    let started_at = Utc::now().timestamp_micros();
    context
        .service
        .store_reauth_nonce(
            &reauth_nonce_key(&nonce, q),
            started_at,
            REAUTH_NONCE_TTL_SECONDS,
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "failed to store reauthentication nonce");
            OAuthEndpointError::json(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "重新认证状态写入失败.",
            )
        })?;
    Ok(nonce)
}

/// Bind one completion to the original request, including the PAR/JAR identity.
/// Sorting makes query ordering irrelevant; length-delimited JSON pairs preserve
/// boundaries between parameter names and values. No request data enters KV keys.
pub(super) fn reauth_nonce_key(nonce: &str, query: &HashMap<String, String>) -> String {
    let parameters: std::collections::BTreeMap<_, _> = query
        .iter()
        .filter(|(name, _)| name.as_str() != REAUTH_NONCE_PARAMETER)
        .collect();
    let encoded = serde_json::to_string(&parameters).expect("string map serialization cannot fail");
    format!("v2:{nonce}:{}", crate::crypto::blake3_hex(&encoded))
}
