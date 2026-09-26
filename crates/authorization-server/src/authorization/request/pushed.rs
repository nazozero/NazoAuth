use super::AuthorizationOutcome;
use crate::contracts::oauth_error::OAuthEndpointError;
use std::collections::HashMap;

use super::{
    AuthorizationRequestContext, AuthorizationResponseRedirect,
    authorization_response_redirect_with_context,
};

pub(crate) async fn authorization_oauth_error_redirect(
    context: &AuthorizationRequestContext<'_>,
    redirect_uri: &str,
    error: &str,
    q: &HashMap<String, String>,
) -> Result<AuthorizationOutcome, OAuthEndpointError> {
    authorization_response_redirect_with_context(
        context,
        AuthorizationResponseRedirect {
            redirect_uri,
            client_id: q.get("client_id").map(String::as_str).unwrap_or(""),
            response_mode: q.get("response_mode").map(String::as_str),
            code: None,
            error: Some(error),
            state: q.get("state").map(String::as_str),
            oidc_sid: None,
            client_policy: None,
        },
    )
    .await
}
