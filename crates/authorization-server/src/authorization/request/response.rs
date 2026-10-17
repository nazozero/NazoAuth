use super::AuthorizationOutcome;
use crate::authorization::presentation::append_query;
use crate::contracts::oauth_error::OAuthEndpointError;
use crate::crypto::random_urlsafe_token;
use crate::domain::client_jwe::{JwePayloadKind, client_jwe_key, encrypt_compact_jwe};
use crate::domain::client_policy::refresh_client_jwks_for_encryption;
use crate::domain::rows::ClientRow;
use http::StatusCode;
use nazo_auth::{
    AuthorizationResponsePlan, AuthorizationResponsePolicyError, AuthorizationResponsePolicyInput,
    issue_oidc_session_state, plan_authorization_response,
};

use super::AuthorizationRequestContext;

pub(crate) struct AuthorizationResponseRedirect<'a> {
    pub(crate) redirect_uri: &'a str,
    pub(crate) response_mode: Option<&'a str>,
    pub(crate) code: Option<&'a str>,
    pub(crate) error: Option<&'a str>,
    pub(crate) state: Option<&'a str>,
    pub(crate) oidc_sid: Option<&'a str>,
}

pub(crate) async fn authorization_response_redirect_with_context(
    context: &AuthorizationRequestContext<'_>,
    client: &mut ClientRow,
    input: AuthorizationResponseRedirect<'_>,
) -> Result<AuthorizationOutcome, OAuthEndpointError> {
    let client_policy = &client.security_policy;
    let ttl_seconds = if context.config.requires_fapi2_security(client_policy) {
        context.config.auth_code_ttl_seconds.min(60)
    } else {
        context.config.auth_code_ttl_seconds
    };
    let jarm_available = crate::authorization::permits_existing_module_transaction(
        context,
        nazo_runtime_modules::ModuleId::Jarm,
    );
    let session_management_available = client_policy.session_management
        && crate::authorization::accepts_module(
            context,
            nazo_runtime_modules::ModuleId::SessionManagement,
        );
    let plan = match plan_authorization_response(AuthorizationResponsePolicyInput {
        issuer: context.config.issuer.as_ref(),
        redirect_uri: input.redirect_uri,
        client_id: &client.client_id,
        response_mode: input.response_mode,
        code: input.code,
        error: input.error,
        state: input.state,
        ttl_seconds: ttl_seconds as i64,
        signed_response_required: context
            .config
            .requires_signed_authorization_response(client_policy),
        jarm_available,
        session_management_available,
    }) {
        Ok(plan) => plan,
        Err(AuthorizationResponsePolicyError::UnsupportedResponseMode) => {
            return Err(OAuthEndpointError::json(
                StatusCode::BAD_REQUEST,
                "unsupported_response_mode",
                "JWT-secured authorization responses are disabled.",
            ));
        }
        Err(AuthorizationResponsePolicyError::MissingClientId) => {
            tracing::warn!("cannot build signed authorization response without client_id");
            return Err(OAuthEndpointError::json(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "authorization response signing failed.",
            ));
        }
        Err(AuthorizationResponsePolicyError::Dependency(error)) => {
            tracing::warn!(?error, "authorization response policy dependency failed");
            return Err(OAuthEndpointError::json(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "authorization response protection failed.",
            ));
        }
    };
    if let AuthorizationResponsePlan::Jarm(jarm) = plan {
        let response_encryption_configured = client.authorization_encrypted_response_alg.is_some()
            || client.authorization_encrypted_response_enc.is_some();
        if let Err(error) = refresh_client_jwks_for_encryption(
            client,
            context.remote_client_documents,
            response_encryption_configured,
        )
        .await
        {
            tracing::warn!(%error, "JARM encryption jwks_uri could not be refreshed");
            return Err(OAuthEndpointError::json(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "authorization response protection failed.",
            ));
        }
        let result = protected_authorization_response_jwt(context, &jarm, client).await;
        return authorization_response_jwt_result(&jarm.redirect_uri, result);
    }
    let (plain, form_post) = match plan {
        AuthorizationResponsePlan::Plain(plain) => (plain, false),
        AuthorizationResponsePlan::FormPost(plain) => (plain, true),
        AuthorizationResponsePlan::Jarm(_) => unreachable!("JARM response returned above"),
    };
    let session_state = if plain.issue_session_state {
        input
            .oidc_sid
            .and_then(|sid| issue_oidc_session_state(&client.client_id, input.redirect_uri, sid))
    } else {
        None
    };
    if form_post {
        return Ok(AuthorizationOutcome::FormPost {
            action: plain.redirect_uri,
            parameters: plain.parameters,
            session_state,
            csp_nonce: random_urlsafe_token(),
        });
    }
    Ok(AuthorizationOutcome::Redirect {
        location: nazo_auth::plain_authorization_response_uri(&plain, session_state.as_deref()),
    })
}

async fn protected_authorization_response_jwt(
    context: &AuthorizationRequestContext<'_>,
    input: &nazo_auth::JarmAuthorizationResponse,
    client: &ClientRow,
) -> anyhow::Result<String> {
    let signed = context
        .service
        .sign_authorization_response(nazo_auth::AuthorizationResponseSignInput {
            issuer: &input.issuer,
            client_id: &input.client_id,
            code: input.code.as_deref(),
            error: input.error.as_deref(),
            state: input.state.as_deref(),
            ttl: input.ttl_seconds,
            signing_algorithm: client.authorization_signed_response_alg.as_deref(),
        })
        .await
        .map_err(|error| anyhow::anyhow!("authorization response signing failed: {error:?}"))?;
    match client_jwe_key(
        client.jwks.as_deref(),
        client.authorization_encrypted_response_alg.as_deref(),
        client.authorization_encrypted_response_enc.as_deref(),
        "authorization response",
    )? {
        Some(key) => Ok(encrypt_compact_jwe(
            &key,
            signed.into_bytes(),
            JwePayloadKind::NestedJwt,
        )?),
        None => Ok(signed),
    }
}

pub(super) fn authorization_response_jwt_result(
    redirect_uri: &str,
    result: anyhow::Result<String>,
) -> Result<AuthorizationOutcome, OAuthEndpointError> {
    match result {
        Ok(response) => authorization_response_jwt_redirect(redirect_uri, &response),
        Err(error) => {
            tracing::warn!(%error, "failed to protect JARM authorization response");
            Err(OAuthEndpointError::json(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "authorization response signing failed.",
            ))
        }
    }
}

pub(super) fn authorization_response_jwt_redirect(
    redirect_uri: &str,
    response: &str,
) -> Result<AuthorizationOutcome, OAuthEndpointError> {
    Ok(AuthorizationOutcome::Redirect {
        location: append_query(redirect_uri, &[("response", response)]),
    })
}

#[cfg(test)]
#[path = "../../../tests/unit/authorization/request/response.rs"]
mod tests;
