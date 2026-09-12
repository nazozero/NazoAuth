use super::{
    policy::{
        ciba_client_assertion_algorithm_supported,
        validate_ciba_security_profile_client_with_config,
    },
    state::{CibaTokenContext, ciba_grant_key},
};
use crate::{
    contracts::{
        oauth_error::OAuthEndpointError,
        request_facts::DpopErrorContext,
        token_endpoint::{TokenEndpointSuccess, TokenRequestFacts},
        token_forms::TokenForm,
    },
    domain::{
        oauth::{RefreshTokenPolicy, TokenIssue},
        rows::ClientRow,
    },
    services::{ServerCibaService, ServerTokenService},
    token::{
        SenderConstraintValidationError,
        client_auth::consume_token_client_assertion_with_authorization_service,
        issue::{TokenIssuanceConfig, TokenIssuanceContext, issue_token_response},
        sender_constraint_multiple_error, token_client_assertion_error,
        validate_token_sender_constraints,
    },
};
use chrono::Utc;
use http::StatusCode as ProtocolStatusCode;
use nazo_auth::{
    CibaAuthenticationContext, CibaPollCommit, CibaPollFailure, CibaRequestState,
    TokenIssuanceMode, ValidatedClientAssertion,
};
use serde_json::json;
use uuid::Uuid;

struct CibaPollIssueRequest<'a, 'issuance> {
    ciba_service: &'a ServerCibaService,
    users: &'a dyn nazo_persistence::CibaAccountStore,
    token_service: &'a ServerTokenService,
    issuance: &'a TokenIssuanceContext<'issuance>,
    client: &'a ClientRow,
    auth_req_id: &'a str,
    initial: nazo_auth::CibaStoredRequest<nazo_auth::CibaStateVersion>,
    ciba_grant_key: String,
    dpop_jkt: Option<String>,
    mtls_x5t_s256: Option<String>,
    client_assertion: Option<ValidatedClientAssertion>,
    tenant_id: uuid::Uuid,
}

pub async fn token_ciba(
    context: CibaTokenContext<'_, '_>,
    client: &ClientRow,
    form: &TokenForm,
    client_assertion: Option<&ValidatedClientAssertion>,
    auth_method: &str,
) -> Result<TokenEndpointSuccess, OAuthEndpointError> {
    let CibaTokenContext {
        token_service,
        issuance,
        handles,
        request: req,
    } = context;
    let config = handles.config.as_ref();
    let ciba_service = handles.service.as_ref();
    let users = handles.users.as_ref();
    if !issuance.permits(nazo_runtime_modules::ModuleId::Ciba) {
        return Err(OAuthEndpointError::token(
            ProtocolStatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "CIBA is not enabled.",
            false,
        ));
    }
    if !client.security_policy.allow_cross_device_flows {
        return Err(OAuthEndpointError::token(
            ProtocolStatusCode::BAD_REQUEST,
            "unauthorized_client",
            "This client is not authorized for cross-device flows.",
            false,
        ));
    }
    let Some(auth_req_id) = form.auth_req_id.as_deref() else {
        return Err(OAuthEndpointError::token(
            ProtocolStatusCode::BAD_REQUEST,
            "invalid_request",
            "CIBA token request requires auth_req_id.",
            false,
        ));
    };
    if !ciba_client_assertion_algorithm_supported(client_assertion) {
        return Err(OAuthEndpointError::token(
            ProtocolStatusCode::UNAUTHORIZED,
            "invalid_client",
            "CIBA private_key_jwt signing algorithm is unsupported.",
            false,
        ));
    }
    validate_ciba_security_profile_client_with_config(config, client, auth_method)?;
    let initial = match ciba_service.load(auth_req_id).await {
        Ok(value) => value,
        Err(error) => return Err(ciba_poll_failure_error(CibaPollFailure::Storage(error))),
    };
    if let Some(initial) = initial.as_ref()
        && let Some(response) = ciba_auth_req_id_client_error(initial.state(), client)
    {
        return Err(response);
    }
    let (dpop_jkt, mtls_x5t_s256) = match ciba_issue_binding(issuance, req, client).await {
        Ok(binding) => binding,
        Err(response) => return Err(response),
    };
    let ciba_grant_key = ciba_grant_key(auth_req_id, dpop_jkt.as_deref(), mtls_x5t_s256.as_deref());
    let Some(initial) = initial else {
        return Err(OAuthEndpointError::token(
            ProtocolStatusCode::BAD_REQUEST,
            "invalid_grant",
            "CIBA auth_req_id is expired.",
            false,
        ));
    };
    let client_assertion = client_assertion.cloned();
    poll_and_issue_ciba(CibaPollIssueRequest {
        ciba_service,
        users,
        token_service,
        issuance,
        client,
        auth_req_id,
        initial,
        ciba_grant_key,
        dpop_jkt,
        mtls_x5t_s256,
        client_assertion,
        tenant_id: config.tenant_id,
    })
    .await
}

async fn poll_and_issue_ciba(
    request: CibaPollIssueRequest<'_, '_>,
) -> Result<TokenEndpointSuccess, OAuthEndpointError> {
    let CibaPollIssueRequest {
        ciba_service,
        users,
        token_service,
        issuance,
        client,
        auth_req_id,
        initial,
        ciba_grant_key,
        dpop_jkt,
        mtls_x5t_s256,
        client_assertion,
        tenant_id,
    } = request;
    if let Err(error) = consume_token_client_assertion_with_authorization_service(
        issuance.authorization,
        client,
        client_assertion.as_ref(),
        issuance.security_audit,
    )
    .await
    {
        return Err(token_client_assertion_error(error));
    }
    let mut ciba = match ciba_service
        .poll(auth_req_id, &client.client_id, initial, || {
            Utc::now().timestamp()
        })
        .await
    {
        Ok(CibaPollCommit::AuthorizationPending) => {
            return Err(OAuthEndpointError::token(
                ProtocolStatusCode::BAD_REQUEST,
                "authorization_pending",
                "CIBA authorization is pending.",
                false,
            ));
        }
        Ok(CibaPollCommit::SlowDown) => {
            return Err(OAuthEndpointError::token(
                ProtocolStatusCode::BAD_REQUEST,
                "slow_down",
                "CIBA polling too fast.",
                false,
            ));
        }
        Ok(CibaPollCommit::Denied) => {
            return Err(OAuthEndpointError::token(
                ProtocolStatusCode::BAD_REQUEST,
                "access_denied",
                "CIBA authorization was denied.",
                false,
            ));
        }
        Ok(CibaPollCommit::Expired) => {
            return Err(OAuthEndpointError::token(
                ProtocolStatusCode::BAD_REQUEST,
                "expired_token",
                "CIBA auth_req_id is expired.",
                false,
            ));
        }
        Ok(CibaPollCommit::Approved(ciba)) => ciba,
        Err(failure) => return Err(ciba_poll_failure_error(failure)),
    };
    let Some(authentication_context) = ciba.authentication_context.take() else {
        tracing::error!("approved CIBA state is missing its authentication context");
        return Err(OAuthEndpointError::token(
            ProtocolStatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "CIBA failed.",
            false,
        ));
    };
    let user = match users
        .by_id(
            nazo_identity::TenantId::new(tenant_id).expect("configured CIBA tenant ID is non-nil"),
            nazo_identity::UserId::new(ciba.user_id).expect("persisted CIBA user ID is non-nil"),
        )
        .await
    {
        Ok(Some(user)) if user.principal.active => user,
        Ok(_) => {
            return Err(OAuthEndpointError::token(
                ProtocolStatusCode::BAD_REQUEST,
                "invalid_grant",
                "CIBA user is unavailable.",
                false,
            ));
        }
        Err(error) => {
            tracing::warn!(%error, "failed to load CIBA user");
            return Err(OAuthEndpointError::token(
                ProtocolStatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "CIBA failed.",
                false,
            ));
        }
    };
    let subject = match ciba_subject_for_client(issuance.config, ciba.user_id, client) {
        Ok(subject) => subject,
        Err(error) => {
            tracing::warn!(%error, "failed to compute CIBA subject");
            return Err(OAuthEndpointError::token(
                ProtocolStatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "CIBA failed.",
                false,
            ));
        }
    };
    let issue = ciba_token_issue(
        user.id(),
        subject,
        *ciba,
        authentication_context,
        dpop_jkt,
        mtls_x5t_s256,
    );
    issue_token_response(
        issuance,
        token_service,
        client,
        TokenIssuanceMode::SingleUse {
            grant_key: ciba_grant_key.clone(),
        },
        issue,
    )
    .await
}

fn ciba_auth_req_id_client_error(
    ciba: &CibaRequestState,
    client: &ClientRow,
) -> Option<OAuthEndpointError> {
    (ciba.client_id != client.client_id).then(|| {
        OAuthEndpointError::token(
            ProtocolStatusCode::BAD_REQUEST,
            "invalid_grant",
            "CIBA auth_req_id was not issued to this client.",
            false,
        )
    })
}

fn ciba_token_issue(
    user_id: Uuid,
    subject: String,
    ciba: CibaRequestState,
    authentication_context: CibaAuthenticationContext,
    dpop_jkt: Option<String>,
    mtls_x5t_s256: Option<String>,
) -> TokenIssue {
    TokenIssue {
        user_id: Some(user_id),
        subject,
        scopes: ciba.scopes,
        authorization_details: json!([]),
        audiences: ciba.audiences,
        nonce: None,
        auth_time: Some(authentication_context.auth_time),
        amr: authentication_context.amr,
        oidc_sid: authentication_context.oidc_sid,
        acr: ciba.acr,
        userinfo_claims: Vec::new(),
        userinfo_claim_requests: Vec::new(),
        id_token_claims: Vec::new(),
        id_token_claim_requests: Vec::new(),
        refresh_id_token_sid: None,
        include_refresh: true,
        refresh_token_policy: RefreshTokenPolicy::IssueNew,
        dpop_jkt: dpop_jkt.clone(),
        refresh_token_dpop_jkt: dpop_jkt,
        mtls_x5t_s256: mtls_x5t_s256.clone(),
        refresh_token_mtls_x5t_s256: mtls_x5t_s256,
        refresh_token_client_attestation_jkt: None,
        refresh_token_scopes: None,
        authorization_code_hash: None,
        actor: None,
        issued_token_type: None,
        native_sso: None,
    }
}

async fn ciba_issue_binding(
    issuance: &TokenIssuanceContext<'_>,
    req: &TokenRequestFacts<'_>,
    client: &ClientRow,
) -> Result<(Option<String>, Option<String>), OAuthEndpointError> {
    let sender = validate_token_sender_constraints(issuance, req, client, None, None, None)
        .await
        .map_err(|error| match error {
            SenderConstraintValidationError::Dpop(error) => OAuthEndpointError::Dpop {
                error,
                context: DpopErrorContext::TokenEndpoint,
            },
            SenderConstraintValidationError::MissingMtls => OAuthEndpointError::token(
                ProtocolStatusCode::BAD_REQUEST,
                "invalid_grant",
                "CIBA requires mTLS sender constraint.",
                false,
            ),
            SenderConstraintValidationError::Multiple => sender_constraint_multiple_error(),
        })?;
    Ok((sender.dpop_jkt, sender.mtls_x5t_s256))
}

fn ciba_subject_for_client(
    config: &TokenIssuanceConfig,
    user_id: Uuid,
    client: &ClientRow,
) -> anyhow::Result<String> {
    let redirect_uri = client.redirect_uris.first().map_or("", String::as_str);
    Ok(nazo_auth::oidc_subject_for_client(
        config.issuer(),
        config.pairwise_subject_secret(),
        user_id,
        &client.subject_type,
        client.sector_identifier_host.as_deref(),
        redirect_uri,
    )?)
}

fn ciba_poll_failure_error(failure: CibaPollFailure) -> OAuthEndpointError {
    match failure {
        CibaPollFailure::Missing => OAuthEndpointError::token(
            ProtocolStatusCode::BAD_REQUEST,
            "invalid_grant",
            "CIBA auth_req_id is expired or consumed.",
            false,
        ),
        CibaPollFailure::ClientMismatch => OAuthEndpointError::token(
            ProtocolStatusCode::BAD_REQUEST,
            "invalid_grant",
            "CIBA auth_req_id was not issued to this client.",
            false,
        ),
        CibaPollFailure::Storage(error) => {
            tracing::warn!(%error, "CIBA poll state operation failed");
            OAuthEndpointError::token(
                ProtocolStatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "CIBA state unavailable.",
                false,
            )
        }
        CibaPollFailure::Contended => OAuthEndpointError::token(
            ProtocolStatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "CIBA state is busy.",
            false,
        ),
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/token/ciba/poll.rs"]
mod tests;
