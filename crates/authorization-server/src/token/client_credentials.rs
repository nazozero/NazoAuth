//! client_credentials grant 处理。
use crate::contracts::{
    oauth_error::OAuthEndpointError, token_endpoint::TokenEndpointSuccess,
    token_endpoint::TokenRequestFacts,
};
use crate::domain::client_policy::audiences_allowed;
use crate::domain::client_policy::is_subset;
use crate::domain::client_policy::parse_scope;
use nazo_auth::ValidatedClientAssertion;

use crate::contracts::request_facts::DpopErrorContext;
use crate::domain::oauth::{RefreshTokenPolicy, TokenIssue};
use crate::domain::rows::ClientRow;
use nazo_auth::TokenIssuanceMode;

use http::StatusCode;

use serde_json::json;

// 只为机密客户端签发无用户主体的访问令牌。
use crate::contracts::token_forms::TokenForm;
use crate::services::ServerTokenService;
use crate::token::SenderConstraintValidationError;
use crate::token::client_auth::consume_token_client_assertion_with_authorization_service;
use crate::token::issue::{TokenIssuanceContext, issue_token_response};
use crate::token::sender_constraint_multiple_error;
use crate::token::validate_token_sender_constraints;

#[derive(Debug)]
pub struct ClientCredentialsIssue {
    pub scopes: Vec<String>,
    pub audiences: Vec<String>,
}

pub fn reject_non_confidential_client_credentials_client(
    client: &ClientRow,
) -> Option<OAuthEndpointError> {
    if client.client_type == "confidential" {
        return None;
    }
    Some(OAuthEndpointError::token(
        StatusCode::BAD_REQUEST,
        "unauthorized_client",
        "client_credentials 只允许机密客户端使用.",
        false,
    ))
}

pub fn client_credentials_issue_request_with_default_audience(
    default_audience: &str,
    client: &ClientRow,
    form: &TokenForm,
) -> Result<ClientCredentialsIssue, OAuthEndpointError> {
    let requested = parse_scope(form.scope.as_deref().unwrap_or(""));
    if !requested.is_empty() && !is_subset(&requested, &client.scopes) {
        return Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "请求的作用域超出客户端允许范围.",
            false,
        ));
    }
    let scopes = if requested.is_empty() {
        client.scopes.clone()
    } else {
        requested
    };
    if scopes.iter().any(|scope| scope == "openid") {
        return Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "client_credentials 不支持 openid scope.",
            false,
        ));
    }
    let audiences = if form.audiences.is_empty() {
        vec![default_audience.to_owned()]
    } else {
        form.audiences.clone()
    };
    if !audiences_allowed(client, &audiences) {
        return Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "请求的 audience 不在客户端允许范围内.",
            false,
        ));
    }
    Ok(ClientCredentialsIssue { scopes, audiences })
}

pub fn client_credentials_issuance_mode(facts: &TokenRequestFacts<'_>) -> TokenIssuanceMode {
    facts
        .idempotency_key
        .clone()
        .map_or(TokenIssuanceMode::Fresh, |grant_key| {
            TokenIssuanceMode::Idempotent { grant_key }
        })
}

pub async fn token_client_credentials_with_service(
    token_service: &ServerTokenService,
    authorization_service: &crate::services::ServerAuthorizationService,
    issuance: &TokenIssuanceContext<'_>,
    facts: &TokenRequestFacts<'_>,
    client: &ClientRow,
    form: &TokenForm,
    client_assertion: Option<&ValidatedClientAssertion>,
) -> Result<TokenEndpointSuccess, OAuthEndpointError> {
    if let Some(response) = reject_non_confidential_client_credentials_client(client) {
        return Err(response);
    }
    let sender =
        match validate_token_sender_constraints(issuance, facts, client, None, None, None).await {
            Ok(value) => value,
            Err(SenderConstraintValidationError::Dpop(error)) => {
                return Err(OAuthEndpointError::Dpop {
                    error,
                    context: DpopErrorContext::TokenEndpoint,
                });
            }
            Err(SenderConstraintValidationError::MissingMtls) => {
                return Err(OAuthEndpointError::token(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "client_credentials requires mTLS sender constraint.",
                    false,
                ));
            }
            Err(SenderConstraintValidationError::Multiple) => {
                return Err(sender_constraint_multiple_error());
            }
        };
    if let Err(error) = consume_token_client_assertion_with_authorization_service(
        authorization_service,
        client,
        client_assertion,
        issuance.security_audit,
    )
    .await
    {
        return Err(crate::token::token_client_assertion_error(error));
    }
    let issue_request = match client_credentials_issue_request_with_default_audience(
        issuance.config.default_audience(),
        client,
        form,
    ) {
        Ok(issue_request) => issue_request,
        Err(response) => return Err(response),
    };
    let mode = client_credentials_issuance_mode(facts);
    issue_token_response(
        issuance,
        token_service,
        client,
        mode,
        TokenIssue {
            user_id: None,
            subject: client.client_id.clone(),
            scopes: issue_request.scopes,
            authorization_details: json!([]),
            audiences: issue_request.audiences,
            nonce: None,
            auth_time: None,
            amr: Vec::new(),
            oidc_sid: None,
            acr: None,
            userinfo_claims: Vec::new(),
            userinfo_claim_requests: Vec::new(),
            id_token_claims: Vec::new(),
            id_token_claim_requests: Vec::new(),
            refresh_id_token_sid: None,
            include_refresh: false,
            refresh_token_policy: RefreshTokenPolicy::PreserveExisting,
            dpop_jkt: sender.dpop_jkt,
            refresh_token_dpop_jkt: None,
            mtls_x5t_s256: sender.mtls_x5t_s256,
            refresh_token_mtls_x5t_s256: None,
            refresh_token_client_attestation_jkt: None,
            refresh_token_scopes: None,
            authorization_code_hash: None,
            actor: None,
            issued_token_type: None,
            native_sso: None,
        },
    )
    .await
}
