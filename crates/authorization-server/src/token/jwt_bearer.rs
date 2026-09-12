//! RFC 7523 JWT bearer authorization grant.
use crate::contracts::{
    oauth_error::OAuthEndpointError, token_endpoint::TokenEndpointSuccess,
    token_endpoint::TokenRequestFacts,
};

use crate::contracts::token_forms::TokenForm;
use crate::crypto::blake3_hex;
use crate::crypto::client_jwt_decoding_key;
use crate::services::ServerTokenService;
use crate::token::SenderConstraintValidationError;
use crate::token::client_auth::consume_token_client_assertion_with_authorization_service;
use crate::token::issue::{TokenIssuanceContext, issue_token_response};
use crate::token::sender_constraint_multiple_error;
use crate::token::validate_token_sender_constraints;
use nazo_auth::ValidatedClientAssertion;

use crate::contracts::request_facts::DpopErrorContext;
use crate::domain::client_policy::refresh_client_jwks;
use crate::domain::oauth::{RefreshTokenPolicy, TokenIssue};
use crate::domain::rows::ClientRow;

use http::StatusCode;

use chrono::Utc;
use nazo_auth::{
    JwtBearerAssertionClaims, JwtBearerGrantError, JwtBearerGrantPolicy, TokenIssuanceMode,
    ValidatedJwtBearerAssertion, admit_jwt_bearer_grant, is_subset, parse_scope,
    validate_jwt_bearer_assertion_claims, validate_jwt_bearer_grant_prerequisites,
};
use serde_json::json;

pub(crate) const JWT_BEARER_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
pub(crate) const JWT_BEARER_ASSERTION_TYP: &str = "oauth-jwt-bearer+jwt";

pub fn jwt_bearer_grant_key(
    assertion_jti: &str,
    dpop_jkt: Option<&str>,
    mtls_x5t_s256: Option<&str>,
) -> String {
    format!(
        "jwt_bearer:{}:{}:{}",
        blake3_hex(assertion_jti),
        dpop_jkt.map(blake3_hex).unwrap_or_default(),
        mtls_x5t_s256.map(blake3_hex).unwrap_or_default(),
    )
}

#[derive(Debug)]
pub enum JwtBearerAssertionError {
    Invalid,
    ReplayDetected,
    StoreUnavailable,
}

fn jwt_bearer_policy<'a>(
    issuance: &'a TokenIssuanceContext<'_>,
    client: &'a ClientRow,
    now: i64,
) -> JwtBearerGrantPolicy<'a> {
    JwtBearerGrantPolicy {
        enabled: issuance.accepts(nazo_runtime_modules::ModuleId::JwtBearerGrant),
        issuer: issuance.config.issuer(),
        client_id: &client.client_id,
        client_is_confidential: client.client_type == "confidential",
        allowed_scopes: &client.scopes,
        allowed_audiences: &client.allowed_audiences,
        default_audience: issuance.config.default_audience(),
        now,
    }
}

pub fn validate_jwt_bearer_assertion_with_issuer(
    issuer: &str,
    client: &ClientRow,
    assertion: &str,
) -> Result<ValidatedJwtBearerAssertion, JwtBearerAssertionError> {
    let header =
        jsonwebtoken::decode_header(assertion).map_err(|_| JwtBearerAssertionError::Invalid)?;
    if header.typ.as_deref() != Some(JWT_BEARER_ASSERTION_TYP) {
        return Err(JwtBearerAssertionError::Invalid);
    }
    let kid = header.kid.ok_or(JwtBearerAssertionError::Invalid)?;
    let decoding_key = client_jwt_decoding_key(client, &kid, header.alg)
        .ok_or(JwtBearerAssertionError::Invalid)?;
    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.validate_aud = false;
    validation.set_issuer(&[client.client_id.as_str()]);
    let token_data =
        jsonwebtoken::decode::<JwtBearerAssertionClaims>(assertion, &decoding_key, &validation)
            .map_err(|_| JwtBearerAssertionError::Invalid)?;
    let now = Utc::now().timestamp();
    validate_jwt_bearer_assertion_claims(
        token_data.claims,
        JwtBearerGrantPolicy {
            enabled: true,
            issuer,
            client_id: &client.client_id,
            client_is_confidential: true,
            allowed_scopes: &[],
            allowed_audiences: &[],
            default_audience: "",
            now,
        },
    )
    .map_err(|_| JwtBearerAssertionError::Invalid)
}

pub async fn consume_jwt_bearer_assertion_with_authorization_service(
    authorization_service: &crate::services::ServerAuthorizationService,
    client: &ClientRow,
    assertion: &ValidatedJwtBearerAssertion,
) -> Result<(), JwtBearerAssertionError> {
    match authorization_service
        .consume_jwt_bearer(
            &client.client_id,
            &assertion.jti,
            assertion.replay_ttl_seconds,
        )
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(JwtBearerAssertionError::ReplayDetected),
        Err(error) => {
            tracing::warn!(%error, "failed to store JWT bearer grant jti");
            Err(JwtBearerAssertionError::StoreUnavailable)
        }
    }
}

fn jwt_bearer_grant_error_response(
    error: JwtBearerGrantError,
    client: &ClientRow,
    form: &TokenForm,
) -> OAuthEndpointError {
    match error {
        JwtBearerGrantError::Disabled => OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "JWT bearer grant is disabled.",
            false,
        ),
        JwtBearerGrantError::UnauthorizedClient => OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "JWT bearer grant requires a confidential client.",
            false,
        ),
        JwtBearerGrantError::MissingAssertion => OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "JWT bearer grant requires an assertion.",
            false,
        ),
        JwtBearerGrantError::InvalidScope => {
            let requested = parse_scope(form.scope.as_deref().unwrap_or(""));
            let description = if !requested.is_empty() && !is_subset(&requested, &client.scopes) {
                "请求的作用域超出客户端允许范围."
            } else {
                "client_credentials 不支持 openid scope."
            };
            OAuthEndpointError::token(StatusCode::BAD_REQUEST, "invalid_scope", description, false)
        }
        JwtBearerGrantError::InvalidTarget => OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "请求的 audience 不在客户端允许范围内.",
            false,
        ),
        JwtBearerGrantError::InvalidAssertion | JwtBearerGrantError::ReplayDetected => {
            OAuthEndpointError::token(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "JWT bearer assertion is invalid.",
                false,
            )
        }
        JwtBearerGrantError::Dependency(error) => {
            tracing::warn!(%error, "JWT bearer assertion state is unavailable");
            OAuthEndpointError::token(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "JWT bearer assertion replay state is unavailable.",
                false,
            )
        }
    }
}

pub async fn token_jwt_bearer_with_service(
    token_service: &ServerTokenService,
    issuance: &TokenIssuanceContext<'_>,
    facts: &TokenRequestFacts<'_>,
    client: &mut ClientRow,
    form: &TokenForm,
    client_assertion: Option<&ValidatedClientAssertion>,
) -> Result<TokenEndpointSuccess, OAuthEndpointError> {
    let policy = jwt_bearer_policy(issuance, client, Utc::now().timestamp());
    if let Err(error) = validate_jwt_bearer_grant_prerequisites(form.assertion.as_deref(), policy) {
        return Err(jwt_bearer_grant_error_response(error, client, form));
    }
    let assertion = form
        .assertion
        .as_deref()
        .expect("validated JWT bearer grant must contain assertion");
    if let Ok(header) = jsonwebtoken::decode_header(assertion)
        && header.kid.is_some()
        && let Err(error) = refresh_client_jwks(
            client,
            issuance.remote_client_documents,
            header.kid.as_deref(),
        )
        .await
    {
        tracing::warn!(%error, "JWT bearer assertion jwks_uri could not be refreshed");
        return Err(OAuthEndpointError::token(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "JWT bearer assertion key source is unavailable.",
            false,
        ));
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
                    "JWT bearer grant requires mTLS sender constraint.",
                    false,
                ));
            }
            Err(SenderConstraintValidationError::Multiple) => {
                return Err(sender_constraint_multiple_error());
            }
        };
    let policy = jwt_bearer_policy(issuance, client, Utc::now().timestamp());
    let assertion = match validate_jwt_bearer_assertion_with_issuer(
        issuance.config.issuer(),
        client,
        assertion,
    ) {
        Ok(assertion) => assertion,
        Err(_) => {
            return Err(OAuthEndpointError::token(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "JWT bearer assertion is invalid.",
                false,
            ));
        }
    };
    let jwt_bearer_grant_key = jwt_bearer_grant_key(
        &assertion.jti,
        sender.dpop_jkt.as_deref(),
        sender.mtls_x5t_s256.as_deref(),
    );
    if let Err(error) = consume_token_client_assertion_with_authorization_service(
        issuance.authorization,
        client,
        client_assertion,
        issuance.security_audit,
    )
    .await
    {
        return Err(crate::token::token_client_assertion_error(error));
    }
    if let Err(error) = consume_jwt_bearer_assertion_with_authorization_service(
        issuance.authorization,
        client,
        &assertion,
    )
    .await
    {
        return match error {
            JwtBearerAssertionError::StoreUnavailable => Err(OAuthEndpointError::token(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "JWT bearer assertion replay state is unavailable.",
                false,
            )),
            JwtBearerAssertionError::Invalid | JwtBearerAssertionError::ReplayDetected => {
                Err(OAuthEndpointError::token(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "JWT bearer assertion is invalid.",
                    false,
                ))
            }
        };
    }
    let admission = match admit_jwt_bearer_grant(
        form.assertion.as_deref(),
        form.scope.as_deref(),
        &form.audiences,
        policy,
    ) {
        Ok(admission) => admission,
        Err(error) => return Err(jwt_bearer_grant_error_response(error, client, form)),
    };
    issue_token_response(
        issuance,
        token_service,
        client,
        TokenIssuanceMode::SingleUse {
            grant_key: jwt_bearer_grant_key.clone(),
        },
        TokenIssue {
            user_id: None,
            subject: assertion.subject,
            scopes: admission.scopes,
            authorization_details: json!([]),
            audiences: admission.audiences,
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
