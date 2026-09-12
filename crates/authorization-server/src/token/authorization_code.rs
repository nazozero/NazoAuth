//! authorization_code grant 处理。
use crate::contracts::{
    oauth_error::OAuthEndpointError, token_endpoint::TokenEndpointSuccess,
    token_endpoint::TokenRequestFacts,
};
use crate::crypto::blake3_hex;
use crate::crypto::constant_time_eq;
use crate::crypto::pkce_s256;
use crate::domain::client_policy::audiences_allowed;
use nazo_auth::ValidatedClientAssertion;

use crate::domain::client_policy::is_subset;
use crate::domain::client_policy::is_valid_pkce_value;

use crate::contracts::request_facts::DpopErrorContext;
use crate::domain::oauth::{
    AuthorizationCodeState, CodePayload, ConsumedAuthorizationCode, RefreshTokenPolicy, TokenIssue,
};
use crate::domain::rows::ClientRow;
use nazo_auth::DpopError;

use http::StatusCode;

use chrono::Utc;
use nazo_auth::TokenIssuanceMode;

use serde_json::json;

// 只消费授权码并转入统一令牌签发逻辑。
use crate::contracts::token_forms::TokenForm;
use crate::services::ServerTokenService;
use crate::token::SenderConstraintValidationError;
use crate::token::client_auth::consume_token_client_assertion_with_authorization_service;
use crate::token::issue::TokenIssuanceConfig;
use crate::token::issue::TokenIssuanceContext;
use crate::token::issue::issue_token_response;
use crate::token::issue::revoke_issued_authorization_code_tokens;
use crate::token::native_sso::native_sso_requested;
use crate::token::native_sso::new_native_sso_token_binding;
use crate::token::sender_constraint_multiple_error;
use crate::token::validate_token_sender_constraints;

pub enum AuthorizationCodeConsumption {
    Consuming(Box<CodePayload>),
    Busy,
    Consumed(ConsumedAuthorizationCode),
    Failed,
    Missing,
    Malformed,
}

pub async fn load_pending_authorization_code_payload_with_service(
    service: &ServerTokenService,
    code_hash: &str,
) -> Result<Option<Box<CodePayload>>, OAuthEndpointError> {
    let stored = match service.load_authorization_code(code_hash).await {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(
                ?error,
                "failed to read authorization code before dpop validation"
            );
            return Err(OAuthEndpointError::token(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权码校验失败.",
                false,
            ));
        }
    };
    let Some(stored) = stored else {
        return Ok(None);
    };
    match stored {
        AuthorizationCodeState::Pending { payload } => Ok(Some(Box::new(payload))),
        _ => Ok(None),
    }
}

pub fn redirect_uri_matches_authorization_request(
    payload: &CodePayload,
    token_redirect_uri: Option<&str>,
) -> bool {
    match (payload.redirect_uri_was_supplied, token_redirect_uri) {
        (true, Some(value)) => value == payload.redirect_uri.as_str(),
        (true, None) => false,
        (false, Some(value)) => value == payload.redirect_uri.as_str(),
        (false, None) => true,
    }
}

fn authorization_code_requires_pkce(client: &ClientRow, payload: &CodePayload) -> bool {
    client.client_type != "confidential"
        || client.require_dpop_bound_tokens
        || client.require_mtls_bound_tokens
        || payload.dpop_jkt.is_some()
        || payload.mtls_x5t_s256.is_some()
        || !payload.scopes.iter().any(|scope| scope == "openid")
}

pub fn authorization_code_dpop_error_response(error: DpopError) -> OAuthEndpointError {
    match error {
        DpopError::UseNonce(_) | DpopError::NonceStoreUnavailable => OAuthEndpointError::Dpop {
            error,
            context: DpopErrorContext::TokenEndpoint,
        },
        _ => OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "authorization code proof of possession validation failed.",
            false,
        ),
    }
}

pub fn authorization_code_mtls_holder_error_response() -> OAuthEndpointError {
    OAuthEndpointError::token(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "authorization code mTLS binding validation failed.",
        false,
    )
}

pub fn authorization_code_client_mismatch_response() -> OAuthEndpointError {
    OAuthEndpointError::token(
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        "授权码与客户端或 redirect_uri 不匹配.",
        false,
    )
}

/// Bind the one-time authorization-code redemption to the request proofs that
/// produced its tokens. The binding is retained only to decide whether a
/// later replay may revoke those tokens; a replay never recovers a response.
pub fn authorization_code_grant_key(
    code_hash: &str,
    form: &TokenForm,
    dpop_jkt: Option<&str>,
    mtls_x5t_s256: Option<&str>,
    client_attestation_jkt: Option<&str>,
) -> String {
    let proof = json!({
        "code_hash": code_hash,
        "code_verifier": form.code_verifier.as_deref().map(blake3_hex),
        "redirect_uri": form.redirect_uri.as_deref().map(blake3_hex),
        "scope": form.scope.as_deref().map(blake3_hex),
        "audiences": &form.audiences,
        "dpop_jkt": dpop_jkt,
        "mtls_x5t_s256": mtls_x5t_s256,
        "client_attestation_jkt": client_attestation_jkt,
    });
    format!("authorization_code:{}", blake3_hex(&proof.to_string()))
}

fn replay_matches_original_redemption(
    marker: &ConsumedAuthorizationCode,
    client_id: uuid::Uuid,
    redemption_binding: &str,
) -> bool {
    marker.client_id == client_id
        && marker
            .redemption_binding
            .as_deref()
            .is_some_and(|expected| {
                constant_time_eq(expected.as_bytes(), redemption_binding.as_bytes())
            })
}

pub struct AuthorizationCodeIssueInput {
    pub payload: CodePayload,
    pub subject: String,
    pub audiences: Vec<String>,
    pub dpop_jkt: Option<String>,
    pub mtls_x5t_s256: Option<String>,
    pub code_hash: String,
    pub refresh_token_dpop_jkt: Option<String>,
    pub refresh_token_mtls_x5t_s256: Option<String>,
    pub refresh_token_client_attestation_jkt: Option<String>,
}

pub fn token_issue_from_authorization_code(input: AuthorizationCodeIssueInput) -> TokenIssue {
    let native_sso = native_sso_requested(&input.payload.scopes)
        .then(|| new_native_sso_token_binding(input.payload.oidc_sid.as_deref()))
        .flatten();
    TokenIssue {
        user_id: Some(input.payload.user_id),
        subject: input.subject,
        scopes: input.payload.scopes,
        authorization_details: input.payload.authorization_details,
        audiences: input.audiences,
        nonce: input.payload.nonce,
        auth_time: Some(input.payload.auth_time),
        amr: input.payload.amr,
        oidc_sid: input.payload.oidc_sid,
        acr: input.payload.acr,
        userinfo_claims: input.payload.userinfo_claims,
        userinfo_claim_requests: input.payload.userinfo_claim_requests,
        id_token_claims: input.payload.id_token_claims,
        id_token_claim_requests: input.payload.id_token_claim_requests,
        refresh_id_token_sid: None,
        include_refresh: true,
        refresh_token_policy: RefreshTokenPolicy::IssueNew,
        dpop_jkt: input.dpop_jkt,
        refresh_token_dpop_jkt: input.refresh_token_dpop_jkt,
        mtls_x5t_s256: input.mtls_x5t_s256,
        refresh_token_mtls_x5t_s256: input.refresh_token_mtls_x5t_s256,
        refresh_token_client_attestation_jkt: input.refresh_token_client_attestation_jkt,
        refresh_token_scopes: None,
        authorization_code_hash: Some(input.code_hash),
        actor: None,
        issued_token_type: None,
        native_sso,
    }
}

fn authorization_code_audiences_with_default(
    default_audience: &str,
    openid4vci_audience: Option<&str>,
    payload: &CodePayload,
    form: &TokenForm,
) -> Result<Vec<String>, ()> {
    if payload.resource_indicators.is_empty() {
        return Ok(if form.audiences.is_empty() {
            vec![openid4vci_audience.unwrap_or(default_audience).to_owned()]
        } else {
            form.audiences.clone()
        });
    }
    if form.audiences.is_empty() {
        return Ok(payload.resource_indicators.clone());
    }
    is_subset(&form.audiences, &payload.resource_indicators)
        .then(|| form.audiences.clone())
        .ok_or(())
}

pub fn refresh_token_dpop_binding(
    client: &ClientRow,
    payload: &CodePayload,
    dpop_jkt: Option<String>,
) -> Option<String> {
    if client.client_type == "public" || payload.dpop_jkt.is_some() {
        dpop_jkt
    } else {
        None
    }
}

pub async fn begin_authorization_code_consumption_with_service(
    service: &ServerTokenService,
    code_hash: &str,
) -> Result<AuthorizationCodeConsumption, OAuthEndpointError> {
    match service
        .begin_authorization_code(code_hash, Utc::now())
        .await
    {
        Ok(nazo_auth::AuthorizationCodeBeginResult::Consuming(payload)) => {
            Ok(AuthorizationCodeConsumption::Consuming(Box::new(payload)))
        }
        Ok(nazo_auth::AuthorizationCodeBeginResult::Busy) => Ok(AuthorizationCodeConsumption::Busy),
        Ok(nazo_auth::AuthorizationCodeBeginResult::Consumed(
            AuthorizationCodeState::Consumed { marker },
        )) => Ok(AuthorizationCodeConsumption::Consumed(marker)),
        Ok(
            nazo_auth::AuthorizationCodeBeginResult::Consumed(_)
            | nazo_auth::AuthorizationCodeBeginResult::Malformed,
        ) => Ok(AuthorizationCodeConsumption::Malformed),
        Ok(nazo_auth::AuthorizationCodeBeginResult::Failed) => {
            Ok(AuthorizationCodeConsumption::Failed)
        }
        Ok(nazo_auth::AuthorizationCodeBeginResult::Missing) => {
            Ok(AuthorizationCodeConsumption::Missing)
        }
        Err(error) => {
            tracing::warn!(?error, "failed to atomically consume authorization code");
            Err(OAuthEndpointError::token(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权码校验失败.",
                false,
            ))
        }
    }
}

async fn revoke_replayed_authorization_code(
    service: &ServerTokenService,
    client: &ClientRow,
    marker: ConsumedAuthorizationCode,
) -> Result<bool, OAuthEndpointError> {
    if let Err(error) = revoke_issued_authorization_code_tokens(
        service,
        client,
        &marker.access_token_jti,
        marker.access_token_expires_at,
        marker.refresh_token_family_id,
    )
    .await
    {
        tracing::warn!(%error, "failed to revoke tokens after authorization code replay");
        return Err(OAuthEndpointError::token(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "授权码重放撤销失败.",
            false,
        ));
    }
    Ok(true)
}

pub async fn token_authorization_code_with_service(
    token_service: &ServerTokenService,
    issuance: &TokenIssuanceContext<'_>,
    facts: &TokenRequestFacts<'_>,
    client: &ClientRow,
    form: &TokenForm,
    client_assertion: Option<&ValidatedClientAssertion>,
    client_attestation_jkt: Option<&str>,
) -> Result<TokenEndpointSuccess, OAuthEndpointError> {
    let Some(code) = &form.code else {
        return Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "缺少 code.",
            false,
        ));
    };
    let code_hash = blake3_hex(code);
    let expected_payload =
        match load_pending_authorization_code_payload_with_service(token_service, &code_hash).await
        {
            Ok(value) => value,
            Err(response) => return Err(response),
        };
    if expected_payload
        .as_ref()
        .is_some_and(|payload| payload.client_id != client.client_id)
    {
        return Err(authorization_code_client_mismatch_response());
    }
    // Pure parameter validation runs before any sender proof, client
    // assertion, or state transition so that an erroneous redemption never
    // consumes a Pending authorization code.
    let pending_audiences = match expected_payload.as_deref() {
        Some(payload) => {
            match validate_pending_authorization_code_request(issuance, client, form, payload) {
                Ok(audiences) => Some(audiences),
                Err(response) => return Err(response),
            }
        }
        None => None,
    };
    let expected_dpop_jkt = expected_payload
        .as_ref()
        .and_then(|payload| payload.dpop_jkt.clone());
    let expected_mtls_x5t_s256 = expected_payload
        .as_ref()
        .and_then(|payload| payload.mtls_x5t_s256.clone());
    let sender = match validate_token_sender_constraints(
        issuance,
        facts,
        client,
        None,
        expected_dpop_jkt.as_deref(),
        expected_mtls_x5t_s256.as_deref(),
    )
    .await
    {
        Ok(value) => value,
        Err(SenderConstraintValidationError::Dpop(error)) => {
            return Err(authorization_code_dpop_error_response(error));
        }
        Err(SenderConstraintValidationError::MissingMtls) => {
            return Err(authorization_code_mtls_holder_error_response());
        }
        Err(SenderConstraintValidationError::Multiple) => {
            return Err(sender_constraint_multiple_error());
        }
    };
    let dpop_jkt = sender.dpop_jkt;
    let mtls_x5t_s256 = sender.mtls_x5t_s256;
    let authorization_code_grant_key = authorization_code_grant_key(
        &code_hash,
        form,
        dpop_jkt.as_deref(),
        mtls_x5t_s256.as_deref(),
        client_attestation_jkt,
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
    // A code that expired while the sender proof was being validated must
    // not be consumed at all: no begin, no Failed transition.
    if expected_payload
        .as_ref()
        .is_some_and(|payload| payload.expires_at <= Utc::now())
    {
        return Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "授权码无效或已过期.",
            false,
        ));
    }
    let payload =
        match begin_authorization_code_consumption_with_service(token_service, &code_hash).await {
            Ok(AuthorizationCodeConsumption::Consuming(payload)) => payload,
            Ok(AuthorizationCodeConsumption::Consumed(marker)) => {
                // Authorization codes are single-use even when the original
                // HTTP response may have been lost. Only an exact replay by
                // the same client and proof set can trigger revocation; all
                // other attempts are rejected without becoming a revocation
                // oracle for another client's tokens.
                if !replay_matches_original_redemption(
                    &marker,
                    client.id,
                    &authorization_code_grant_key,
                ) {
                    return Err(OAuthEndpointError::token(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "授权码已被使用.",
                        false,
                    ));
                }
                match revoke_replayed_authorization_code(token_service, client, marker).await {
                    Ok(true) => {
                        return Err(OAuthEndpointError::token(
                            StatusCode::BAD_REQUEST,
                            "invalid_grant",
                            "授权码已被使用，相关令牌已撤销.",
                            false,
                        ));
                    }
                    Ok(false) => {}
                    Err(response) => return Err(response),
                }
                return Err(OAuthEndpointError::token(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "授权码已被使用.",
                    false,
                ));
            }
            Ok(AuthorizationCodeConsumption::Busy) => {
                return Err(OAuthEndpointError::token(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "授权码正在兑换.",
                    false,
                ));
            }
            Ok(AuthorizationCodeConsumption::Failed) => {
                return Err(OAuthEndpointError::token(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "授权码兑换已失败.",
                    false,
                ));
            }
            Ok(AuthorizationCodeConsumption::Missing) => {
                return Err(OAuthEndpointError::token(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "授权码无效或已过期.",
                    false,
                ));
            }
            Ok(AuthorizationCodeConsumption::Malformed) => {
                return Err(OAuthEndpointError::token(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "授权码状态无效.",
                    false,
                ));
            }
            Err(response) => return Err(response),
        };
    let payload = *payload;
    if payload.expires_at <= Utc::now() {
        mark_failed_authorization_code(
            token_service,
            issuance.config.auth_code_ttl_seconds(),
            &code_hash,
            "authorization_code_expired",
        )
        .await;
        return Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "授权码无效或已过期.",
            false,
        ));
    }
    let refresh_token_dpop_jkt = refresh_token_dpop_binding(client, &payload, dpop_jkt.clone());
    let refresh_token_mtls_x5t_s256 = mtls_x5t_s256.clone();
    // begin only yields Consuming from a Pending state, so the pure audience
    // facts computed before the sender proof must exist here.  Subject
    // derivation is intentionally performed after begin: a missing pairwise
    // secret is a server-side policy failure, not a client parameter error,
    // and must terminally fail the one-time grant.
    let audiences = pending_audiences.expect("Consuming requires pre-computed pending facts");
    let subject = match authorization_code_subject(issuance.config, &payload, client) {
        Ok(subject) => subject,
        Err(_) => {
            mark_failed_authorization_code(
                token_service,
                issuance.config.auth_code_ttl_seconds(),
                &code_hash,
                "subject_policy_invalid",
            )
            .await;
            return Err(OAuthEndpointError::token(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "subject invalid",
                false,
            ));
        }
    };
    issue_token_response(
        issuance,
        token_service,
        client,
        TokenIssuanceMode::SingleUse {
            grant_key: authorization_code_grant_key.clone(),
        },
        token_issue_from_authorization_code(AuthorizationCodeIssueInput {
            payload,
            subject,
            audiences,
            dpop_jkt,
            mtls_x5t_s256,
            code_hash,
            refresh_token_dpop_jkt,
            refresh_token_mtls_x5t_s256,
            refresh_token_client_attestation_jkt: client_attestation_jkt.map(ToOwned::to_owned),
        }),
    )
    .await
}

/// Pure Pending-redemption validation performed before any sender proof or
/// atomic consumption. On error the authorization code stays Pending and no
/// store transition happens.
pub fn validate_pending_authorization_code_request(
    issuance: &TokenIssuanceContext<'_>,
    client: &ClientRow,
    form: &TokenForm,
    payload: &CodePayload,
) -> Result<Vec<String>, OAuthEndpointError> {
    if payload.expires_at <= Utc::now() {
        return Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "授权码无效或已过期.",
            false,
        ));
    }
    if !redirect_uri_matches_authorization_request(payload, form.redirect_uri.as_deref()) {
        return Err(authorization_code_client_mismatch_response());
    }
    match (&payload.code_challenge, &payload.code_challenge_method) {
        (Some(code_challenge), Some(method)) if method == "S256" => {
            let Some(verifier) = &form.code_verifier else {
                return Err(OAuthEndpointError::token(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "缺少 code_verifier.",
                    false,
                ));
            };
            if !is_valid_pkce_value(verifier) || pkce_s256(verifier) != *code_challenge {
                return Err(OAuthEndpointError::token(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "PKCE 校验失败.",
                    false,
                ));
            }
        }
        (None, None) if !authorization_code_requires_pkce(client, payload) => {
            if form.code_verifier.is_some() {
                return Err(OAuthEndpointError::token(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "原授权请求未包含 code_challenge.",
                    false,
                ));
            }
        }
        _ => {
            return Err(OAuthEndpointError::token(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权码 PKCE 状态无效.",
                false,
            ));
        }
    }
    let audiences = match authorization_code_audiences_with_default(
        issuance.config.default_audience(),
        issuance
            .config
            .openid4vci_audience(&payload.scopes, &payload.authorization_details),
        payload,
        form,
    ) {
        Ok(audiences) => audiences,
        Err(()) => {
            return Err(OAuthEndpointError::token(
                StatusCode::BAD_REQUEST,
                "invalid_target",
                "请求的 resource 超出授权请求范围.",
                false,
            ));
        }
    };
    if !audiences_allowed(client, &audiences) {
        return Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "请求的 audience 不在客户端允许范围内.",
            false,
        ));
    }
    if native_sso_requested(&payload.scopes) {
        if !issuance.permits(nazo_runtime_modules::ModuleId::NativeSso) {
            return Err(OAuthEndpointError::token(
                StatusCode::BAD_REQUEST,
                "invalid_scope",
                "Native SSO is not enabled.",
                false,
            ));
        }
        if !payload.scopes.iter().any(|scope| scope == "openid") {
            return Err(OAuthEndpointError::token(
                StatusCode::BAD_REQUEST,
                "invalid_scope",
                "Native SSO requires openid.",
                false,
            ));
        }
    }
    Ok(audiences)
}

async fn mark_failed_authorization_code(
    service: &ServerTokenService,
    ttl_seconds: u64,
    code_hash: &str,
    error_code: &str,
) {
    if let Err(error) = crate::token::issue::mark_failed_authorization_code(
        service,
        code_hash,
        error_code,
        ttl_seconds,
    )
    .await
    {
        tracing::warn!(%error, "failed to mark authorization code exchange as failed");
    }
}

fn authorization_code_subject(
    config: &TokenIssuanceConfig,
    payload: &CodePayload,
    client: &ClientRow,
) -> anyhow::Result<String> {
    let subject_type = client.subject_type.as_str();
    let sector_host = client.sector_identifier_host.as_deref();
    let redirect_uri = payload.redirect_uri.as_str();
    let user_id = payload.user_id;
    Ok(nazo_auth::oidc_subject_for_client(
        config.issuer(),
        config.pairwise_subject_secret(),
        user_id,
        subject_type,
        sector_host,
        redirect_uri,
    )?)
}

#[cfg(test)]
#[path = "../../tests/unit/token/authorization_code.rs"]
mod tests;

#[cfg(test)]
#[path = "../../tests/unit/token/authorization_code_pkce.rs"]
mod pkce_tests;
