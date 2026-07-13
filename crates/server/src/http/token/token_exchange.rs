//! RFC 8693 OAuth 2.0 Token Exchange grant.
//!
//! This implementation intentionally accepts only locally issued access tokens
//! and issues only locally signed access tokens. External token trust, refresh
//! token exchange, and ID-token issuance require separate policy models.
use nazo_http_actix::oauth_token_error;

use super::issue::{TokenIssuanceContext, issue_token_response_with_service};
use super::{
    ServerTokenService, TokenForm, consume_token_client_assertion_with_authorization_service,
};
use super::{native_sso_profile_requested, token_native_sso_exchange};
use crate::domain::{ClientRow, RefreshTokenPolicy, TokenIssue};
#[cfg(test)]
use crate::support::{DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID, DEFAULT_TENANT_ID};
use crate::support::{
    DpopError, DpopErrorContext, ValidatedClientAssertion, access_token_tenant_id,
    audiences_allowed, constant_time_eq, dpop_error_response, is_subset, parse_scope,
    request_mtls_thumbprint_from_trusted_proxy, validate_dpop_proof_with_authorization_service,
};
use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse};
use chrono::Utc;
use nazo_auth::Claims;
use serde_json::{Value, json};
use uuid::Uuid;

pub(crate) const TOKEN_EXCHANGE_GRANT_TYPE: &str =
    "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

#[derive(Debug, PartialEq, Eq)]
enum TokenExchangeTokenError {
    Invalid,
    StoreUnavailable,
}

#[derive(Debug, PartialEq, Eq)]
enum TokenExchangeTypeError {
    MissingSubjectToken,
    MissingSubjectTokenType,
    UnsupportedSubjectTokenType,
    ActorTokenTypeWithoutActorToken,
    MissingActorTokenType,
    UnsupportedActorTokenType,
    UnsupportedRequestedTokenType,
}

#[derive(Debug, PartialEq, Eq)]
enum SenderBinding {
    Dpop(String),
    Mtls(String),
}

fn validate_token_exchange_type_policy(form: &TokenForm) -> Result<(), TokenExchangeTypeError> {
    if form.subject_token.is_none() {
        return Err(TokenExchangeTypeError::MissingSubjectToken);
    }
    match form.subject_token_type.as_deref() {
        Some(ACCESS_TOKEN_TYPE) => {}
        Some(_) => return Err(TokenExchangeTypeError::UnsupportedSubjectTokenType),
        None => return Err(TokenExchangeTypeError::MissingSubjectTokenType),
    }
    match (form.actor_token.as_ref(), form.actor_token_type.as_deref()) {
        (None, None) => {}
        (None, Some(_)) => return Err(TokenExchangeTypeError::ActorTokenTypeWithoutActorToken),
        (Some(_), Some(ACCESS_TOKEN_TYPE)) => {}
        (Some(_), Some(_)) => return Err(TokenExchangeTypeError::UnsupportedActorTokenType),
        (Some(_), None) => return Err(TokenExchangeTypeError::MissingActorTokenType),
    }
    if let Some(requested_token_type) = form.requested_token_type.as_deref()
        && requested_token_type != ACCESS_TOKEN_TYPE
    {
        return Err(TokenExchangeTypeError::UnsupportedRequestedTokenType);
    }
    Ok(())
}

fn token_exchange_type_error_response(error: TokenExchangeTypeError) -> HttpResponse {
    match error {
        TokenExchangeTypeError::MissingSubjectToken
        | TokenExchangeTypeError::MissingSubjectTokenType
        | TokenExchangeTypeError::ActorTokenTypeWithoutActorToken
        | TokenExchangeTypeError::MissingActorTokenType => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "token exchange request is missing required token parameters.",
            false,
        ),
        TokenExchangeTypeError::UnsupportedSubjectTokenType
        | TokenExchangeTypeError::UnsupportedActorTokenType
        | TokenExchangeTypeError::UnsupportedRequestedTokenType => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "unsupported token exchange token type.",
            false,
        ),
    }
}

fn token_exchange_requested_scopes(
    client: &ClientRow,
    subject: &Claims,
    requested_scope: Option<&str>,
) -> Result<Vec<String>, HttpResponse> {
    let subject_scopes = parse_scope(&subject.scope);
    let requested = parse_scope(requested_scope.unwrap_or(""));
    let scopes = if requested.is_empty() {
        subject_scopes
            .iter()
            .filter(|scope| *scope != "openid" && client.scopes.contains(scope))
            .cloned()
            .collect::<Vec<_>>()
    } else {
        if requested.iter().any(|scope| scope == "openid")
            || !is_subset(&requested, &subject_scopes)
            || !is_subset(&requested, &client.scopes)
        {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_scope",
                "token exchange scope must be a subset of the subject token and client scopes.",
                false,
            ));
        }
        requested
    };
    if scopes.is_empty() {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "token exchange cannot issue an access token without non-OIDC scopes.",
            false,
        ));
    }
    Ok(scopes)
}

fn token_exchange_requested_audiences(
    client: &ClientRow,
    form: &TokenForm,
) -> Result<Vec<String>, HttpResponse> {
    if form.audiences.is_empty() {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "token exchange requires an explicit resource or audience.",
            false,
        ));
    }
    if !audiences_allowed(client, &form.audiences) {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "requested token exchange target is not allowed for this client.",
            false,
        ));
    }
    Ok(form.audiences.clone())
}

fn token_exchange_client_authorized(client: &ClientRow, subject: &Claims) -> bool {
    subject.client_id == client.client_id
}

fn token_exchange_subject_user_id(subject: &Claims) -> Result<Option<Uuid>, HttpResponse> {
    match subject.user_id.as_deref() {
        Some(user_id) => user_id.parse::<Uuid>().map(Some).map_err(|_| {
            oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "subject token contains an invalid user boundary.",
                false,
            )
        }),
        None => Ok(None),
    }
}

async fn validate_exchange_access_token(
    token_service: &ServerTokenService,
    issuer: &str,
    client: &ClientRow,
    raw_token: &str,
) -> Result<Claims, TokenExchangeTokenError> {
    let Some(claims) = token_service
        .decode_access_token(issuer, raw_token)
        .await
        .map_err(|error| {
            tracing::warn!(?error, "failed to decode token exchange access token");
            TokenExchangeTokenError::StoreUnavailable
        })?
    else {
        return Err(TokenExchangeTokenError::Invalid);
    };
    if access_token_tenant_id(&claims) != Some(client.tenant_id)
        || claims.exp <= Utc::now().timestamp()
    {
        return Err(TokenExchangeTokenError::Invalid);
    }
    let revoked = token_service
        .access_token_revoked(client.tenant_id, &claims.jti)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "failed to query token exchange access token revocation state");
            TokenExchangeTokenError::StoreUnavailable
        })?;
    if revoked {
        return Err(TokenExchangeTokenError::Invalid);
    }
    Ok(claims)
}

fn exchange_token_error_response(error: TokenExchangeTokenError) -> HttpResponse {
    match error {
        TokenExchangeTokenError::Invalid => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "token exchange input token is invalid.",
            false,
        ),
        TokenExchangeTokenError::StoreUnavailable => oauth_token_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "token exchange token state is unavailable.",
            false,
        ),
    }
}

async fn validate_subject_sender_binding(
    authorization_service: &crate::http::authorization::ServerAuthorizationService,
    issuance: &TokenIssuanceContext<'_>,
    req: &HttpRequest,
    subject_token: &str,
    subject: &Claims,
) -> Result<Option<SenderBinding>, HttpResponse> {
    let Some(cnf) = subject.cnf.as_ref() else {
        return Ok(None);
    };
    if let Some(jkt) = cnf.jkt.as_deref() {
        let proof_jkt = validate_dpop_proof_with_authorization_service(
            authorization_service,
            issuance.config.issuer(),
            issuance.config.mtls_endpoint_base_url(),
            issuance.config.dpop_nonce_policy(),
            req,
            Some(subject_token),
            Some(jkt),
        )
        .await
        .map_err(|error| dpop_error_response(error, DpopErrorContext::TokenEndpoint))?;
        return Ok(proof_jkt.map(SenderBinding::Dpop));
    }
    if let Some(expected) = cnf.x5t_s256.as_deref() {
        let Some(actual) =
            request_mtls_thumbprint_from_trusted_proxy(req, issuance.config.trusted_proxy_cidrs())
        else {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "mTLS-bound subject token requires a verified client certificate.",
                false,
            ));
        };
        if !constant_time_eq(expected.as_bytes(), actual.as_bytes()) {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "mTLS-bound subject token certificate mismatch.",
                false,
            ));
        }
        return Ok(Some(SenderBinding::Mtls(actual)));
    }
    Ok(None)
}

async fn token_exchange_issue_binding(
    authorization_service: &crate::http::authorization::ServerAuthorizationService,
    issuance: &TokenIssuanceContext<'_>,
    req: &HttpRequest,
    client: &ClientRow,
    subject_binding: Option<SenderBinding>,
) -> Result<(Option<String>, Option<String>), HttpResponse> {
    match subject_binding {
        Some(SenderBinding::Dpop(jkt)) => {
            if client.require_mtls_bound_tokens {
                return Err(oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "token exchange cannot convert DPoP subject binding to mTLS.",
                    false,
                ));
            }
            Ok((Some(jkt), None))
        }
        Some(SenderBinding::Mtls(x5t_s256)) => {
            if client.require_dpop_bound_tokens {
                return Err(oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "token exchange cannot convert mTLS subject binding to DPoP.",
                    false,
                ));
            }
            Ok((None, Some(x5t_s256)))
        }
        None if client.require_dpop_bound_tokens => {
            let dpop_jkt = validate_dpop_proof_with_authorization_service(
                authorization_service,
                issuance.config.issuer(),
                issuance.config.mtls_endpoint_base_url(),
                issuance.config.dpop_nonce_policy(),
                req,
                None,
                None,
            )
            .await
            .map_err(|error| dpop_error_response(error, DpopErrorContext::TokenEndpoint))?;
            if dpop_jkt.is_none() {
                return Err(dpop_error_response(
                    DpopError::MissingProof,
                    DpopErrorContext::TokenEndpoint,
                ));
            }
            Ok((dpop_jkt, None))
        }
        None if client.require_mtls_bound_tokens => {
            let Some(x5t_s256) = request_mtls_thumbprint_from_trusted_proxy(
                req,
                issuance.config.trusted_proxy_cidrs(),
            ) else {
                return Err(oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "token exchange requires mTLS sender constraint.",
                    false,
                ));
            };
            Ok((None, Some(x5t_s256)))
        }
        None => Ok((None, None)),
    }
}

fn actor_claim(actor: &Claims) -> Value {
    let mut claim = json!({
        "sub": actor.sub,
        "client_id": actor.client_id
    });
    if let Some(previous_actor) = actor.act.as_ref() {
        claim["act"] = previous_actor.clone();
    }
    claim
}

async fn validate_actor_token(
    token_service: &ServerTokenService,
    issuer: &str,
    client: &ClientRow,
    actor_token: Option<&str>,
) -> Result<Option<Value>, HttpResponse> {
    let Some(actor_token) = actor_token else {
        return Ok(None);
    };
    let actor = validate_exchange_access_token(token_service, issuer, client, actor_token)
        .await
        .map_err(exchange_token_error_response)?;
    if actor.client_id != client.client_id {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "actor token must be issued to the authenticated client.",
            false,
        ));
    }
    if actor.cnf.is_some() {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "sender-constrained actor tokens are not supported for token exchange.",
            false,
        ));
    }
    Ok(Some(actor_claim(&actor)))
}

pub(crate) async fn token_exchange(
    token_service: &ServerTokenService,
    authorization_service: &crate::http::authorization::ServerAuthorizationService,
    issuance: &TokenIssuanceContext<'_>,
    req: &HttpRequest,
    client: &ClientRow,
    form: &TokenForm,
    client_assertion: Option<&ValidatedClientAssertion>,
) -> HttpResponse {
    if native_sso_profile_requested(form) {
        return token_native_sso_exchange(
            token_service,
            issuance,
            req,
            client,
            form,
            client_assertion,
        )
        .await;
    }
    if !issuance.accepts(nazo_runtime_modules::ModuleId::TokenExchange) {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "Token exchange is disabled.",
            false,
        );
    }
    if client.client_type != "confidential" {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "token exchange requires a confidential client.",
            false,
        );
    }
    if let Err(error) = validate_token_exchange_type_policy(form) {
        return token_exchange_type_error_response(error);
    }
    if let Err(response) = consume_token_client_assertion_with_authorization_service(
        authorization_service,
        client,
        client_assertion,
    )
    .await
    {
        return response;
    }
    let subject_token = form
        .subject_token
        .as_deref()
        .expect("validated token exchange form must contain subject_token");
    let subject = match validate_exchange_access_token(
        token_service,
        issuance.config.issuer(),
        client,
        subject_token,
    )
    .await
    {
        Ok(claims) => claims,
        Err(error) => return exchange_token_error_response(error),
    };
    if !token_exchange_client_authorized(client, &subject) {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "client is not authorized to exchange this subject token.",
            false,
        );
    }
    let subject_binding = match validate_subject_sender_binding(
        authorization_service,
        issuance,
        req,
        subject_token,
        &subject,
    )
    .await
    {
        Ok(binding) => binding,
        Err(response) => return response,
    };
    let (dpop_jkt, mtls_x5t_s256) = match token_exchange_issue_binding(
        authorization_service,
        issuance,
        req,
        client,
        subject_binding,
    )
    .await
    {
        Ok(binding) => binding,
        Err(response) => return response,
    };
    let actor = match validate_actor_token(
        token_service,
        issuance.config.issuer(),
        client,
        form.actor_token.as_deref(),
    )
    .await
    {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    let scopes = match token_exchange_requested_scopes(client, &subject, form.scope.as_deref()) {
        Ok(scopes) => scopes,
        Err(response) => return response,
    };
    let audiences = match token_exchange_requested_audiences(client, form) {
        Ok(audiences) => audiences,
        Err(response) => return response,
    };
    let user_id = match token_exchange_subject_user_id(&subject) {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    issue_token_response_with_service(
        issuance,
        token_service,
        client,
        TokenIssue {
            user_id,
            subject: subject.sub,
            scopes,
            authorization_details: json!([]),
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
            include_refresh: false,
            refresh_token_policy: RefreshTokenPolicy::PreserveExisting,
            dpop_jkt,
            refresh_token_dpop_jkt: None,
            mtls_x5t_s256,
            refresh_token_mtls_x5t_s256: None,
            authorization_code_hash: None,
            actor,
            issued_token_type: Some(ACCESS_TOKEN_TYPE.to_owned()),
            native_sso: None,
        },
    )
    .await
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/token/tests/token_exchange.rs"]
mod tests;
