//! RFC 7523 JWT bearer authorization grant.
#[cfg(test)]
use nazo_http_actix::OAuthJsonErrorFields;
use nazo_http_actix::oauth_token_error;

use super::issue::{TokenIssuanceContext, issue_token_response_with_service};
use super::{
    ServerTokenService, TokenForm, client_credentials_issue_request_with_default_audience,
    consume_token_client_assertion_with_authorization_service,
};
#[cfg(test)]
use crate::domain::AppState;
use crate::domain::{ClientRow, RefreshTokenPolicy, TokenIssue};
#[cfg(test)]
use crate::settings::Settings;
use crate::support::{
    dpop::DpopError, dpop::DpopErrorContext, dpop::dpop_error_response,
    dpop::validate_dpop_proof_with_authorization_service,
    mtls::request_mtls_thumbprint_from_trusted_proxy, security::ValidatedClientAssertion,
    security::client_jwt_decoding_key,
};
#[cfg(test)]
use crate::support::{
    tenancy::DEFAULT_ORGANIZATION_ID, tenancy::DEFAULT_REALM_ID, tenancy::DEFAULT_TENANT_ID,
};
#[cfg(test)]
use crate::test_support::{ClientSigningFixture, client_signing_fixture};
use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse};
#[cfg(test)]
use base64::Engine;
use chrono::Utc;
use serde_json::{Value, json};
#[cfg(test)]
use uuid::Uuid;

pub(crate) const JWT_BEARER_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

const JWT_BEARER_ASSERTION_MAX_TTL_SECONDS: i64 = 300;
const JWT_BEARER_ASSERTION_CLOCK_SKEW_SECONDS: i64 = 30;
const JWT_BEARER_ASSERTION_MAX_JTI_BYTES: usize = 128;

#[derive(serde::Deserialize)]
struct JwtBearerAssertionClaims {
    iss: String,
    sub: String,
    aud: Value,
    exp: i64,
    nbf: Option<i64>,
    iat: Option<i64>,
    jti: String,
}

pub(crate) struct ValidatedJwtBearerAssertion {
    pub(crate) subject: String,
    pub(crate) jti: String,
    exp: i64,
}

#[derive(Debug)]
pub(crate) enum JwtBearerAssertionError {
    Invalid,
    ReplayDetected,
    StoreUnavailable,
}

fn validate_jwt_bearer_assertion_with_issuer(
    issuer: &str,
    client: &ClientRow,
    assertion: &str,
) -> Result<ValidatedJwtBearerAssertion, JwtBearerAssertionError> {
    let header =
        jsonwebtoken::decode_header(assertion).map_err(|_| JwtBearerAssertionError::Invalid)?;
    let kid = header.kid.ok_or(JwtBearerAssertionError::Invalid)?;
    let decoding_key = client_jwt_decoding_key(client, &kid, header.alg)
        .ok_or(JwtBearerAssertionError::Invalid)?;
    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.validate_aud = false;
    validation.set_issuer(&[client.client_id.as_str()]);
    let token_data =
        jsonwebtoken::decode::<JwtBearerAssertionClaims>(assertion, &decoding_key, &validation)
            .map_err(|_| JwtBearerAssertionError::Invalid)?;
    let claims = token_data.claims;
    let now = Utc::now().timestamp();
    if claims.iss != client.client_id
        || claims.sub != client.client_id
        || !jwt_bearer_audience_matches(&claims.aud, issuer)
        || !valid_jwt_bearer_times(&claims, now)
        || !valid_jwt_bearer_jti(&claims.jti)
    {
        return Err(JwtBearerAssertionError::Invalid);
    }
    Ok(ValidatedJwtBearerAssertion {
        subject: claims.sub,
        jti: claims.jti,
        exp: claims.exp,
    })
}

#[cfg(test)]
fn validate_jwt_bearer_assertion(
    settings: &Settings,
    client: &ClientRow,
    assertion: &str,
) -> Result<ValidatedJwtBearerAssertion, JwtBearerAssertionError> {
    validate_jwt_bearer_assertion_with_issuer(&settings.endpoint.issuer, client, assertion)
}

fn jwt_bearer_audience_matches(aud: &Value, issuer: &str) -> bool {
    matches!(aud, Value::String(value) if value == issuer)
}

fn valid_jwt_bearer_times(claims: &JwtBearerAssertionClaims, now: i64) -> bool {
    if claims.exp <= now || claims.exp > now.saturating_add(JWT_BEARER_ASSERTION_MAX_TTL_SECONDS) {
        return false;
    }
    if claims
        .nbf
        .is_some_and(|nbf| nbf > now.saturating_add(JWT_BEARER_ASSERTION_CLOCK_SKEW_SECONDS))
    {
        return false;
    }
    if claims.iat.is_some_and(|iat| {
        iat > now.saturating_add(JWT_BEARER_ASSERTION_CLOCK_SKEW_SECONDS)
            || now.saturating_sub(iat) > JWT_BEARER_ASSERTION_MAX_TTL_SECONDS
    }) {
        return false;
    }
    true
}

fn valid_jwt_bearer_jti(jti: &str) -> bool {
    let trimmed = jti.trim();
    !trimmed.is_empty() && trimmed.len() <= JWT_BEARER_ASSERTION_MAX_JTI_BYTES
}

impl ValidatedJwtBearerAssertion {
    fn replay_ttl_seconds(&self, now: i64) -> u64 {
        self.exp
            .saturating_sub(now)
            .clamp(1, JWT_BEARER_ASSERTION_MAX_TTL_SECONDS) as u64
    }
}

async fn consume_jwt_bearer_assertion_with_authorization_service(
    authorization_service: &crate::http::authorization::ServerAuthorizationService,
    client: &ClientRow,
    assertion: &ValidatedJwtBearerAssertion,
) -> Result<(), JwtBearerAssertionError> {
    let now = Utc::now().timestamp();
    match authorization_service
        .consume_jwt_bearer(
            &client.client_id,
            &assertion.jti,
            assertion.replay_ttl_seconds(now),
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

#[cfg(test)]
async fn consume_jwt_bearer_assertion(
    state: &AppState,
    client: &ClientRow,
    assertion: &ValidatedJwtBearerAssertion,
) -> Result<(), JwtBearerAssertionError> {
    let authorization = super::issue::test_authorization_service(state);
    consume_jwt_bearer_assertion_with_authorization_service(&authorization, client, assertion).await
}

pub(crate) async fn token_jwt_bearer_with_service(
    token_service: &ServerTokenService,
    issuance: &TokenIssuanceContext<'_>,
    req: &HttpRequest,
    client: &ClientRow,
    form: &TokenForm,
    client_assertion: Option<&ValidatedClientAssertion>,
) -> HttpResponse {
    if !issuance.accepts(nazo_runtime_modules::ModuleId::JwtBearerGrant) {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "JWT bearer grant is disabled.",
            false,
        );
    }
    if client.client_type != "confidential" {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "JWT bearer grant requires a confidential client.",
            false,
        );
    }
    let Some(assertion) = form.assertion.as_deref() else {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "JWT bearer grant requires an assertion.",
            false,
        );
    };
    let dpop_jkt = match validate_dpop_proof_with_authorization_service(
        issuance.authorization,
        issuance.config.issuer(),
        issuance.config.mtls_endpoint_base_url(),
        issuance.config.dpop_nonce_policy(),
        req,
        None,
        None,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => return dpop_error_response(error, DpopErrorContext::TokenEndpoint),
    };
    if client.require_dpop_bound_tokens && dpop_jkt.is_none() {
        return dpop_error_response(DpopError::MissingProof, DpopErrorContext::TokenEndpoint);
    }
    let mtls_x5t_s256 = if client.require_mtls_bound_tokens {
        match request_mtls_thumbprint_from_trusted_proxy(req, issuance.config.trusted_proxy_cidrs())
        {
            Some(value) => Some(value),
            None => {
                return oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "JWT bearer grant requires mTLS sender constraint.",
                    false,
                );
            }
        }
    } else {
        None
    };
    if let Err(response) = consume_token_client_assertion_with_authorization_service(
        issuance.authorization,
        client,
        client_assertion,
    )
    .await
    {
        return response;
    }
    let assertion = match validate_jwt_bearer_assertion_with_issuer(
        issuance.config.issuer(),
        client,
        assertion,
    ) {
        Ok(assertion) => assertion,
        Err(_) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "JWT bearer assertion is invalid.",
                false,
            );
        }
    };
    if let Err(error) = consume_jwt_bearer_assertion_with_authorization_service(
        issuance.authorization,
        client,
        &assertion,
    )
    .await
    {
        return match error {
            JwtBearerAssertionError::StoreUnavailable => oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "JWT bearer assertion replay state is unavailable.",
                false,
            ),
            JwtBearerAssertionError::Invalid | JwtBearerAssertionError::ReplayDetected => {
                oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "JWT bearer assertion is invalid.",
                    false,
                )
            }
        };
    }
    let issue_request = match client_credentials_issue_request_with_default_audience(
        issuance.config.default_audience(),
        client,
        form,
    ) {
        Ok(issue_request) => issue_request,
        Err(response) => return response,
    };
    issue_token_response_with_service(
        issuance,
        token_service,
        client,
        TokenIssue {
            user_id: None,
            subject: assertion.subject,
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
            include_refresh: false,
            refresh_token_policy: RefreshTokenPolicy::PreserveExisting,
            dpop_jkt,
            refresh_token_dpop_jkt: None,
            mtls_x5t_s256,
            refresh_token_mtls_x5t_s256: None,
            authorization_code_hash: None,
            actor: None,
            issued_token_type: None,
            native_sso: None,
        },
    )
    .await
}

#[cfg(test)]
pub(crate) async fn token_jwt_bearer(
    state: &AppState,
    req: &HttpRequest,
    client: &ClientRow,
    form: &TokenForm,
    client_assertion: Option<&ValidatedClientAssertion>,
) -> HttpResponse {
    let connection = state.valkey_connection();
    let service = ServerTokenService::new(
        nazo_postgres::TokenIssuanceRepository::new(state.diesel_db.clone()),
        nazo_valkey::TokenIssuanceStateAdapter::new(&connection),
        state.keyset.clone(),
    );
    let config = super::issue::TokenIssuanceConfig::from(state.settings.as_ref());
    let modules = state.active_module_snapshot();
    let authorization = super::issue::test_authorization_service(state);
    token_jwt_bearer_with_service(
        &service,
        &TokenIssuanceContext {
            config: &config,
            modules: &modules,
            authorization: &authorization,
        },
        req,
        client,
        form,
        client_assertion,
    )
    .await
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/token/tests/jwt_bearer.rs"]
mod tests;
