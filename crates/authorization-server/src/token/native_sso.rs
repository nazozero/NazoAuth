//! Shared Native SSO state and binding semantics.
use crate::contracts::{oauth_error::OAuthEndpointError, token_forms::TokenForm};
use crate::crypto::random_urlsafe_token;
use crate::domain::{
    client_policy::{is_subset, parse_scope},
    oauth::{NativeSsoTokenBinding, TokenIssue},
    rows::ClientRow,
};
use crate::services::ServerTokenService;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use http::StatusCode;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const DEVICE_SSO_SCOPE: &str = "device_sso";
pub const NATIVE_SSO_DEVICE_SECRET_TYPE: &str = "urn:openid:params:token-type:device-secret";
pub const NATIVE_SSO_ID_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:id_token";

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct NativeSsoDeviceSecretState {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub subject: String,
    pub sid: String,
    pub source_client_id: String,
    pub refresh_token_family_id: Uuid,
    pub expires_at: DateTime<Utc>,
}

#[derive(Deserialize)]
pub struct NativeSsoIdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: Value,
    pub ds_hash: String,
    pub sid: String,
    pub auth_time: i64,
    pub amr: Vec<String>,
}

pub fn native_sso_requested(scopes: &[String]) -> bool {
    scopes.iter().any(|scope| scope == DEVICE_SSO_SCOPE)
}

pub fn native_sso_client_authorized(client: &ClientRow) -> bool {
    client.scopes.iter().any(|scope| scope == DEVICE_SSO_SCOPE)
}

pub fn native_sso_device_secret_hash(device_secret: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(device_secret.as_bytes()))
}

pub fn native_sso_profile_requested(form: &TokenForm) -> bool {
    form.grant_type == "urn:ietf:params:oauth:grant-type:token-exchange"
        && form.subject_token_type.as_deref() == Some(NATIVE_SSO_ID_TOKEN_TYPE)
        && form.actor_token_type.as_deref() == Some(NATIVE_SSO_DEVICE_SECRET_TYPE)
}

pub fn new_native_sso_token_binding(oidc_sid: Option<&str>) -> Option<NativeSsoTokenBinding> {
    let sid = oidc_sid?;
    let device_secret = format!("{}.{}", random_urlsafe_token(), random_urlsafe_token());
    Some(NativeSsoTokenBinding {
        ds_hash: native_sso_device_secret_hash(&device_secret),
        device_secret,
        sid: sid.to_owned(),
    })
}

pub fn native_sso_id_token_audience_contains(
    claims: &NativeSsoIdTokenClaims,
    client_id: &str,
) -> bool {
    match &claims.aud {
        Value::String(value) => value == client_id,
        Value::Array(values) => values.iter().any(|value| value.as_str() == Some(client_id)),
        _ => false,
    }
}

pub async fn decode_native_sso_id_token_with_service(
    token_service: &ServerTokenService,
    issuer: &str,
    token: &str,
) -> Result<Option<NativeSsoIdTokenClaims>, nazo_auth::TokenPortError> {
    let claims = token_service
        .decode_id_token(issuer, token)
        .await?
        .map(serde_json::from_value)
        .transpose()
        .map_err(|_| nazo_auth::TokenPortError::CorruptData)?;
    Ok(claims.filter(|claims: &NativeSsoIdTokenClaims| claims.iss == issuer))
}

pub async fn load_native_sso_device_secret_state(
    token_service: &ServerTokenService,
    device_secret: &str,
) -> Result<Option<NativeSsoDeviceSecretState>, OAuthEndpointError> {
    let value = token_service
        .load_native_sso(device_secret)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "failed to load Native SSO device secret state");
            OAuthEndpointError::token(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Native SSO device secret state is unavailable.",
                false,
            )
        })?;
    let Some(value) = value else {
        return Ok(None);
    };
    serde_json::from_value(value).map(Some).map_err(|error| {
        tracing::warn!(%error, "Native SSO device secret state is malformed");
        OAuthEndpointError::token(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "Native SSO device secret state is invalid.",
            false,
        )
    })
}

pub async fn native_sso_refresh_family_active(
    token_service: &ServerTokenService,
    secret: &NativeSsoDeviceSecretState,
) -> Result<bool, OAuthEndpointError> {
    token_service
        .refresh_family_active(
            secret.tenant_id,
            secret.refresh_token_family_id,
            secret.user_id,
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "failed to query Native SSO refresh family state");
            OAuthEndpointError::token(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Native SSO session state is unavailable.",
                false,
            )
        })
}

pub fn native_sso_requested_scopes(
    client: &ClientRow,
    requested_scope: Option<&str>,
) -> Result<Vec<String>, OAuthEndpointError> {
    let requested = parse_scope(requested_scope.unwrap_or("openid offline_access device_sso"));
    if !requested.iter().any(|scope| scope == "openid")
        || !requested.iter().any(|scope| scope == DEVICE_SSO_SCOPE)
        || !is_subset(&requested, &client.scopes)
    {
        return Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "Native SSO scope must include allowed openid and device_sso scopes.",
            false,
        ));
    }
    Ok(requested)
}

pub fn native_sso_subject_for_client(
    config: &crate::token::issue::TokenIssuanceConfig,
    user_id: Uuid,
    client: &ClientRow,
) -> anyhow::Result<String> {
    let redirect_uri = client.redirect_uris.first().map_or("", String::as_str);
    Ok(nazo_auth::oidc_subject_for_client(
        config.issuer(),
        config.pairwise_subject_secret(),
        user_id,
        client.subject_type.as_str(),
        client.sector_identifier_host.as_deref(),
        redirect_uri,
    )?)
}

pub async fn persist_native_sso_device_secret(
    token_service: &ServerTokenService,
    refresh_token_ttl_seconds: i64,
    client: &ClientRow,
    issue: &TokenIssue,
    binding: &NativeSsoTokenBinding,
    refresh_token_family_id: Uuid,
) -> anyhow::Result<()> {
    let Some(user_id) = issue.user_id else {
        return Ok(());
    };
    let expires_at = Utc::now() + Duration::seconds(refresh_token_ttl_seconds);
    let payload = NativeSsoDeviceSecretState {
        tenant_id: client.tenant_id,
        user_id,
        subject: issue.subject.clone(),
        sid: binding.sid.clone(),
        source_client_id: client.client_id.clone(),
        refresh_token_family_id,
        expires_at,
    };
    token_service
        .store_native_sso(
            &binding.device_secret,
            &serde_json::to_value(payload)?,
            refresh_token_ttl_seconds.max(1) as u64,
        )
        .await?;
    Ok(())
}

use crate::contracts::{
    request_facts::DpopErrorContext,
    token_endpoint::{TokenEndpointSuccess, TokenRequestFacts},
};
use crate::domain::oauth::RefreshTokenPolicy;
use crate::token::client_auth::consume_token_client_assertion_with_authorization_service;
use crate::token::issue::{TokenIssuanceContext, issue_token_response};
use crate::token::{
    SenderConstraintValidationError, sender_constraint_multiple_error,
    validate_token_sender_constraints,
};
use nazo_auth::{TokenIssuanceMode, ValidatedClientAssertion};
use serde_json::json;

pub async fn native_sso_issue_binding(
    issuance: &TokenIssuanceContext<'_>,
    facts: &TokenRequestFacts<'_>,
    client: &ClientRow,
) -> Result<(Option<String>, Option<String>), OAuthEndpointError> {
    let sender = validate_token_sender_constraints(issuance, facts, client, None, None, None)
        .await
        .map_err(|error| match error {
            SenderConstraintValidationError::Dpop(error) => OAuthEndpointError::Dpop {
                error,
                context: DpopErrorContext::TokenEndpoint,
            },
            SenderConstraintValidationError::MissingMtls => OAuthEndpointError::token(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Native SSO requires mTLS sender constraint.",
                false,
            ),
            SenderConstraintValidationError::Multiple => sender_constraint_multiple_error(),
        })?;
    Ok((sender.dpop_jkt, sender.mtls_x5t_s256))
}

pub async fn token_native_sso_exchange(
    token_service: &ServerTokenService,
    issuance: &TokenIssuanceContext<'_>,
    facts: &TokenRequestFacts<'_>,
    client: &ClientRow,
    form: &TokenForm,
    client_assertion: Option<&ValidatedClientAssertion>,
) -> Result<TokenEndpointSuccess, OAuthEndpointError> {
    if !issuance.permits(nazo_runtime_modules::ModuleId::NativeSso) {
        return Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "Native SSO is not enabled.",
            false,
        ));
    }
    if !native_sso_client_authorized(client) {
        return Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "Client is not authorized for Native SSO.",
            false,
        ));
    }
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
    if form.audiences.as_slice() != [issuance.config.issuer()] {
        return Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "Native SSO token exchange audience must be the issuer.",
            false,
        ));
    }
    let Some(subject_token) = form.subject_token.as_deref() else {
        return Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Native SSO requires subject_token.",
            false,
        ));
    };
    let Some(device_secret) = form.actor_token.as_deref() else {
        return Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Native SSO requires actor_token.",
            false,
        ));
    };
    let claims = match decode_native_sso_id_token_with_service(
        token_service,
        issuance.config.issuer(),
        subject_token,
    )
    .await
    {
        Ok(Some(claims)) => claims,
        Ok(None) | Err(_) => {
            return Err(OAuthEndpointError::token(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Native SSO id_token is invalid.",
                false,
            ));
        }
    };
    if claims.ds_hash != native_sso_device_secret_hash(device_secret) {
        return Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Native SSO id_token is not bound to the device secret.",
            false,
        ));
    }
    let secret = match load_native_sso_device_secret_state(token_service, device_secret).await {
        Ok(Some(secret)) => secret,
        Ok(None) => {
            return Err(OAuthEndpointError::token(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Native SSO device secret is invalid.",
                false,
            ));
        }
        Err(response) => return Err(response),
    };
    if secret.tenant_id != client.tenant_id
        || secret.expires_at <= Utc::now()
        || secret.subject != claims.sub
        || secret.sid != claims.sid
        || !native_sso_id_token_audience_contains(&claims, &secret.source_client_id)
    {
        return Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Native SSO device secret state does not match the id_token.",
            false,
        ));
    }
    match native_sso_refresh_family_active(token_service, &secret).await {
        Ok(true) => {}
        Ok(false) => {
            return Err(OAuthEndpointError::token(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Native SSO session is no longer active.",
                false,
            ));
        }
        Err(response) => return Err(response),
    }
    let scopes = match native_sso_requested_scopes(client, form.scope.as_deref()) {
        Ok(scopes) => scopes,
        Err(response) => return Err(response),
    };
    let subject = match native_sso_subject_for_client(issuance.config, secret.user_id, client) {
        Ok(subject) => subject,
        Err(error) => {
            tracing::warn!(%error, "failed to compute Native SSO destination subject");
            return Err(OAuthEndpointError::token(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Native SSO subject policy failed.",
                false,
            ));
        }
    };
    let (dpop_jkt, mtls_x5t_s256) = match native_sso_issue_binding(issuance, facts, client).await {
        Ok(binding) => binding,
        Err(response) => return Err(response),
    };
    let idempotency_key = facts.idempotency_key.clone();
    let mode = idempotency_key.map_or(TokenIssuanceMode::Fresh, |grant_key| {
        TokenIssuanceMode::Idempotent { grant_key }
    });
    issue_token_response(
        issuance,
        token_service,
        client,
        mode,
        TokenIssue {
            user_id: Some(secret.user_id),
            subject,
            scopes,
            authorization_details: json!([]),
            audiences: vec![issuance.config.default_audience().to_owned()],
            nonce: None,
            auth_time: Some(claims.auth_time),
            amr: claims.amr,
            oidc_sid: Some(secret.sid),
            acr: None,
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
            issued_token_type: Some("urn:ietf:params:oauth:token-type:access_token".to_owned()),
            native_sso: new_native_sso_token_binding(Some(&claims.sid)),
        },
    )
    .await
}

#[cfg(test)]
#[path = "../../tests/unit/token/native_sso.rs"]
mod tests;
