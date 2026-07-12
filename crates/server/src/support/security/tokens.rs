use super::jwt_decoding_key_from_jwk;

use chrono::Utc;
use nazo_auth::{
    AccessTokenClaimsInput, AuthorizationResponseClaimsInput, BackchannelLogoutClaimsInput, Claims,
    IdTokenClaimsInput, OidcClaimRequest,
};
use serde_json::Value;
use uuid::Uuid;

use crate::domain::AppState;
use crate::support::signing_algorithm_name;

pub(crate) struct AccessTokenJwtInput<'a> {
    pub(crate) tenant_id: Uuid,
    pub(crate) subject: &'a str,
    pub(crate) user_id: Option<Uuid>,
    pub(crate) subject_type: &'a str,
    pub(crate) client_id: &'a str,
    pub(crate) audiences: &'a [String],
    pub(crate) scopes: &'a [String],
    pub(crate) authorization_details: &'a Value,
    pub(crate) userinfo_claims: &'a [String],
    pub(crate) userinfo_claim_requests: &'a [OidcClaimRequest],
    pub(crate) ttl: i64,
    pub(crate) dpop_jkt: Option<&'a str>,
    pub(crate) mtls_x5t_s256: Option<&'a str>,
    pub(crate) actor: Option<&'a Value>,
}

pub(crate) struct IssuedAccessToken {
    pub(crate) token: String,
    pub(crate) jti: String,
    pub(crate) exp: i64,
}

pub(super) fn validate_access_token_sender_constraint(
    dpop_jkt: Option<&str>,
    mtls_x5t_s256: Option<&str>,
) -> jsonwebtoken::errors::Result<()> {
    if dpop_jkt.is_some() && mtls_x5t_s256.is_some() {
        return Err(jsonwebtoken::errors::Error::from(
            jsonwebtoken::errors::ErrorKind::InvalidToken,
        ));
    }
    Ok(())
}

pub(crate) async fn make_jwt(
    state: &AppState,
    input: AccessTokenJwtInput<'_>,
) -> jsonwebtoken::errors::Result<IssuedAccessToken> {
    validate_access_token_sender_constraint(input.dpop_jkt, input.mtls_x5t_s256)?;
    let now = Utc::now().timestamp();
    let jti = Uuid::now_v7().to_string();
    let exp = now + input.ttl;
    let claims = nazo_auth::access_token_claims(
        &state.settings.issuer,
        AccessTokenClaimsInput {
            tenant_id: input.tenant_id,
            subject: input.subject,
            user_id: input.user_id,
            subject_type: input.subject_type,
            client_id: input.client_id,
            audiences: input.audiences,
            scopes: input.scopes,
            authorization_details: input.authorization_details,
            userinfo_claims: input.userinfo_claims,
            userinfo_claim_requests: input.userinfo_claim_requests,
            ttl: input.ttl,
            dpop_jkt: input.dpop_jkt,
            mtls_x5t_s256: input.mtls_x5t_s256,
            actor: input.actor,
        },
        now,
        &jti,
    );
    let keyset = state.keyset.snapshot();
    let header = access_token_header(keyset.active_alg, &keyset.active_kid);
    let token = state
        .keyset
        .encode_jwt(nazo_auth::SigningPurpose::AccessToken, &header, &claims)
        .await?;
    Ok(IssuedAccessToken { token, jti, exp })
}

pub(super) fn access_token_header(alg: jsonwebtoken::Algorithm, kid: &str) -> jsonwebtoken::Header {
    let mut header = jsonwebtoken::Header::new(alg);
    header.typ = Some("at+jwt".to_string());
    header.kid = Some(kid.to_owned());
    header
}

pub(crate) struct IdTokenInput<'a> {
    pub(crate) subject: &'a str,
    pub(crate) client_id: &'a str,
    pub(crate) nonce: Option<String>,
    pub(crate) auth_time: Option<i64>,
    pub(crate) amr: &'a [String],
    pub(crate) sid: Option<&'a str>,
    pub(crate) acr: Option<&'a str>,
    pub(crate) extra_claims: Option<&'a Value>,
    pub(crate) ttl: i64,
    pub(crate) signing_alg: Option<jsonwebtoken::Algorithm>,
}

pub(crate) async fn make_id_token(
    state: &AppState,
    input: IdTokenInput<'_>,
) -> jsonwebtoken::errors::Result<String> {
    let now = Utc::now().timestamp();
    let claims = nazo_auth::id_token_claims(
        &state.settings.issuer,
        &IdTokenClaimsInput {
            subject: input.subject,
            client_id: input.client_id,
            nonce: input.nonce.as_deref(),
            auth_time: input.auth_time,
            amr: input.amr,
            sid: input.sid,
            acr: input.acr,
            extra_claims: input.extra_claims,
            ttl: input.ttl,
        },
        now,
    );
    sign_response_jwt(
        state,
        nazo_auth::SigningPurpose::IdToken,
        &Value::Object(claims),
        "JWT",
        input.signing_alg,
    )
    .await
}

pub(crate) async fn sign_response_jwt(
    state: &AppState,
    purpose: nazo_auth::SigningPurpose,
    claims: &Value,
    typ: &str,
    signing_alg: Option<jsonwebtoken::Algorithm>,
) -> jsonwebtoken::errors::Result<String> {
    let keyset = state.keyset.snapshot();
    let alg = signing_alg.unwrap_or(keyset.active_alg);
    let mut header = jsonwebtoken::Header::new(alg);
    header.typ = Some(typ.to_owned());
    state.keyset.encode_jwt(purpose, &header, claims).await
}

pub(crate) struct AuthorizationResponseJwtInput<'a> {
    pub(crate) client_id: &'a str,
    pub(crate) code: Option<&'a str>,
    pub(crate) error: Option<&'a str>,
    pub(crate) state: Option<&'a str>,
    pub(crate) ttl: i64,
}

pub(crate) struct BackchannelLogoutTokenInput<'a> {
    pub(crate) client_id: &'a str,
    pub(crate) subject: Option<&'a str>,
    pub(crate) sid: Option<&'a str>,
    pub(crate) ttl: i64,
}

pub(crate) async fn make_backchannel_logout_token(
    state: &AppState,
    input: BackchannelLogoutTokenInput<'_>,
) -> jsonwebtoken::errors::Result<String> {
    let now = Utc::now().timestamp();
    let claims = nazo_auth::backchannel_logout_token_claims(
        &state.settings.issuer,
        &BackchannelLogoutClaimsInput {
            client_id: input.client_id,
            subject: input.subject,
            sid: input.sid,
            ttl: input.ttl,
        },
        now,
    );
    let keyset = state.keyset.snapshot();
    let mut header = jsonwebtoken::Header::new(keyset.active_alg);
    header.typ = Some("logout+jwt".to_string());
    header.kid = Some(keyset.active_kid.clone());
    state
        .keyset
        .encode_jwt(
            nazo_auth::SigningPurpose::LogoutToken,
            &header,
            &Value::Object(claims),
        )
        .await
}

pub(crate) async fn make_authorization_response_jwt(
    state: &AppState,
    input: AuthorizationResponseJwtInput<'_>,
    signing_alg: Option<jsonwebtoken::Algorithm>,
) -> jsonwebtoken::errors::Result<String> {
    let now = Utc::now().timestamp();
    let claims = nazo_auth::authorization_response_jwt_claims(
        &state.settings.issuer,
        &AuthorizationResponseClaimsInput {
            client_id: input.client_id,
            code: input.code,
            error: input.error,
            state: input.state,
            ttl: input.ttl,
        },
        now,
    );
    sign_response_jwt(
        state,
        nazo_auth::SigningPurpose::Jarm,
        &Value::Object(claims),
        "oauth-authz-resp+jwt",
        signing_alg,
    )
    .await
}

pub(crate) fn decode_access_claims(state: &AppState, token: &str) -> Option<Claims> {
    let header = jsonwebtoken::decode_header(token).ok()?;
    if header.typ.as_deref() != Some("at+jwt") || signing_algorithm_name(header.alg).is_none() {
        return None;
    }
    let keyset = state.keyset.snapshot();
    let verification_key = keyset.verification_key(header.kid.as_deref()?)?;
    let decoding_key = jwt_decoding_key_from_jwk(&verification_key.public_jwk, header.alg)?;
    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.validate_aud = false;
    validation.set_issuer(&[state.settings.issuer.as_str()]);
    let token_data = jsonwebtoken::decode::<Claims>(token, &decoding_key, &validation).ok()?;
    if token_data.claims.token_use != "access" {
        return None;
    }
    Some(token_data.claims)
}
