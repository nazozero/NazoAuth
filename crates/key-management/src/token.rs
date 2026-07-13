use chrono::Utc;
use nazo_auth::{
    AccessTokenClaimsInput, AccessTokenSignInput, IdTokenClaimsInput, IdTokenSignInput,
    IssuedAccessToken, SigningPurpose, TokenFuture, TokenPortError, TokenSignerPort,
    access_token_claims, id_token_claims,
};
use serde_json::Value;
use uuid::Uuid;

use crate::{KeyManager, signing_algorithm_from_name};

impl TokenSignerPort for KeyManager {
    fn sign_access_token<'a>(
        &'a self,
        input: AccessTokenSignInput<'a>,
    ) -> TokenFuture<'a, IssuedAccessToken> {
        Box::pin(async move {
            let now = Utc::now().timestamp();
            let jti = Uuid::now_v7().to_string();
            let expires_at = now + input.ttl_seconds;
            let claims = access_token_claims(
                input.issuer,
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
                    ttl: input.ttl_seconds,
                    dpop_jkt: input.dpop_jkt,
                    mtls_x5t_s256: input.mtls_x5t_s256,
                    actor: input.actor,
                },
                now,
                &jti,
            );
            let keyset = self.snapshot();
            let mut header = jsonwebtoken::Header::new(keyset.active_alg);
            header.typ = Some("at+jwt".to_owned());
            header.kid = Some(keyset.active_kid.clone());
            let token = self
                .encode_jwt(SigningPurpose::AccessToken, &header, &claims)
                .await
                .map_err(|_| TokenPortError::Unavailable)?;
            Ok(IssuedAccessToken {
                token,
                jti,
                expires_at,
            })
        })
    }

    fn sign_id_token<'a>(&'a self, input: IdTokenSignInput<'a>) -> TokenFuture<'a, String> {
        Box::pin(async move {
            let claims = id_token_claims(
                input.issuer,
                &IdTokenClaimsInput {
                    subject: input.subject,
                    client_id: input.client_id,
                    nonce: input.nonce,
                    auth_time: input.auth_time,
                    amr: input.amr,
                    sid: input.sid,
                    acr: input.acr,
                    extra_claims: input.extra_claims,
                    ttl: input.ttl_seconds,
                },
                Utc::now().timestamp(),
            );
            let algorithm = match input.signing_algorithm {
                Some(name) => {
                    signing_algorithm_from_name(name).ok_or(TokenPortError::Unexpected)?
                }
                None => self.snapshot().active_alg,
            };
            let mut header = jsonwebtoken::Header::new(algorithm);
            header.typ = Some("JWT".to_owned());
            self.encode_jwt(SigningPurpose::IdToken, &header, &Value::Object(claims))
                .await
                .map_err(|_| TokenPortError::Unavailable)
        })
    }
}
