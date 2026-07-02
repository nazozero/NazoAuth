//! OpenID Connect Federation entity statement endpoint.

use crate::http::prelude::*;

#[derive(serde::Serialize)]
struct FederationEntityStatement {
    iss: String,
    sub: String,
    iat: i64,
    exp: i64,
    jwks: Value,
    metadata: Value,
    authority_hints: Vec<String>,
}

fn federation_entity_statement_claims(
    issuer: &str,
    jwks: Value,
    now: i64,
    ttl_seconds: i64,
) -> FederationEntityStatement {
    FederationEntityStatement {
        iss: issuer.to_owned(),
        sub: issuer.to_owned(),
        iat: now,
        exp: now + ttl_seconds,
        jwks,
        metadata: json!({
            "openid_provider": {
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/authorize"),
                "token_endpoint": format!("{issuer}/token"),
                "jwks_uri": format!("{issuer}/jwks.json"),
                "pushed_authorization_request_endpoint": format!("{issuer}/par"),
                "userinfo_endpoint": format!("{issuer}/userinfo"),
                "end_session_endpoint": format!("{issuer}/logout")
            },
            "oauth_authorization_server": {
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/authorize"),
                "token_endpoint": format!("{issuer}/token"),
                "jwks_uri": format!("{issuer}/jwks.json"),
                "pushed_authorization_request_endpoint": format!("{issuer}/par")
            }
        }),
        authority_hints: Vec::new(),
    }
}

pub(crate) async fn openid_federation_entity_statement(state: Data<AppState>) -> HttpResponse {
    if !state.settings.enable_oidc_federation {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let keyset = state.keyset.snapshot();
    let mut header = jsonwebtoken::Header::new(keyset.active_alg);
    header.kid = Some(keyset.active_kid.clone());
    header.typ = Some("entity-statement+jwt".to_owned());
    let claims = federation_entity_statement_claims(
        &state.settings.issuer,
        keyset.jwks(),
        Utc::now().timestamp(),
        86_400,
    );
    match keyset.sign_jwt(&header, &claims).await {
        Ok(jwt) => HttpResponse::Ok()
            .insert_header((header::CACHE_CONTROL, "no-store"))
            .content_type("application/entity-statement+jwt")
            .body(jwt),
        Err(error) => {
            tracing::warn!(%error, "failed to sign OpenID Federation entity statement");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Federation entity statement signing failed.",
            )
        }
    }
}

#[cfg(test)]
#[path = "../../tests/in_source/src/http/tests/federation_entity.rs"]
mod tests;
