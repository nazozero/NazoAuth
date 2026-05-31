use super::prelude::*;

pub(crate) async fn health() -> Json<Value> {
    Json(json!({"status": "正常"}))
}

pub(crate) async fn captcha_config() -> Json<Value> {
    Json(json!({
        "turnstile_enabled": false,
        "turnstile_site_key": null,
        "registration_enabled": true
    }))
}

pub(crate) async fn discovery(state: Data<AppState>) -> Json<Value> {
    let issuer = state.settings.issuer.trim_end_matches('/');
    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "revocation_endpoint": format!("{issuer}/revoke"),
        "introspection_endpoint": format!("{issuer}/introspect"),
        "userinfo_endpoint": format!("{issuer}/userinfo"),
        "jwks_uri": format!("{issuer}/jwks.json"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt", "none"],
        "token_endpoint_auth_signing_alg_values_supported": ["EdDSA"],
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "claims_supported": ["sub", "preferred_username", "name", "email", "email_verified", "picture"],
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
        "authorization_response_iss_parameter_supported": true,
        "code_challenge_methods_supported": ["S256"],
        "dpop_signing_alg_values_supported": ["EdDSA"]
    }))
}

pub(crate) async fn jwks(state: Data<AppState>) -> Json<Value> {
    Json(state.keyset.jwks())
}
