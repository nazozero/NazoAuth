use super::prelude::*;

const CLIENT_JWT_SIGNING_ALGS: [&str; 4] = ["EdDSA", "RS256", "ES256", "PS256"];
const PROMPT_VALUES_SUPPORTED: [&str; 4] = ["login", "consent", "select_account", "none"];

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

fn authorization_server_metadata_value(state: &AppState) -> Value {
    let issuer = state.settings.issuer.as_str();
    json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "pushed_authorization_request_endpoint": format!("{issuer}/par"),
        "revocation_endpoint": format!("{issuer}/revoke"),
        "introspection_endpoint": format!("{issuer}/introspect"),
        "userinfo_endpoint": format!("{issuer}/userinfo"),
        "jwks_uri": format!("{issuer}/jwks.json"),
        "response_types_supported": ["code"],
        "subject_types_supported": [state.settings.subject_type.as_str()],
        "id_token_signing_alg_values_supported": state.keyset.signing_alg_values_supported(),
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt", "none"],
        "token_endpoint_auth_signing_alg_values_supported": CLIENT_JWT_SIGNING_ALGS,
        "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt", "none"],
        "revocation_endpoint_auth_signing_alg_values_supported": CLIENT_JWT_SIGNING_ALGS,
        "introspection_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt"],
        "introspection_endpoint_auth_signing_alg_values_supported": CLIENT_JWT_SIGNING_ALGS,
        "scopes_supported": ["openid", "profile", "email", "address", "phone", "offline_access"],
        "claims_supported": ["sub", "auth_time", "amr", "nonce", "preferred_username", "name", "given_name", "family_name", "middle_name", "nickname", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "email", "email_verified", "address", "phone_number", "phone_number_verified", "updated_at"],
        "prompt_values_supported": PROMPT_VALUES_SUPPORTED,
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
        "authorization_response_iss_parameter_supported": true,
        "claims_parameter_supported": true,
        "request_parameter_supported": true,
        "request_uri_parameter_supported": false,
        "code_challenge_methods_supported": ["S256"],
        "dpop_signing_alg_values_supported": CLIENT_JWT_SIGNING_ALGS,
        "request_object_signing_alg_values_supported": CLIENT_JWT_SIGNING_ALGS
    })
}

pub(crate) async fn discovery(state: Data<AppState>) -> Json<Value> {
    Json(authorization_server_metadata_value(&state))
}

pub(crate) async fn oauth_authorization_server_metadata(state: Data<AppState>) -> Json<Value> {
    Json(authorization_server_metadata_value(&state))
}

pub(crate) async fn jwks(state: Data<AppState>) -> Json<Value> {
    Json(state.keyset.jwks())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_prompt_values_match_authorization_request_parser() {
        assert_eq!(
            PROMPT_VALUES_SUPPORTED,
            ["login", "consent", "select_account", "none"]
        );
    }
}
