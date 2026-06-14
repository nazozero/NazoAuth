use super::prelude::*;
use crate::domain::{Keyset, SUPPORTED_AUTHORIZATION_DETAILS_TYPES};
use crate::settings::{AuthorizationServerProfile, Settings};

const CLIENT_JWT_SIGNING_ALGS: [&str; 4] = ["EdDSA", "RS256", "ES256", "PS256"];
const REQUEST_OBJECT_SIGNING_ALGS: [&str; 5] = ["none", "EdDSA", "RS256", "ES256", "PS256"];
const PROMPT_VALUES_SUPPORTED: [&str; 4] = ["login", "consent", "select_account", "none"];
const CLAIMS_SUPPORTED: [&str; 24] = [
    "sub",
    "auth_time",
    "amr",
    "acr",
    "nonce",
    "preferred_username",
    "name",
    "given_name",
    "family_name",
    "middle_name",
    "nickname",
    "profile",
    "picture",
    "website",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
    "email",
    "email_verified",
    "address",
    "phone_number",
    "phone_number_verified",
    "updated_at",
];
const CLIENT_AUTH_METHODS: [&str; 6] = [
    "client_secret_basic",
    "client_secret_post",
    "private_key_jwt",
    "tls_client_auth",
    "self_signed_tls_client_auth",
    "none",
];
const FAPI2_CLIENT_AUTH_METHODS: [&str; 3] = [
    "private_key_jwt",
    "tls_client_auth",
    "self_signed_tls_client_auth",
];

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
    authorization_server_metadata(&state.settings, &state.keyset)
}

fn authorization_server_metadata(settings: &Settings, keyset: &Keyset) -> Value {
    let issuer = settings.issuer.as_str();
    let mtls_base = settings.mtls_endpoint_base_url.as_str();
    let id_token_signing_algs = id_token_signing_alg_values_supported(keyset);
    let authorization_signing_algs = active_signing_alg_values_supported(keyset);
    let mtls_enabled = !settings.trusted_proxy_cidrs.is_empty();
    let token_auth_methods =
        token_endpoint_auth_methods_supported(settings.authorization_server_profile, mtls_enabled);
    let request_object_signing_algs = request_object_signing_alg_values_supported(
        settings.authorization_server_profile,
        authorization_signing_algs.as_slice(),
    );
    let mut metadata = json!({
        "issuer": issuer,
        "authorization_server_profile": settings.authorization_server_profile.as_str(),
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "end_session_endpoint": format!("{issuer}/logout"),
        "pushed_authorization_request_endpoint": format!("{issuer}/par"),
        "revocation_endpoint": format!("{issuer}/revoke"),
        "introspection_endpoint": format!("{issuer}/introspect"),
        "userinfo_endpoint": format!("{issuer}/userinfo"),
        "jwks_uri": format!("{issuer}/jwks.json"),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query", "jwt"],
        "subject_types_supported": [settings.subject_type.as_str()],
        "id_token_signing_alg_values_supported": id_token_signing_algs,
        "authorization_signing_alg_values_supported": authorization_signing_algs,
        "token_endpoint_auth_methods_supported": token_auth_methods,
        "token_endpoint_auth_signing_alg_values_supported": CLIENT_JWT_SIGNING_ALGS,
        "revocation_endpoint_auth_methods_supported": token_auth_methods,
        "revocation_endpoint_auth_signing_alg_values_supported": CLIENT_JWT_SIGNING_ALGS,
        "introspection_endpoint_auth_methods_supported": token_auth_methods,
        "introspection_endpoint_auth_signing_alg_values_supported": CLIENT_JWT_SIGNING_ALGS,
        "scopes_supported": ["openid", "profile", "email", "address", "phone", "offline_access"],
        "claims_supported": CLAIMS_SUPPORTED,
        "prompt_values_supported": PROMPT_VALUES_SUPPORTED,
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
        "authorization_response_iss_parameter_supported": true,
        "claims_parameter_supported": true,
        "authorization_details_types_supported": SUPPORTED_AUTHORIZATION_DETAILS_TYPES,
        "backchannel_logout_supported": true,
        "backchannel_logout_session_supported": true,
        "request_parameter_supported": true,
        "request_uri_parameter_supported": false,
        "require_pushed_authorization_requests": settings.require_pushed_authorization_requests,
        "code_challenge_methods_supported": ["S256"],
        "dpop_signing_alg_values_supported": CLIENT_JWT_SIGNING_ALGS,
        "request_object_signing_alg_values_supported": request_object_signing_algs
    });
    if mtls_enabled {
        metadata["tls_client_certificate_bound_access_tokens"] = json!(true);
        metadata["mtls_endpoint_aliases"] = json!({
            "token_endpoint": format!("{mtls_base}/token"),
            "pushed_authorization_request_endpoint": format!("{mtls_base}/par"),
            "revocation_endpoint": format!("{mtls_base}/revoke"),
            "introspection_endpoint": format!("{mtls_base}/introspect"),
            "userinfo_endpoint": format!("{mtls_base}/userinfo")
        });
    }
    metadata
}

fn token_endpoint_auth_methods_supported(
    profile: AuthorizationServerProfile,
    mtls_enabled: bool,
) -> Vec<&'static str> {
    let methods = if profile.requires_fapi2_security() {
        FAPI2_CLIENT_AUTH_METHODS.as_slice()
    } else {
        CLIENT_AUTH_METHODS.as_slice()
    };
    methods
        .iter()
        .copied()
        .filter(|method| {
            mtls_enabled || !matches!(*method, "tls_client_auth" | "self_signed_tls_client_auth")
        })
        .collect()
}

fn request_object_signing_alg_values_supported(
    profile: AuthorizationServerProfile,
    active_signing_algs: &[&'static str],
) -> Vec<&'static str> {
    if profile.requires_signed_authorization_request() {
        return active_signing_algs.to_vec();
    }
    REQUEST_OBJECT_SIGNING_ALGS.to_vec()
}

fn active_signing_alg_values_supported(keyset: &Keyset) -> Vec<&'static str> {
    signing_algorithm_name(keyset.active_alg)
        .map(|alg| vec![alg])
        .unwrap_or_default()
}

fn id_token_signing_alg_values_supported(keyset: &Keyset) -> Vec<&'static str> {
    let mut values = active_signing_alg_values_supported(keyset);
    values.push("RS256");
    values.sort_unstable();
    values.dedup();
    values
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
#[path = "tests/well_known.rs"]
mod tests;
